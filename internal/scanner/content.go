package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/intelligence"
)

type FileEvidence = assessments.FileEvidence

// Clamd uses INSTREAM, never a path on the daemon's filesystem. The endpoint is
// operator configuration, not supplied by scanned repositories or API callers.
func clamd(ctx context.Context, address string, source io.Reader) (string, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", errors.New("malware engine unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err = io.WriteString(conn, "zINSTREAM\x00"); err != nil {
		return "", err
	}
	buffer := make([]byte, 32<<10)
	var length [4]byte
	var total int64
	for {
		n, readErr := source.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > 25<<20 {
				return "", errors.New("malware file limit exceeded")
			}
			binary.BigEndian.PutUint32(length[:], uint32(n))
			if _, err = conn.Write(length[:]); err != nil {
				return "", err
			}
			if _, err = io.Copy(conn, bytes.NewReader(buffer[:n])); err != nil {
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	if _, err = conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString(0)
	if err != nil {
		return "", errors.New("incomplete malware response")
	}
	reply = strings.TrimSuffix(reply, "\x00")
	if reply == "stream: OK" {
		return "", nil
	}
	if strings.HasPrefix(reply, "stream: ") && strings.HasSuffix(reply, " FOUND") {
		signature := strings.TrimSuffix(strings.TrimPrefix(reply, "stream: "), " FOUND")
		if strings.HasPrefix(signature, "Heuristics.Limits.Exceeded") {
			return "", errors.New("malware engine scan limit exceeded")
		}
		return signature, nil
	}
	return "", errors.New("malware engine rejected stream")
}

type Indicator = intelligence.Indicator
type IndicatorBundle = intelligence.Bundle

func loadIndicators(filename string) (IndicatorBundle, error) {
	f, err := os.Open(filename)
	if err != nil {
		return IndicatorBundle{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return IndicatorBundle{}, err
	}
	return intelligence.Parse(data)
}

var contentDomain = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}\b`)
var contentIPv4 = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)
var secretsPattern = regexp.MustCompile(`(?i)tojson\s*\(\s*secrets\s*\)`)

// INT-010: fetch-and-execute in build files that developers run locally.
var remoteExec = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
var hiddenHelper = regexp.MustCompile(`^\.ci-[A-Za-z0-9_-]+\.sh$`)

// yaraCanary is matched only by the SCRS_Canary rule shipped in rules/scrs.yar.
const yaraCanary = "SCRS-YARA-CANARY-7f3c9a1e5b2d4086-coverage-probe"

func contentFinding(kind, id, title, path, digest string) assessments.Finding {
	evidence, _ := json.Marshal(map[string]string{"path": path, "sha256": digest, "rule_id": id})
	return assessments.Finding{Type: kind, AdvisoryID: id, Title: title, Severity: "critical", Score: 100, Component: assessments.Component{Path: path}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Quarantine this revision, review the matched file, and rotate exposed credentials when applicable. Do not execute suspicious content.","automatic_changes":false}`)}
}

func integrityFinding(id, title, severity, path, digest string, detail map[string]any) assessments.Finding {
	f := contentFinding("integrity", id, title, path, digest)
	f.Severity = severity
	f.Score = map[string]int{"critical": 100, "high": 60, "medium": 30}[severity]
	evidence := map[string]any{"path": path, "sha256": digest, "rule_id": id}
	for k, v := range detail {
		evidence[k] = v
	}
	f.Evidence, _ = json.Marshal(evidence)
	f.Guidance = json.RawMessage(`{"summary":"Confirm the change is intended. Install hooks and fetch-and-execute steps run on developer machines and build hosts, not only in CI.","automatic_changes":false}`)
	return f
}

// indicatorSet groups active content indicators by matcher (TIF, INT-008).
type indicatorSet struct {
	hashes, domains, ips map[string][]Indicator
	paths, contents      []intelligence.Pattern
	steps                []Indicator
	active               int
}

func newIndicatorSet(b IndicatorBundle, now time.Time) indicatorSet {
	set := indicatorSet{hashes: map[string][]Indicator{}, domains: map[string][]Indicator{}, ips: map[string][]Indicator{}}
	for _, i := range b.Indicators {
		if !now.Before(i.ValidUntil) {
			continue
		}
		switch i.Type {
		case "sha256":
			set.hashes[strings.ToLower(i.Value)] = append(set.hashes[strings.ToLower(i.Value)], i)
		case "domain":
			set.domains[i.Value] = append(set.domains[i.Value], i)
		case "ipv4":
			set.ips[i.Value] = append(set.ips[i.Value], i)
		case "workflow_step_name":
			set.steps = append(set.steps, i)
		case "purl":
			// Matched against the SBOM after SCA.
		default:
			continue // event-only patterns (titles, branches, messages)
		}
		set.active++
	}
	set.paths = b.Patterns("file_path_regex", now)
	set.contents = b.Patterns("file_content_regex", now)
	set.active += len(set.paths) + len(set.contents)
	return set
}

// contentScan holds one assessment's malware, YARA, IOC and integrity state.
// Repository walks and image layer streams feed it one file at a time.
type contentScan struct {
	ctx                           context.Context
	address                       string
	set                           indicatorSet
	malware, yara, ioc, integrity assessments.Stage
	findings                      []assessments.Finding
	// Files are streamed to clamd by a few workers; one file at a time made
	// large repositories and images exceed their time budget. verdicts holds
	// results by content digest (guarded by mu), queued the digests submitted,
	// and pending the files awaiting a verdict until finish.
	mu       sync.Mutex
	verdicts map[string]string
	queued   map[string]bool
	pending  []FileEvidence
	jobs     chan clamJob
	wg       sync.WaitGroup
	// image disables repository-only rules (workflows, hooks, root helpers).
	image bool
}

type clamJob struct {
	sha  string
	data []byte
}

// clamWorkers stays well below clamd's default MaxThreads (10).
const clamWorkers = 4

// submit queues one distinct content for a malware verdict. It blocks while
// all workers are busy, which bounds the file data held in memory.
func (c *contentScan) submit(sha string, data []byte) {
	if c.queued[sha] {
		return
	}
	c.queued[sha] = true
	if c.jobs == nil {
		c.jobs = make(chan clamJob)
		for i := 0; i < clamWorkers; i++ {
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				for job := range c.jobs {
					verdict := "clean"
					if sig, err := clamd(c.ctx, c.address, bytes.NewReader(job.data)); err != nil {
						verdict = "error"
					} else if sig != "" {
						verdict = "infected:" + sig
					}
					c.mu.Lock()
					c.verdicts[job.sha] = verdict
					c.mu.Unlock()
				}
			}()
		}
	}
	c.jobs <- clamJob{sha, data}
}

// finish waits for outstanding verdicts, records malware findings and reports
// each pending file's final status. Call it once, after the last file.
func (c *contentScan) finish(resolve func(FileEvidence)) {
	if c.jobs != nil {
		close(c.jobs)
		c.wg.Wait()
		c.jobs = nil
	}
	for _, p := range c.pending {
		p.Malware = "clean"
		verdict := c.verdicts[p.SHA256]
		if sig, infected := strings.CutPrefix(verdict, "infected:"); infected {
			p.Malware = "infected"
			finding := contentFinding("malware", sig, "ClamAV detected "+sig, p.Path, p.SHA256)
			if strings.HasPrefix(sig, "YARA.") {
				finding.Title = "YARA rule matched: " + strings.TrimSuffix(strings.TrimPrefix(sig, "YARA."), ".UNOFFICIAL")
			}
			c.findings = append(c.findings, finding)
		} else if verdict != "clean" {
			p.Malware = "error"
			c.malware.Status = "partial"
		}
		resolve(p)
	}
	c.pending = nil
}

func (e Engine) newContentScan(ctx context.Context, image bool) *contentScan {
	c := &contentScan{ctx: ctx, address: e.ClamdAddress, image: image, verdicts: map[string]string{}, queued: map[string]bool{}, findings: []assessments.Finding{}}
	c.malware = assessments.Stage{Name: "malware", Status: "ok", Detail: "ClamAV regular-file INSTREAM coverage"}
	c.yara = assessments.Stage{Name: "yara", Status: "skipped", Detail: "ClamAV endpoint not configured"}
	if e.ClamdAddress == "" {
		c.malware.Status, c.malware.Detail = "skipped", "ClamAV endpoint not configured"
	} else {
		version, dated, versionErr := clamdVersion(ctx, e.ClamdAddress)
		if versionErr != nil {
			c.malware.Status, c.malware.Detail = "partial", "ClamAV signature freshness unavailable"
		} else {
			c.malware.Detail = version
			if time.Since(dated) > 26*time.Hour || dated.After(time.Now().Add(5*time.Minute)) {
				c.malware.Status = "partial"
				f := contentFinding("posture", "SCRS-CLAMAV-SIGNATURE-AGE", "ClamAV signature date outside freshness threshold", "", "")
				f.Severity = "high"
				f.Score = 45
				f.Evidence, _ = json.Marshal(map[string]any{"engine": version, "signature_date": dated, "max_age_hours": 26})
				c.findings = append(c.findings, f)
			}
		}
		// Prove the SCRS YARA ruleset is loaded instead of assuming it.
		sig, err := clamd(ctx, e.ClamdAddress, strings.NewReader(yaraCanary))
		switch {
		case err != nil:
			c.yara.Status, c.yara.Detail = "partial", "YARA canary could not be scanned"
		case strings.Contains(sig, "SCRS_Canary"):
			c.yara.Status, c.yara.Detail = "ok", "SCRS YARA ruleset "+RulesVersion+" loaded in ClamAV (canary detected)"
		default:
			c.yara.Status, c.yara.Detail = "skipped", "SCRS YARA ruleset not loaded in ClamAV; run the yara-install step"
		}
	}
	c.ioc = assessments.Stage{Name: "ioc", Status: "skipped", Detail: "Indicator bundle not configured"}
	bundle, err := loadIndicators(e.IndicatorFile)
	if e.Indicators != nil {
		bundle = *e.Indicators
		err = nil
	}
	if e.IndicatorFile != "" || e.Indicators != nil {
		if err != nil {
			c.ioc.Status, c.ioc.Detail = "failed", "Invalid indicator bundle"
		} else {
			c.set = newIndicatorSet(bundle, time.Now())
			c.ioc.Status = "ok"
			c.ioc.Detail = "Hash, domain, IPv4, path, content and workflow-step matching; bundle " + bundle.Version
			if c.set.active == 0 {
				c.ioc.Status, c.ioc.Detail = "skipped", "No unexpired indicators"
			}
		}
	}
	c.integrity = assessments.Stage{Name: "integrity", Status: "ok", Detail: "Workflow secret serialization, install hooks, fetch-and-execute and hidden helper scripts; workflow changes against the prior revision"}
	if image {
		c.integrity.Detail = "Every layer file is inspected, including files hidden by later layers; repository workflow rules do not apply to images"
	}
	return c
}

// file inspects one regular file of known size. Files up to the ClamAV stream
// limit are read once into memory and reused for hashing, malware and text rules.
func (c *contentScan) file(relative string, size int64, r io.Reader) (FileEvidence, error) {
	record := FileEvidence{Path: relative, Size: size, Malware: "skipped"}
	var data []byte
	if size <= 25<<20 {
		var err error
		if data, err = io.ReadAll(io.LimitReader(r, size+1)); err != nil {
			return record, err
		}
		if int64(len(data)) != size {
			return record, errors.New("file size changed while reading")
		}
		sum := sha256.Sum256(data)
		record.SHA256 = hex.EncodeToString(sum[:])
	} else {
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return record, err
		}
		record.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	if c.address != "" {
		if data == nil {
			record.Malware = "skipped_oversize"
			c.malware.Status = "partial"
		} else {
			// Resolved by finish.
			record.Malware = "pending"
			c.pending = append(c.pending, record)
			c.submit(record.SHA256, data)
		}
	}
	for _, i := range c.set.hashes[record.SHA256] {
		c.findings = append(c.findings, contentFinding("ioc_match", i.ID, "File hash matches active indicator", record.Path, record.SHA256))
	}
	for _, p := range c.set.paths {
		if p.MatchString(record.Path) {
			c.findings = append(c.findings, contentFinding("ioc_match", p.ID, "File path matches active indicator", record.Path, record.SHA256))
		}
	}
	if !c.image && !strings.Contains(record.Path, "/") && hiddenHelper.MatchString(filepath.Base(record.Path)) {
		c.findings = append(c.findings, integrityFinding("SCRS-HIDDEN-CI-HELPER", "Hidden CI helper script at repository root", "high", record.Path, record.SHA256, nil))
	}
	if size <= 1<<20 {
		if !bytes.ContainsRune(data, 0) {
			text := string(data)
			if c.image {
				c.findings = append(c.findings, matchText(record, text, c.set)...)
			} else {
				c.findings = append(c.findings, inspectText(record, text, c.set)...)
			}
		}
	} else if c.ioc.Status == "ok" && (len(c.set.domains) > 0 || len(c.set.ips) > 0 || len(c.set.contents) > 0) {
		c.ioc.Status = "partial"
		c.ioc.Detail = "Text indicators skipped files above 1 MiB"
	}
	if len(c.findings) > 10000 {
		return record, errors.New("content findings limit exceeded")
	}
	return record, nil
}

// incomplete marks every content stage partial after an interrupted walk.
func (c *contentScan) incomplete(detail string) {
	c.malware.Status, c.ioc.Status, c.integrity.Status = "partial", "partial", "partial"
	c.integrity.Detail = detail
}

func (c *contentScan) stages() []assessments.Stage {
	return []assessments.Stage{c.malware, c.yara, c.ioc, c.integrity}
}

func (e Engine) inspectContent(ctx context.Context, root string) ([]FileEvidence, []assessments.Finding, []assessments.Stage) {
	scan := e.newContentScan(ctx, false)
	files := []FileEvidence{}
	index := map[string]int{}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("nonregular content")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		record, err := scan.file(filepath.ToSlash(relative), info.Size(), f)
		if err != nil {
			return err
		}
		index[record.Path] = len(files)
		files = append(files, record)
		return nil
	})
	scan.finish(func(f FileEvidence) { files[index[f.Path]].Malware = f.Malware })
	if walkErr != nil {
		scan.incomplete("Content walk did not complete")
	}
	return files, scan.findings, scan.stages()
}

// matchText applies only indicator matching; image files are not build inputs.
func matchText(record FileEvidence, text string, set indicatorSet) []assessments.Finding {
	var out []assessments.Finding
	seen := map[string]bool{}
	for _, domain := range contentDomain.FindAllString(text, -1) {
		domain = strings.ToLower(domain)
		if seen[domain] {
			continue
		}
		seen[domain] = true
		for _, i := range set.domains[domain] {
			out = append(out, contentFinding("ioc_match", i.ID, "Text domain matches active indicator", record.Path, record.SHA256))
		}
	}
	if len(set.ips) > 0 {
		for _, ip := range contentIPv4.FindAllString(text, -1) {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			for _, i := range set.ips[ip] {
				out = append(out, contentFinding("ioc_match", i.ID, "Text IPv4 address matches active indicator", record.Path, record.SHA256))
			}
		}
	}
	for _, p := range set.contents {
		if p.MatchString(text) {
			out = append(out, contentFinding("ioc_match", p.ID, "File content matches active indicator", record.Path, record.SHA256))
		}
	}
	return out
}

// inspectText applies text indicators and INT-009/INT-010 rules to one file.
func inspectText(record FileEvidence, text string, set indicatorSet) []assessments.Finding {
	out := matchText(record, text, set)
	workflow := strings.HasPrefix(record.Path, ".github/workflows/")
	if workflow {
		if secretsPattern.MatchString(text) {
			out = append(out, contentFinding("integrity", "SCRS-WORKFLOW-SECRETS", "Workflow serializes repository secrets", record.Path, record.SHA256))
		}
		lower := strings.ToLower(text)
		for _, i := range set.steps {
			if strings.Contains(lower, "name: "+strings.ToLower(i.Value)) || strings.Contains(lower, "name: \""+strings.ToLower(i.Value)) || strings.Contains(lower, "name: '"+strings.ToLower(i.Value)) {
				out = append(out, contentFinding("ioc_match", i.ID, "Workflow step name matches active indicator", record.Path, record.SHA256))
			}
		}
	}
	base := filepath.Base(record.Path)
	if base == "package.json" && !strings.Contains(record.Path, "node_modules/") {
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal([]byte(text), &manifest) == nil {
			var hooks []string
			for _, hook := range []string{"preinstall", "install", "postinstall"} {
				if _, ok := manifest.Scripts[hook]; ok {
					hooks = append(hooks, hook)
				}
			}
			if len(hooks) > 0 {
				out = append(out, integrityFinding("SCRS-INSTALL-HOOK", "npm install lifecycle hook runs on every install", "medium", record.Path, record.SHA256, map[string]any{"hooks": hooks}))
			}
		}
	}
	if base == "Makefile" || strings.HasSuffix(base, ".mk") || strings.HasSuffix(base, ".sh") || base == "Dockerfile" || workflow {
		if remoteExec.MatchString(text) {
			out = append(out, integrityFinding("SCRS-REMOTE-EXEC", "Build step downloads and executes remote content", "medium", record.Path, record.SHA256, nil))
		}
	}
	return out
}

func clamdVersion(ctx context.Context, address string) (string, time.Time, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", time.Time{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err = io.WriteString(conn, "zVERSION\x00"); err != nil {
		return "", time.Time{}, err
	}
	raw, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString(0)
	if err != nil {
		return "", time.Time{}, err
	}
	raw = strings.TrimSuffix(raw, "\x00")
	parts := strings.Split(raw, "/")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "ClamAV ") {
		return "", time.Time{}, errors.New("invalid ClamAV version")
	}
	date, err := time.Parse("Mon Jan _2 15:04:05 2006", parts[2])
	return raw, date, err
}
