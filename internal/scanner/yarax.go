package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/intelligence"
)

// YARA-X (the `yr` CLI) runs third-party packs and team rules with the pe,
// elf, math, hash and dotnet modules. It runs as a child process, like
// OSV-Scanner, so a crash or hang in rule evaluation cannot take down the
// scanner, and per-file timeouts bound hostile inputs.

type (
	RuleSet    = intelligence.RuleSet
	RulePack   = intelligence.RulePack
	Diagnostic = intelligence.Diagnostic
	RuleError  = intelligence.RuleError
)

const (
	MaxRulePackSize = intelligence.MaxRulePackSize
	// Files above this are not written for YARA-X and mark the stage partial.
	// With the batch bound, an image scan stays well inside the scanner's
	// 1 GiB work area: image archive (400 MiB) + batch + one spilled file.
	maxRuleFileBytes = 128 << 20
	// A batch is scanned when it reaches either bound, and at the end.
	ruleBatchBytes = 128 << 20
	ruleBatchFiles = 4096
	// Paths reported per matching content digest.
	maxPathsPerDigest = 20
)

var (
	diagnosticHead    = regexp.MustCompile(`^(error|warning)(?:\[([A-Za-z0-9_]+)\])?: (.+)$`)
	diagnosticPlace   = regexp.MustCompile(`^\s*--> .*:(\d+):(\d+)$`)
	checkRuleText     = intelligence.CheckRuleText
	checkPack         = intelligence.CheckPack
	ruleSeverityScore = intelligence.RuleSeverityScore
)

// ValidateRules compiles one ruleset and returns its warnings, or a
// *RuleError with located diagnostics when it does not compile.
func ValidateRules(ctx context.Context, binary, workRoot, rules string) ([]Diagnostic, error) {
	if err := checkRuleText(rules); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(workRoot, "scrs-rules-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	source := filepath.Join(directory, "rules.yar")
	if err := os.WriteFile(source, []byte(rules), 0600); err != nil {
		return nil, err
	}
	diagnostics, err := runCompiler(ctx, binary, directory, filepath.Join(directory, "rules.yarc"), false, []string{"ruleset:" + source})
	if err != nil {
		return nil, err
	}
	return diagnostics, nil
}

// runCompiler runs `yr compile` in an empty directory with no inherited
// environment. It returns the diagnostics; a failed compile is a *RuleError.
func runCompiler(ctx context.Context, binary, directory, output string, quiet bool, sources []string) ([]Diagnostic, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	args := []string{"compile", "--relaxed-re-syntax", "-o", output}
	if quiet {
		args = append(args, "--disable-warnings")
	}
	command := exec.CommandContext(ctx, binary, append(args, sources...)...)
	command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory, "NO_COLOR=1"}
	command.Dir = directory
	stderr := &cappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = io.Discard, stderr
	err := command.Run()
	if ctx.Err() != nil {
		return nil, errors.New("rule compilation timed out")
	}
	diagnostics := parseDiagnostics(stderr.String())
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, errors.New("YARA-X compiler unavailable")
		}
		return nil, &RuleError{Diagnostics: diagnostics}
	}
	return diagnostics, nil
}

func parseDiagnostics(stderr string) []Diagnostic {
	out := []Diagnostic{}
	for _, line := range strings.Split(stderr, "\n") {
		if m := diagnosticHead.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			if m[1] == "error" && m[2] == "" && strings.HasSuffix(m[3], "error(s) found") {
				continue // summary line
			}
			if len(out) == 100 {
				break
			}
			out = append(out, Diagnostic{Level: m[1], Code: m[2], Message: clipText(m[3], 300)})
		} else if m := diagnosticPlace.FindStringSubmatch(line); m != nil && len(out) > 0 && out[len(out)-1].Line == 0 {
			out[len(out)-1].Line, _ = strconv.Atoi(m[1])
			out[len(out)-1].Column, _ = strconv.Atoi(m[2])
		}
	}
	return out
}

func clipText(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

// ruleCompiles serializes cache fills; compiled rules depend only on content.
var ruleCompiles sync.Mutex

// compiledPack returns the compiled rules for a pack, compiling once per
// content version and keeping the three most recent versions.
func compiledPack(ctx context.Context, binary, workRoot string, p RulePack, version string) (string, error) {
	cache := filepath.Join(workRoot, "yarax-cache")
	target := filepath.Join(cache, version+".yarc")
	ruleCompiles.Lock()
	defer ruleCompiles.Unlock()
	if _, err := os.Stat(target); err == nil {
		now := time.Now()
		_ = os.Chtimes(target, now, now)
		return target, nil
	}
	if err := os.MkdirAll(cache, 0700); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(workRoot, "scrs-compile-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	var sources []string
	for _, set := range p.RuleSets {
		path := filepath.Join(directory, set.Name+".yar")
		if err := os.WriteFile(path, []byte(set.Rules), 0600); err != nil {
			return "", err
		}
		sources = append(sources, set.Name+":"+path)
	}
	output := filepath.Join(directory, "pack.yarc")
	if _, err := runCompiler(ctx, binary, directory, output, true, sources); err != nil {
		return "", err
	}
	if err := os.Rename(output, target); err != nil {
		return "", err
	}
	entries, _ := os.ReadDir(cache)
	sort.Slice(entries, func(i, j int) bool {
		a, _ := entries[i].Info()
		b, _ := entries[j].Info()
		return a != nil && b != nil && a.ModTime().After(b.ModTime())
	})
	for i, entry := range entries {
		if i >= 3 {
			_ = os.Remove(filepath.Join(cache, entry.Name()))
		}
	}
	return target, nil
}

// ruleScan batches distinct file contents for YARA-X. Files are written once
// per SHA-256, named by digest, so matches map back to every path seen.
type ruleScan struct {
	binary, compiled, directory string
	sets                        map[string]RuleSet
	stage                       assessments.Stage
	paths                       map[string][]string
	written                     map[string]bool
	matches                     map[string][]ruleMatch
	batchBytes                  int64
	batchFiles                  int
	scanned, oversize           int
	failure                     string
}

type ruleMatch struct {
	Identifier string               `json:"identifier"`
	Namespace  string               `json:"namespace"`
	Meta       [][2]json.RawMessage `json:"meta"`
	Tags       []string             `json:"tags"`
}

// newRuleScan prepares a scan with the pack compiled; a nil pack skips it.
// Batches live under scanDir, which the caller removes with the scan.
func newRuleScan(ctx context.Context, binary, workRoot, scanDir string, pack *RulePack) *ruleScan {
	r := &ruleScan{binary: binary, stage: assessments.Stage{Name: "yara_x", Status: "skipped", Detail: "No YARA-X rulesets enabled"}, sets: map[string]RuleSet{}, paths: map[string][]string{}, written: map[string]bool{}, matches: map[string][]ruleMatch{}}
	if pack == nil || len(pack.RuleSets) == 0 {
		return r
	}
	version, err := checkPack(*pack)
	if err != nil {
		r.stage.Status, r.stage.Detail = "failed", "Rule pack rejected"
		return r
	}
	if binary == "" {
		r.stage.Status, r.stage.Detail = "failed", "YARA-X binary not configured"
		return r
	}
	if r.compiled, err = compiledPack(ctx, binary, workRoot, *pack, version); err != nil {
		r.stage.Status, r.stage.Detail = "failed", clipText("Rule pack did not compile: "+err.Error(), 300)
		return r
	}
	if r.directory, err = os.MkdirTemp(scanDir, "rulescan-"); err != nil {
		r.stage.Status, r.stage.Detail = "failed", "Rule scan work area unavailable"
		return r
	}
	modes := map[string]int{}
	for _, set := range pack.RuleSets {
		r.sets[set.Name] = set
		modes[set.Mode]++
	}
	r.stage.Status = "ok"
	r.stage.Detail = fmt.Sprintf("YARA-X rule pack %s: %d rulesets (block %d, alert %d, hunt %d)", version, len(pack.RuleSets), modes["block"], modes["alert"], modes["hunt"])
	return r
}

func (r *ruleScan) active() bool { return r.directory != "" }

// add records a path for content already in memory.
func (r *ruleScan) add(ctx context.Context, digest, path string, data []byte) {
	if !r.record(digest, path) {
		return
	}
	if err := os.WriteFile(filepath.Join(r.directory, digest), data, 0600); err != nil {
		r.fail("Rule scan work area write failed")
		return
	}
	r.grow(ctx, int64(len(data)))
}

// record notes a path and reports whether its content still needs writing.
func (r *ruleScan) record(digest, path string) bool {
	if !r.active() {
		return false
	}
	if len(r.paths[digest]) < maxPathsPerDigest {
		r.paths[digest] = append(r.paths[digest], path)
	}
	if r.written[digest] {
		return false
	}
	r.written[digest] = true
	return true
}

// writer streams a large file into the batch while its digest is computed;
// commit names it by digest once known. It returns nil above the size limit.
func (r *ruleScan) writer(size int64) (*os.File, error) {
	if !r.active() {
		return nil, nil
	}
	if size > maxRuleFileBytes {
		r.oversize++
		return nil, nil
	}
	return os.CreateTemp(r.directory, ".partial-")
}

func (r *ruleScan) commit(ctx context.Context, f *os.File, digest, path string, size int64) {
	name := f.Name()
	closeErr := f.Close()
	if !r.record(digest, path) || closeErr != nil {
		_ = os.Remove(name)
		if closeErr != nil {
			r.fail("Rule scan work area write failed")
		}
		return
	}
	if err := os.Rename(name, filepath.Join(r.directory, digest)); err != nil {
		r.fail("Rule scan work area write failed")
		return
	}
	r.grow(ctx, size)
}

func (r *ruleScan) grow(ctx context.Context, size int64) {
	r.batchBytes += size
	r.batchFiles++
	if r.batchBytes >= ruleBatchBytes || r.batchFiles >= ruleBatchFiles {
		r.flush(ctx)
	}
}

func (r *ruleScan) fail(detail string) {
	if r.failure == "" {
		r.failure = detail
	}
}

// flush scans the current batch and empties it.
func (r *ruleScan) flush(ctx context.Context) {
	if !r.active() || r.batchFiles == 0 || r.failure != "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, r.binary, "scan", "-C", r.compiled, r.directory, "--recursive=0", "--output-format", "ndjson", "--print-meta", "--print-namespace", "--print-tags", "--disable-console-logs", "--fast-scan", "--timeout", "20", "--threads", "4", "--skip-larger", strconv.Itoa(maxRuleFileBytes), "--max-matches-per-pattern", "1000")
	command.Env = []string{"HOME=" + r.directory, "TMPDIR=" + r.directory, "NO_COLOR=1"}
	command.Dir = r.directory
	stdout := &cappedBuffer{limit: 32 << 20}
	stderr := &cappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	switch {
	case ctx.Err() != nil:
		r.fail("YARA-X scan exceeded its time budget")
	case err != nil:
		r.fail("YARA-X scan failed")
	case strings.Contains(stderr.String(), "error"):
		// Per-file errors, including timeouts, are reported on stderr.
		r.fail("YARA-X could not scan some files (for example a per-file timeout)")
	}
	r.parse(stdout.Bytes())
	r.scanned += r.batchFiles
	entries, _ := os.ReadDir(r.directory)
	for _, entry := range entries {
		_ = os.Remove(filepath.Join(r.directory, entry.Name()))
	}
	r.batchBytes, r.batchFiles = 0, 0
}

func (r *ruleScan) parse(output []byte) {
	lines := bufio.NewScanner(bytes.NewReader(output))
	lines.Buffer(make([]byte, 64<<10), 16<<20)
	for lines.Scan() {
		var record struct {
			Path  string      `json:"path"`
			Rules []ruleMatch `json:"rules"`
		}
		if json.Unmarshal(lines.Bytes(), &record) != nil {
			r.fail("YARA-X output unreadable")
			continue
		}
		digest := filepath.Base(record.Path)
		if !r.written[digest] {
			continue
		}
		r.matches[digest] = append(r.matches[digest], record.Rules...)
	}
}

// finish scans the last batch, removes the work area and returns findings.
func (r *ruleScan) finish(ctx context.Context) []assessments.Finding {
	if !r.active() {
		return nil
	}
	r.flush(ctx)
	_ = os.RemoveAll(r.directory)
	r.stage.Detail += fmt.Sprintf("; %d distinct files", r.scanned)
	if r.oversize > 0 {
		r.stage.Status = "partial"
		r.stage.Detail += fmt.Sprintf("; %d files above 128 MiB not scanned", r.oversize)
	}
	if r.failure != "" {
		r.stage.Status = "partial"
		r.stage.Detail += "; " + r.failure
	}
	var findings []assessments.Finding
	digests := make([]string, 0, len(r.matches))
	for digest := range r.matches {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		for _, m := range r.matches[digest] {
			set, ok := r.sets[m.Namespace]
			if !ok {
				continue
			}
			for _, path := range r.paths[digest] {
				findings = append(findings, ruleFinding(set, m, path, digest))
			}
		}
	}
	return findings
}

// ruleFinding maps a match to a finding whose type carries the ruleset mode:
// yara_match blocks like malware, yara_alert gates by severity, yara_hunt
// is recorded only.
func ruleFinding(set RuleSet, m ruleMatch, path, digest string) assessments.Finding {
	meta := map[string]any{}
	severity := set.Severity
	for _, pair := range m.Meta {
		var key string
		var value any
		if json.Unmarshal(pair[0], &key) != nil || json.Unmarshal(pair[1], &value) != nil || len(meta) >= 16 {
			continue
		}
		if text, ok := value.(string); ok {
			value = clipText(text, 512)
			if strings.EqualFold(key, "severity") {
				if _, valid := ruleSeverityScore[strings.ToLower(text)]; valid {
					severity = strings.ToLower(text)
				}
			}
		}
		meta[clipText(key, 64)] = value
	}
	kind, score := "yara_"+set.Mode, ruleSeverityScore[severity]
	if set.Mode == "block" {
		kind, severity, score = "yara_match", "critical", 100
	}
	if len(m.Tags) > 16 {
		m.Tags = m.Tags[:16]
	}
	title := "YARA rule " + m.Identifier + " matched (" + set.Name + ")"
	if description, ok := meta["description"].(string); ok && description != "" {
		title += ": " + description
	}
	evidence, _ := json.Marshal(map[string]any{"path": path, "sha256": digest, "rule": m.Identifier, "ruleset": set.Name, "ruleset_id": set.ID, "mode": set.Mode, "tags": m.Tags, "meta": meta})
	guidance := `{"summary":"Review the matched file. For hunt rules, confirm or tune the rule before promoting it. For alert and block rules, treat the revision as suspect until reviewed. Do not execute suspicious content.","automatic_changes":false}`
	return assessments.Finding{Type: kind, AdvisoryID: clipText("YARA:"+set.Name+":"+m.Identifier, 128), Title: clipText(title, 512), Severity: severity, Score: score, Component: assessments.Component{Path: path}, Evidence: evidence, Guidance: json.RawMessage(guidance)}
}
