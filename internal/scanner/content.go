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
var secretsPattern = regexp.MustCompile(`(?i)tojson\s*\(\s*secrets\s*\)`)

func contentFinding(kind, id, title, path, digest string) assessments.Finding {
	evidence, _ := json.Marshal(map[string]string{"path": path, "sha256": digest, "rule_id": id})
	return assessments.Finding{Type: kind, AdvisoryID: id, Title: title, Severity: "critical", Score: 100, Component: assessments.Component{Path: path}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Quarantine this revision, review the matched file, and rotate exposed credentials when applicable. Do not execute suspicious content.","automatic_changes":false}`)}
}
func (e Engine) inspectContent(ctx context.Context, root string) ([]FileEvidence, []assessments.Finding, []assessments.Stage) {
	files := []FileEvidence{}
	findings := []assessments.Finding{}
	malware := assessments.Stage{Name: "malware", Status: "ok", Detail: "ClamAV regular-file INSTREAM coverage; separate YARA stage reports its own coverage"}
	if e.ClamdAddress == "" {
		malware.Status = "skipped"
		malware.Detail = "ClamAV endpoint not configured"
	}
	if e.ClamdAddress != "" {
		version, dated, versionErr := clamdVersion(ctx, e.ClamdAddress)
		if versionErr != nil {
			malware.Status = "partial"
			malware.Detail = "ClamAV signature freshness unavailable"
		} else {
			malware.Detail = version
			if time.Since(dated) > 26*time.Hour || dated.After(time.Now().Add(5*time.Minute)) {
				malware.Status = "partial"
				f := contentFinding("posture", "SCRS-CLAMAV-SIGNATURE-AGE", "ClamAV signature date outside freshness threshold", "", "")
				f.Severity = "high"
				f.Score = 45
				f.Evidence, _ = json.Marshal(map[string]any{"engine": version, "signature_date": dated, "max_age_hours": 26})
				findings = append(findings, f)
			}
		}
	}
	ioc := assessments.Stage{Name: "ioc", Status: "skipped", Detail: "Indicator bundle not configured"}
	bundle, err := loadIndicators(e.IndicatorFile)
	if e.Indicators != nil {
		bundle = *e.Indicators
		err = nil
	}
	hashRules := map[string][]Indicator{}
	domainRules := map[string][]Indicator{}
	if e.IndicatorFile != "" || e.Indicators != nil {
		if err != nil {
			ioc.Status = "failed"
			ioc.Detail = "Invalid indicator bundle"
		} else {
			ioc.Status = "ok"
			ioc.Detail = "SHA256 and bounded text domain matching; bundle " + bundle.Version
			active := 0
			for _, i := range bundle.Indicators {
				if time.Now().Before(i.ValidUntil) {
					active++
					if i.Type == "sha256" {
						hashRules[strings.ToLower(i.Value)] = append(hashRules[strings.ToLower(i.Value)], i)
					} else {
						domainRules[strings.ToLower(i.Value)] = append(domainRules[strings.ToLower(i.Value)], i)
					}
				}
			}
			if active == 0 {
				ioc.Status = "skipped"
				ioc.Detail = "No unexpired indicators"
			}
		}
	}
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
		record := FileEvidence{Path: filepath.ToSlash(relative), Size: info.Size(), Malware: "skipped"}
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			return err
		}
		record.SHA256 = hex.EncodeToString(h.Sum(nil))
		if e.ClamdAddress != "" {
			if info.Size() > 25<<20 {
				record.Malware = "skipped_oversize"
				malware.Status = "partial"
			} else {
				if _, err = f.Seek(0, 0); err != nil {
					return err
				}
				sig, scanErr := clamd(ctx, e.ClamdAddress, f)
				if scanErr != nil {
					record.Malware = "error"
					malware.Status = "partial"
				} else if sig != "" {
					record.Malware = "infected"
					findings = append(findings, contentFinding("malware", sig, "ClamAV detected "+sig, record.Path, record.SHA256))
				} else {
					record.Malware = "clean"
				}
			}
		}
		for _, i := range hashRules[record.SHA256] {
			findings = append(findings, contentFinding("ioc_match", i.ID, "File hash matches active indicator", record.Path, record.SHA256))
		}
		if info.Size() <= 1<<20 {
			if _, err = f.Seek(0, 0); err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
			if err != nil {
				return err
			}
			if !strings.ContainsRune(string(data), 0) {
				seen := map[string]bool{}
				for _, domain := range contentDomain.FindAllString(string(data), -1) {
					domain = strings.ToLower(domain)
					if seen[domain] {
						continue
					}
					seen[domain] = true
					for _, i := range domainRules[domain] {
						findings = append(findings, contentFinding("ioc_match", i.ID, "Text domain matches active indicator", record.Path, record.SHA256))
					}
				}
				if strings.HasPrefix(record.Path, ".github/workflows/") && secretsPattern.Match(data) {
					findings = append(findings, contentFinding("integrity", "SCRS-WORKFLOW-SECRETS", "Workflow serializes repository secrets", record.Path, record.SHA256))
				}
			}
		} else if ioc.Status == "ok" && len(domainRules) > 0 {
			ioc.Status = "partial"
			ioc.Detail = "Text-domain scan skipped files above 1 MiB"
		}
		files = append(files, record)
		if len(findings) > 10000 {
			return errors.New("content findings limit exceeded")
		}
		return nil
	})
	if walkErr != nil {
		malware.Status = "partial"
		ioc.Status = "partial"
	}
	return files, findings, []assessments.Stage{malware, ioc, {Name: "yara", Status: "skipped", Detail: "Independent YARA analyzer not yet configured"}, {Name: "integrity", Status: "partial", Detail: "Workflow secret serialization checked; baseline and provider metadata checks pending"}}
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
