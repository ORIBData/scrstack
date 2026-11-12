package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
)

type Engine struct {
	Indicators                  *IndicatorBundle
	Binary, WorkRoot, Database  string
	RemediationEnabled          bool
	RemediationProxy            string
	ClamdAddress, IndicatorFile string
}
type Output struct {
	Files      []FileEvidence          `json:"files"`
	Components []assessments.Component `json:"components"`
	Findings   []assessments.Finding   `json:"findings"`
	SBOM       json.RawMessage         `json:"sbom"`
	Stages     []assessments.Stage     `json:"stages"`
}
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("scanner output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func Extract(data []byte, root string) error {
	if len(data) > 64<<20 {
		return errors.New("archive too large")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid gzip archive")
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: (256 << 20) + 1}
	reader := tar.NewReader(limited)
	files := 0
	var total int64
	prefix := ""
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("invalid tar archive")
		}
		if h.Size < 0 || h.Size > 32<<20 {
			return errors.New("archive file limit exceeded")
		}
		name := h.Name
		if strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") {
			return errors.New("unsafe archive path")
		}
		parts := strings.SplitN(strings.TrimSuffix(name, "/"), "/", 2)
		if parts[0] == ".." || parts[0] == "." || parts[0] == "" {
			return errors.New("unsafe archive root")
		}
		if prefix == "" {
			prefix = parts[0]
		}
		if prefix != parts[0] {
			return errors.New("archive contains multiple roots")
		}
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			return errors.New("archive contains links or special files")
		}
		if len(parts) < 2 {
			if h.Typeflag != tar.TypeDir {
				return errors.New("invalid archive root")
			}
			continue
		}
		relative := parts[1]
		if !filepath.IsLocal(relative) {
			return errors.New("unsafe archive path")
		}
		destination := filepath.Join(root, filepath.FromSlash(relative))
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(destination, 0700); err != nil {
				return err
			}
			continue
		}
		files++
		total += h.Size
		if files > 10000 || total > 256<<20 {
			return errors.New("archive expansion limit exceeded")
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("duplicate or invalid archive path")
		}
		_, copyErr := io.CopyN(f, reader, h.Size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("archive extraction failed")
		}
	}
	if limited.N <= 0 || files == 0 {
		return errors.New("archive empty or expansion exceeded")
	}
	return nil
}
func (e Engine) Run(ctx context.Context, archive []byte) (out Output, err error) {
	directory, err := os.MkdirTemp(e.WorkRoot, "scrs-scan-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(directory)
	source := filepath.Join(directory, "checkout")
	if err := os.Mkdir(source, 0700); err != nil {
		return out, err
	}
	if err := Extract(archive, source); err != nil {
		return out, err
	}
	contentCtx, done := context.WithTimeout(ctx, 90*time.Second)
	files, findings, stages := e.inspectContent(contentCtx, source)
	done()
	out.Files = files
	out.Findings = findings
	defer func() {
		out.Stages = append(out.Stages, stages...)
		if len(out.Findings) > 10000 {
			out.Findings = out.Findings[:10000]
			err = errors.New("finding limit exceeded")
		}
		if len(out.Components) > 20000 {
			out.Components = out.Components[:20000]
			err = errors.New("component limit exceeded")
		}
		if err != nil {
			out.Stages = append(out.Stages, assessments.Stage{Name: "inventory", Status: "failed", Detail: "SCA extraction or matching failed; file findings retained"})
			err = nil
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	database, err := pinnedFeed(e.Database)
	if err != nil {
		return out, err
	}
	config := filepath.Join(directory, "policy.toml")
	if err := os.WriteFile(config, []byte("# SCRS: no repository-provided suppressions\n"), 0600); err != nil {
		return out, err
	}
	run := func(format string) ([]byte, error) {
		command := exec.CommandContext(ctx, e.Binary, "scan", "source", "--offline", "--no-resolve", "--no-call-analysis=go,rust", "--no-ignore", "--all-packages", "--all-vulns", "--recursive", "--config", config, "--format", format, source)
		// Never inherit provider, PostgreSQL, Redis, S3 or service-token credentials.
		command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + database, "NO_COLOR=1"}
		command.Dir = directory
		stdout := &cappedBuffer{limit: 32 << 20}
		stderr := &cappedBuffer{limit: 1 << 20}
		command.Stdout = stdout
		command.Stderr = stderr
		err := command.Run()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				return nil, errors.New("offline scanner failed; check feed coverage and input support")
			}
		}
		// Warnings may signal partial package extraction; fail closed rather than
		// treating a parse failure as a successful clean assessment.
		if strings.Contains(strings.ToLower(stderr.String()), "error") || strings.Contains(strings.ToLower(stderr.String()), "warning") {
			return nil, errors.New("scanner reported incomplete coverage")
		}
		if !json.Valid(stdout.Bytes()) {
			return nil, errors.New("invalid scanner JSON")
		}
		return stdout.Bytes(), nil
	}
	raw, err := run("json")
	if err != nil {
		return out, err
	}
	var results struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package         assessments.Component `json:"package"`
				Vulnerabilities []json.RawMessage     `json:"vulnerabilities"`
				Groups          []struct {
					IDs []string `json:"ids"`
					Max string   `json:"max_severity"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &results) != nil {
		return out, errors.New("invalid scanner result")
	}
	for _, result := range results.Results {
		relative, err := filepath.Rel(source, result.Source.Path)
		if err != nil || !filepath.IsLocal(relative) {
			return out, errors.New("scanner source path escaped workspace")
		}
		for _, pkg := range result.Packages {
			c := pkg.Package
			c.Path = filepath.ToSlash(relative)
			if c.PURL == "" {
				return out, errors.New("scanner omitted package identity")
			}
			out.Components = append(out.Components, c)
			for _, raw := range pkg.Vulnerabilities {
				var v struct {
					ID       string `json:"id"`
					Summary  string `json:"summary"`
					Database struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
					Affected []struct {
						Package struct {
							Name      string `json:"name"`
							Ecosystem string `json:"ecosystem"`
						} `json:"package"`
						Ranges []struct {
							Events []struct {
								Fixed string `json:"fixed"`
							} `json:"events"`
						} `json:"ranges"`
					} `json:"affected"`
				}
				if json.Unmarshal(raw, &v) != nil || v.ID == "" {
					return out, errors.New("invalid advisory result")
				}
				severity := strings.ToLower(v.Database.Severity)
				score := 20
				for _, group := range pkg.Groups {
					for _, id := range group.IDs {
						if id == v.ID {
							if cvss, err := strconv.ParseFloat(group.Max, 64); err == nil {
								switch {
								case cvss >= 9:
									severity = "critical"
								case cvss >= 7:
									severity = "high"
								case cvss >= 4:
									severity = "medium"
								case cvss > 0:
									severity = "low"
								}
							}
						}
					}
				}
				switch severity {
				case "critical":
					score = 60
				case "high":
					score = 45
				case "moderate", "medium":
					severity = "medium"
					score = 25
				case "low":
					score = 10
				default:
					severity = "unknown"
				}
				kind := "vulnerability"
				if strings.HasPrefix(v.ID, "MAL-") {
					kind = "malicious_dependency"
					severity = "critical"
					score = 100
				}
				fixed := []string{}
				for _, affected := range v.Affected {
					if affected.Package.Name != c.Name || affected.Package.Ecosystem != c.Ecosystem {
						continue
					}
					for _, r := range affected.Ranges {
						for _, event := range r.Events {
							if event.Fixed != "" {
								fixed = append(fixed, event.Fixed)
							}
						}
					}
				}
				guidance, _ := json.Marshal(map[string]any{"summary": "Review the advisory and upgrade to a compatible fixed version; rerun the assessment.", "fixed_versions": fixed, "reference": "https://osv.dev/vulnerability/" + v.ID, "automatic_changes": false})
				out.Findings = append(out.Findings, assessments.Finding{Type: kind, AdvisoryID: v.ID, Title: v.Summary, Severity: severity, Score: score, Component: c, Evidence: raw, Guidance: guidance})
			}
		}
	}
	if len(out.Components) == 0 || len(out.Components) > 20000 || len(out.Findings) > 10000 {
		return out, errors.New("inventory empty or exceeded limits")
	}
	out.SBOM, err = run("cyclonedx-1-6")
	if err != nil {
		return out, err
	}
	// Never expose ephemeral filesystem paths from the scanner's document.
	out.SBOM = bytes.ReplaceAll(out.SBOM, []byte(source+string(os.PathSeparator)), []byte(""))
	out.Stages = []assessments.Stage{{Name: "inventory", Status: "ok"}, {Name: "sbom", Status: "ok"}, {Name: "match_vuln", Status: "ok"}, {Name: "match_malicious", Status: "ok", Detail: "OSV records in configured feeds"}}

	return out, nil
}
func (e Engine) Handler(token string) http.Handler {
	expected := sha256.Sum256([]byte(token))
	slots := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/healthz" {
			if _, err := pinnedFeed(e.Database); err != nil {
				http.Error(w, "offline feeds unavailable", 503)
			} else {
				w.WriteHeader(200)
			}
			return
		}
		if r.Method != "POST" || (r.URL.Path != "/scan" && r.URL.Path != "/remediate") {
			http.NotFound(w, r)
			return
		}
		provided := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if len(token) < 32 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "scanner busy", 429)
			return
		}
		body, indicators, err := scanInput(w, r)
		if err != nil {
			http.Error(w, "archive too large", 413)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
		defer cancel()
		if r.URL.Path == "/remediate" {
			result, err := e.Remediate(ctx, body, r.URL.Query().Get("manifest"), r.URL.Query().Get("strategy"))
			if err != nil {
				http.Error(w, "remediation unavailable or failed", 422)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(result)
			return
		}
		engine := e
		engine.Indicators = indicators
		result, err := engine.Run(ctx, body)
		if err != nil {
			http.Error(w, "scan failed or incomplete", 422)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}
