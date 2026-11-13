package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
)

// RunImage inventories a docker-save archive offline (M6): OS and language
// packages, CycloneDX SBOM and OSV/MAL matching. Layer malware, YARA, IOC and
// integrity analysis are not yet applied to images; those stages report
// skipped so the verdict can never be pass on partial coverage.
func (e Engine) RunImage(ctx context.Context, archivePath string) (Output, error) {
	out := Output{Files: []FileEvidence{}}
	for _, name := range []string{"malware", "yara", "ioc", "integrity"} {
		out.Stages = append(out.Stages, assessments.Stage{Name: name, Status: "skipped", Detail: "Not yet applied to container image layers"})
	}
	database, err := pinnedFeed(e.Database)
	if err != nil {
		out.Stages = append(out.Stages, assessments.Stage{Name: "inventory", Status: "failed", Detail: "Offline feeds unavailable"})
		return out, nil
	}
	directory := filepath.Dir(archivePath)
	config := filepath.Join(directory, "policy.toml")
	if err := os.WriteFile(config, []byte("# SCRS: no image-provided suppressions\n"), 0600); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	run := func(format string) ([]byte, error) {
		command := exec.CommandContext(ctx, e.Binary, "scan", "image", "--archive", "--offline", "--all-packages", "--all-vulns", "--config", config, "--format", format, archivePath)
		command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + database, "NO_COLOR=1"}
		command.Dir = directory
		stdout := &cappedBuffer{limit: 32 << 20}
		stderr := &cappedBuffer{limit: 1 << 20}
		command.Stdout, command.Stderr = stdout, stderr
		err := command.Run()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var exit *exec.ExitError
		if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
			return nil, errors.New("offline image scan failed; check ecosystem feeds for the image's OS")
		}
		if reportsProblem(stderr.String()) || !json.Valid(stdout.Bytes()) {
			return nil, errors.New("image scanner reported incomplete coverage")
		}
		return stdout.Bytes(), nil
	}
	failed := func(detail string) (Output, error) {
		out.Stages = append(out.Stages, assessments.Stage{Name: "inventory", Status: "failed", Detail: detail})
		return out, nil
	}
	raw, err := run("json")
	if err != nil {
		return failed(err.Error())
	}
	enrich := loadEnrichment(database)
	components, findings, err := e.parseResults(raw, enrich, func(p string) (string, error) {
		cleaned := strings.TrimPrefix(path.Clean("/"+p), "/")
		if cleaned == "" || strings.Contains(cleaned, "..") {
			return "", errors.New("invalid in-image path")
		}
		return cleaned, nil
	})
	out.Components, out.Findings = components, findings
	if err != nil || len(components) == 0 || len(components) > 20000 || len(findings) > 10000 {
		return failed("Image inventory empty, invalid or over limits")
	}
	if out.SBOM, err = run("cyclonedx-1-6"); err != nil {
		return failed(err.Error())
	}
	out.SBOM = bytes.ReplaceAll(out.SBOM, []byte(archivePath), []byte("image"))
	enrichStage := assessments.Stage{Name: "enrich", Status: "skipped", Detail: "KEV and EPSS feeds not available in this snapshot"}
	if enrich != nil {
		enrichStage = assessments.Stage{Name: "enrich", Status: "ok", Detail: fmt.Sprintf("CISA KEV (%d) and EPSS (%d) exploitation context", len(enrich.kev), len(enrich.epss))}
	}
	out.Stages = append(out.Stages, assessments.Stage{Name: "inventory", Status: "ok", Detail: "OS and language packages from image layers"}, assessments.Stage{Name: "sbom", Status: "ok"}, assessments.Stage{Name: "match_vuln", Status: "ok"}, assessments.Stage{Name: "match_malicious", Status: "ok", Detail: "OSV records in configured feeds"}, enrichStage)
	return out, nil
}

// imageHandler streams an image archive to the scanner's tmpfs under a size
// cap, so the worker never buffers whole images in memory.
func (e Engine) imageHandler(expected [32]byte, slots chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "scanner busy", http.StatusTooManyRequests)
			return
		}
		limit := e.MaxImageBytes
		if limit <= 0 {
			limit = 1 << 30
		}
		directory, err := os.MkdirTemp(e.WorkRoot, "scrs-image-")
		if err != nil {
			http.Error(w, "work area unavailable", http.StatusInsufficientStorage)
			return
		}
		defer os.RemoveAll(directory)
		archive := filepath.Join(directory, "image.tar")
		f, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			http.Error(w, "work area unavailable", http.StatusInsufficientStorage)
			return
		}
		n, copyErr := io.Copy(f, io.LimitReader(r.Body, limit+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || n > limit {
			slog.Warn("image upload rejected", "bytes", n, "error", copyErr)
			http.Error(w, "image archive too large or incomplete", http.StatusRequestEntityTooLarge)
			return
		}
		result, err := e.RunImage(r.Context(), archive)
		if err != nil {
			slog.Warn("image scan failed", "error", err)
			http.Error(w, "image scan failed", http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}
