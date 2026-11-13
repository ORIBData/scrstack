package scanner

import (
	"archive/tar"
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
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// RunImage assesses a docker-save archive offline (M6): OS and language
// packages, CycloneDX SBOM and OSV/MAL matching, plus ClamAV, YARA and IOC
// inspection of every layer file. Both halves run concurrently so the scan
// fits the worker's deadline.
func (e Engine) RunImage(ctx context.Context, archivePath string) (Output, error) {
	type content struct {
		files    []FileEvidence
		findings []assessments.Finding
		stages   []assessments.Stage
	}
	layers := make(chan content, 1)
	go func() {
		layerCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		files, findings, stages := e.scanLayers(layerCtx, archivePath)
		layers <- content{files, findings, stages}
	}()
	out, err := e.inventoryImage(ctx, archivePath)
	c := <-layers
	out.Files = c.files
	out.Findings = append(c.findings, out.Findings...)
	out.Stages = append(c.stages, out.Stages...)
	if len(out.Findings) > 10000 {
		out.Findings = out.Findings[:10000]
		out.Stages = append(out.Stages, assessments.Stage{Name: "inventory", Status: "failed", Detail: "Finding limit exceeded"})
	}
	return out, err
}

// scanLayers streams every layer through the content scanner. Files deleted by
// later layers are still inspected: they remain in the blobs every pull fetches.
// Only files with a malware verdict other than clean, or with findings, are
// recorded as evidence; whole-image inventories exceed the evidence budget.
func (e Engine) scanLayers(ctx context.Context, archivePath string) ([]FileEvidence, []assessments.Finding, []assessments.Stage) {
	scan := e.newContentScan(ctx, true)
	files := []FileEvidence{}
	image, err := tarball.ImageFromPath(archivePath, nil)
	if err != nil {
		scan.incomplete("Image archive unreadable")
		return files, scan.findings, scan.stages()
	}
	layers, err := image.Layers()
	if err != nil {
		scan.incomplete("Image layers unreadable")
		return files, scan.findings, scan.stages()
	}
	total := 0
	walk := func(layer v1.Layer) error {
		rc, err := layer.Uncompressed()
		if err != nil {
			return err
		}
		defer rc.Close()
		reader := tar.NewReader(rc)
		for {
			h, err := reader.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
			if h.Typeflag != tar.TypeReg || name == "" || strings.HasPrefix(path.Base(name), ".wh.") {
				continue
			}
			if total++; total > 200000 {
				return errors.New("image file limit exceeded")
			}
			before := len(scan.findings)
			record, err := scan.file(ctx, name, h.Size, reader)
			if err != nil {
				return err
			}
			if (record.Malware != "clean" && record.Malware != "skipped") || len(scan.findings) != before {
				if len(files) < 10000 {
					files = append(files, record)
				}
			}
		}
	}
	for _, layer := range layers {
		if err := walk(layer); err != nil {
			scan.incomplete("Layer inspection did not complete: " + err.Error())
			return files, scan.findings, scan.stages()
		}
	}
	scan.malware.Detail += fmt.Sprintf("; %d files across %d layers", total, len(layers))
	return files, scan.findings, scan.stages()
}

// inventoryImage runs the OSV-Scanner half of RunImage.
func (e Engine) inventoryImage(ctx context.Context, archivePath string) (Output, error) {
	out := Output{Files: []FileEvidence{}}
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
