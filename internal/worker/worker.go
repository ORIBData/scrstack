package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/scanner"
)

type Artifacts interface {
	PutSBOM(context.Context, []byte) (string, string, error)
	PutPlan(context.Context, []byte) (string, string, error)
}

// ImageSource streams a registry image as a docker-save archive (M6).
type ImageSource interface {
	ImageArchive(context.Context, connections.Connection, json.RawMessage, string, string, string, string, int64, io.Writer) (string, error)
}

type Snapshotter interface {
	GitHubSnapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error)
}
type Worker struct {
	Source                   Snapshotter
	Images                   ImageSource
	MaxImageBytes            int64
	Store                    *assessments.Store
	Connections              *connections.Store
	Artifacts                Artifacts
	ScannerURL, ScannerToken string
	Logger                   *slog.Logger
	AutoRemediation          bool
	Notify                   *notify.Store
	// Snapshots stores each fetched source archive for restore (INT-006).
	Snapshots interface {
		PutSnapshot(context.Context, []byte) (string, error)
	}
}

// MonitorFeeds polls the scanner's feed health and emits feed.stale once per
// healthy-to-stale transition, so subscribers learn that coverage degraded.
func (w Worker) MonitorFeeds(ctx context.Context, every time.Duration) {
	endpoint, err := url.Parse(w.ScannerURL)
	if err != nil || w.Notify == nil {
		return
	}
	endpoint.Path, endpoint.RawQuery = "/healthz", ""
	client := &http.Client{Timeout: 5 * time.Second}
	healthy := true
	for {
		stale := false
		if resp, err := client.Get(endpoint.String()); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			stale = resp.StatusCode == http.StatusServiceUnavailable
		}
		if stale && healthy {
			emitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := w.Notify.EmitNow(emitCtx, "feed.stale", map[string]any{"feed": "osv", "detail": "offline vulnerability feeds are missing or older than 24 hours; assessments report incomplete SCA coverage"}); err != nil {
				w.Logger.Warn("feed.stale event not recorded", "error", err)
			} else {
				healthy = false
			}
			cancel()
		} else if !stale {
			healthy = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (w Worker) Run(ctx context.Context) error {
	endpoint, err := url.Parse(w.ScannerURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || len(w.ScannerToken) < 32 {
		return errors.New("invalid internal scanner configuration")
	}
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if w.AutoRemediation {
			dispatchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := w.Store.DispatchAutomaticPlan(dispatchCtx)
			cancel()
			if err != nil {
				w.Logger.Warn("automatic remediation dispatch deferred", "error", err)
			}
		}
		a, err := w.Store.Claim(ctx)
		if err != nil {
			if !errors.Is(err, assessments.ErrNotFound) {
				w.Logger.Error("assessment claim failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
				continue
			}
		}
		deadline := 5 * time.Minute
		if a.Request.Target.Type == "image" {
			deadline = 9 * time.Minute // registry download plus scan; lease is 10 minutes
		}
		jobCtx, cancel := context.WithTimeout(ctx, deadline)
		err = w.run(jobCtx, &a)
		cancel()
		if err != nil {
			failureCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			retry := !errors.Is(err, assessments.ErrScope)
			if failErr := w.Store.Fail(failureCtx, a, "assessment stage failed; scan coverage incomplete", retry); failErr != nil && !errors.Is(failErr, assessments.ErrLease) {
				w.Logger.Error("assessment failure persistence failed", "assessment_id", a.ID, "error", failErr)
			}
			done()
			// Provider, scanner and store errors are sanitized at their source;
			// operators need the cause, which the stored assessment keeps generic.
			w.Logger.Warn("assessment failed", "assessment_id", a.ID, "attempt", a.Attempts, "retry", retry, "error", err)
		}
	}
}
func (w Worker) run(ctx context.Context, a *assessments.Assessment) error {
	name, err := w.Connections.NameByID(ctx, a.ConnectionID)
	if err != nil {
		return assessments.ErrScope
	}
	c, secret, err := w.Connections.Get(ctx, name)
	if err != nil {
		return err
	}
	if !c.Enabled || c.ConfigurationRevision != a.ConnectionRevision {
		return assessments.ErrScope
	}
	revision := a.Commit
	if revision == "" {
		revision = a.Request.Target.Commit
	}
	if a.Request.Target.Type == "image" {
		return w.runImage(ctx, a, c, secret, revision)
	}
	source := w.Source
	if source == nil {
		source = connections.NewNativeAdapters()
	}
	ref := a.Request.Target.Ref
	if a.Request.Target.PullRequest != nil {
		ref = ""
	}
	archive, commit, moved, err := source.GitHubSnapshot(ctx, c, secret, a.Request.Target.Repository, ref, revision)
	if err != nil {
		return err
	}
	if err = w.Store.BindRevision(ctx, *a, commit, moved); err != nil {
		return err
	}
	a.Commit = commit
	if w.Snapshots != nil && a.Request.Remediation == nil {
		key, err := w.Snapshots.PutSnapshot(ctx, archive)
		if err != nil {
			return err
		}
		if err := w.Store.RecordSnapshot(ctx, *a, key); err != nil {
			return err
		}
	}
	endpoint := w.ScannerURL
	if a.Request.Remediation != nil {
		target, _ := url.Parse(endpoint)
		target.Path = "/remediate"
		query := url.Values{}
		query.Set("manifest", a.Request.Remediation.Manifest)
		query.Set("strategy", a.Request.Remediation.Strategy)
		target.RawQuery = query.Encode()
		endpoint = target.String()
	}
	payload := archive
	contentType := "application/gzip"
	if a.Request.Remediation == nil {
		bundle, err := w.Store.ActiveIndicators(ctx)
		if err != nil {
			return err
		}
		if len(bundle) > 0 {
			var body bytes.Buffer
			m := multipart.NewWriter(&body)
			part, err := m.CreateFormFile("archive", "snapshot.tar.gz")
			if err != nil {
				return err
			}
			if _, err = part.Write(archive); err != nil {
				return err
			}
			if err = m.WriteField("indicators", string(bundle)); err != nil {
				return err
			}
			if err = m.Close(); err != nil {
				return err
			}
			payload = body.Bytes()
			contentType = m.FormDataContentType()
		}
	}
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+w.ScannerToken)
	request.Header.Set("Content-Type", contentType)
	client := &http.Client{Timeout: 4 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("scanner unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("scanner failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		return errors.New("scanner result exceeded limit")
	}
	if a.Request.Remediation != nil {
		if !json.Valid(data) {
			return errors.New("invalid remediation result")
		}
		key, digest, err := w.Artifacts.PutPlan(ctx, data)
		if err != nil {
			return err
		}
		return w.Store.CompletePlan(ctx, *a, key, digest)
	}
	var output scanner.Output
	if json.Unmarshal(data, &output) != nil {
		return errors.New("invalid scanner result")
	}
	var key, digest string
	if len(output.SBOM) > 0 {
		key, digest, err = w.Artifacts.PutSBOM(ctx, output.SBOM)
		if err != nil {
			return err
		}
	}
	stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}}
	stages = append(stages, output.Stages...)
	return w.Store.Complete(ctx, *a, assessments.Result{Files: output.Files, Commit: commit, RefMoved: moved, Stages: stages, Components: output.Components, Findings: output.Findings, SBOMKey: key, SBOMSHA256: digest, Complete: true})
}

// Maintain runs retention, idempotency expiry and optional default-branch
// rescans on a schedule (M13, M14, ING-007). One replica wins each pass.
func (w Worker) Maintain(ctx context.Context, every, rescan time.Duration) {
	for {
		passCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		report, err := w.Store.Maintain(passCtx, assessments.SchedulerActor, "scheduled")
		if err != nil {
			w.Logger.Warn("scheduled maintenance failed", "error", err)
		} else if !report.Skipped {
			if rescan > 0 {
				report.Rescans, err = w.Store.EnqueueRescans(passCtx, rescan, 500)
				if err != nil {
					w.Logger.Warn("scheduled rescans failed", "error", err)
				}
			}
			w.Logger.Info("scheduled maintenance completed", "report", report)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// runImage streams the image from the registry straight to the scanner, so
// neither side holds the whole archive in memory, then publishes like a scan.
func (w Worker) runImage(ctx context.Context, a *assessments.Assessment, c connections.Connection, secret json.RawMessage, digest string) error {
	images := w.Images
	if images == nil {
		images = connections.NewNativeAdapters()
	}
	limit := w.MaxImageBytes
	if limit <= 0 {
		limit = 400 << 20
	}
	endpoint, err := url.Parse(w.ScannerURL)
	if err != nil {
		return err
	}
	endpoint.Path, endpoint.RawQuery = "/scan-image", ""
	reader, writer := io.Pipe()
	type resolved struct {
		digest string
		err    error
	}
	done := make(chan resolved, 1)
	go func() {
		d, err := images.ImageArchive(ctx, c, secret, a.Request.Target.Repository, a.Request.Target.Ref, digest, a.Request.Target.Platform, limit, writer)
		writer.CloseWithError(err)
		done <- resolved{d, err}
	}()
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), reader)
	if err != nil {
		reader.CloseWithError(err)
		<-done
		return err
	}
	request.Header.Set("Authorization", "Bearer "+w.ScannerToken)
	request.Header.Set("Content-Type", "application/x-tar")
	client := &http.Client{Timeout: 8 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	reader.CloseWithError(errors.New("scanner request finished"))
	result := <-done
	if result.err != nil {
		if response != nil {
			response.Body.Close()
		}
		return result.err
	}
	if err != nil {
		return errors.New("scanner unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("image scanner failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		return errors.New("scanner result exceeded limit")
	}
	var output scanner.Output
	if json.Unmarshal(data, &output) != nil {
		return errors.New("invalid scanner result")
	}
	if err := w.Store.BindRevision(ctx, *a, result.digest, false); err != nil {
		return err
	}
	a.Commit = result.digest
	var key, sbomDigest string
	if len(output.SBOM) > 0 {
		if key, sbomDigest, err = w.Artifacts.PutSBOM(ctx, output.SBOM); err != nil {
			return err
		}
	}
	stages := append([]assessments.Stage{{Name: "resolve", Status: "ok", Detail: "Tag resolved to platform manifest digest"}, {Name: "fetch", Status: "ok"}}, output.Stages...)
	return w.Store.Complete(ctx, *a, assessments.Result{Files: output.Files, Commit: result.digest, Stages: stages, Components: output.Components, Findings: output.Findings, SBOMKey: key, SBOMSHA256: sbomDigest, Complete: true})
}
