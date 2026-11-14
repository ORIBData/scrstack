package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// errScannerBusy is the scanner's 429: its single slot serves another worker.
var errScannerBusy = errors.New("scanner busy")

// errScannerRejected is the scanner's 413 for a source archive over its limits.
var errScannerRejected = errors.New("scanner rejected archive size or file limits")

type Artifacts interface {
	PutSBOM(context.Context, []byte) (string, string, error)
	PutPlan(context.Context, []byte) (string, string, error)
}

// ImageSource streams a registry image as a docker-save archive (M6).
type ImageSource interface {
	ImageArchive(context.Context, connections.Connection, json.RawMessage, string, string, string, string, int64, io.Writer) (string, error)
}

type Snapshotter interface {
	Snapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error)
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
	// Mirrors stores git history bundles (INT-006); nil disables mirroring.
	Mirrors interface {
		PutMirror(context.Context, string, io.Reader) (string, int64, error)
		DeleteMirror(context.Context, string) error
	}
	MirrorSource interface {
		Mirror(context.Context, connections.Connection, json.RawMessage, string, int64, io.Writer) (connections.MirrorInfo, error)
	}
	MaxMirrorBytes int64
	KeepMirrors    int
	// MirrorMinAgeDays protects bundles younger than this from pruning.
	MirrorMinAgeDays int
}

// RunMirrors processes queued mirror requests one at a time. A bundle streams
// from the git host through a SHA-256 hash into S3 without touching disk.
func (w Worker) RunMirrors(ctx context.Context) {
	if w.Mirrors == nil {
		return
	}
	for {
		m, err := w.Store.ClaimMirror(ctx)
		if err != nil {
			if !errors.Is(err, assessments.ErrNotFound) && ctx.Err() == nil {
				w.Logger.Warn("mirror claim failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		jobCtx, cancel := context.WithTimeout(ctx, 25*time.Minute)
		result, err := w.mirror(jobCtx, m)
		cancel()
		failure := ""
		if err != nil {
			failure = err.Error()
			w.Logger.Warn("mirror failed", "mirror_id", m.ID, "error", err)
		}
		finishCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		pruned, err := w.Store.FinishMirror(finishCtx, m, result, failure, w.KeepMirrors, w.MirrorMinAgeDays)
		if err != nil {
			w.Logger.Error("mirror result not recorded", "mirror_id", m.ID, "error", err)
		}
		for _, key := range pruned {
			if err := w.Mirrors.DeleteMirror(finishCtx, key); err != nil {
				w.Logger.Warn("pruned mirror object not deleted", "key", key, "error", err)
			}
		}
		done()
	}
}

func (w Worker) mirror(ctx context.Context, m assessments.Mirror) (*assessments.Mirror, error) {
	name, err := w.Connections.NameByID(ctx, m.ConnectionID)
	if err != nil {
		return nil, errors.New("connection unavailable")
	}
	c, secret, err := w.Connections.Get(ctx, name)
	if err != nil {
		return nil, errors.New("connection unavailable")
	}
	source := w.MirrorSource
	if source == nil {
		source = connections.NewNativeAdapters()
	}
	limit := w.MaxMirrorBytes
	if limit <= 0 {
		limit = 2 << 30
	}
	reader, writer := io.Pipe()
	hash := sha256.New()
	type outcome struct {
		info connections.MirrorInfo
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		info, err := source.Mirror(ctx, c, secret, m.Locator, limit, io.MultiWriter(writer, hash))
		writer.CloseWithError(err)
		done <- outcome{info, err}
	}()
	key, size, putErr := w.Mirrors.PutMirror(ctx, m.ID.String(), reader)
	reader.CloseWithError(errors.New("upload finished"))
	fetched := <-done
	if fetched.err != nil {
		if key != "" {
			_ = w.Mirrors.DeleteMirror(context.WithoutCancel(ctx), key)
		}
		return nil, fetched.err
	}
	if putErr != nil {
		return nil, errors.New("mirror upload failed")
	}
	return &assessments.Mirror{ObjectKey: key, SHA256: hex.EncodeToString(hash.Sum(nil)), SizeBytes: size, Refs: fetched.info.Refs, Head: fetched.info.Head}, nil
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
		if errors.Is(err, errScannerBusy) {
			// Back-pressure from another worker's scan is not a failed attempt.
			releaseCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			if releaseErr := w.Store.Release(releaseCtx, a, 15*time.Second); releaseErr != nil && !errors.Is(releaseErr, assessments.ErrLease) {
				w.Logger.Error("assessment requeue failed", "assessment_id", a.ID, "error", releaseErr)
			}
			done()
			// Pause before claiming again so a busy scanner is not hammered.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if err != nil {
			failureCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			retry, message := failurePolicy(err)
			if failErr := w.Store.Fail(failureCtx, a, message, retry); failErr != nil && !errors.Is(failErr, assessments.ErrLease) {
				w.Logger.Error("assessment failure persistence failed", "assessment_id", a.ID, "error", failErr)
			}
			done()
			// Provider, scanner and store errors are sanitized at their source;
			// operators need the cause, which the stored assessment keeps generic.
			w.Logger.Warn("assessment failed", "assessment_id", a.ID, "attempt", a.Attempts, "retry", retry, "error", err)
		}
	}
}

// failurePolicy decides whether a failed attempt is retried and the reason
// stored on the assessment. Scope withdrawal and size-limit rejections are
// deterministic: retrying them only repeats the download.
func failurePolicy(err error) (bool, string) {
	if errors.Is(err, connections.ErrTooLarge) || errors.Is(err, errScannerRejected) {
		return false, "source exceeds SCRS size limits; not retried"
	}
	return !errors.Is(err, assessments.ErrScope), "assessment stage failed; scan coverage incomplete"
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
	if !c.Enabled || c.ConfigurationRevision != a.ConnectionRevision || a.Request.Import != nil {
		// An import whose recording was interrupted is not scanned instead.
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
	// Fetch by the locator discovery recorded: requests are lowercased, and
	// not every git host resolves paths case-insensitively.
	asset, err := w.Connections.Asset(ctx, a.AssetID)
	if err != nil {
		return assessments.ErrScope
	}
	archive, commit, moved, err := source.Snapshot(ctx, c, secret, asset.Locator, ref, revision)
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
	var payload io.Reader = bytes.NewReader(archive)
	contentType := "application/gzip"
	if a.Request.Remediation == nil {
		intel, err := w.scanContext(ctx)
		if err != nil {
			return err
		}
		if len(intel) > 0 {
			// Stream the multipart body so the archive is not held twice.
			reader, writer := io.Pipe()
			m := multipart.NewWriter(writer)
			go func() {
				err := writeContext(m, intel)
				if err == nil {
					var part io.Writer
					if part, err = m.CreateFormFile("archive", "snapshot.tar.gz"); err == nil {
						_, err = part.Write(archive)
					}
				}
				if err == nil {
					err = m.Close()
				}
				writer.CloseWithError(err)
			}()
			defer reader.Close()
			payload = reader
			contentType = m.FormDataContentType()
		}
	}
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, payload)
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
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return errScannerBusy
	case http.StatusRequestEntityTooLarge:
		return errScannerRejected
	default:
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
func (w Worker) Maintain(ctx context.Context, every, rescan, mirror time.Duration) {
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
			if mirror > 0 && w.Mirrors != nil {
				if queued, err := w.Store.ScheduleMirrors(passCtx, mirror); err != nil {
					w.Logger.Warn("scheduled mirrors failed", "error", err)
				} else if queued > 0 {
					w.Logger.Info("scheduled mirrors queued", "count", queued)
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

// CheckGitHubHooks runs the GitHub webhook delivery check on a schedule:
// GitHub never retries a failed delivery, so this requests redelivery of
// events SCRS missed and alerts on hooks that would drop them.
func (w Worker) CheckGitHubHooks(ctx context.Context, every time.Duration, hookURL string) {
	api := connections.NewNativeAdapters()
	for {
		passCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		checks, ran, err := w.Connections.CheckGitHubHooks(passCtx, api, hookURL, time.Now())
		cancel()
		if err != nil {
			w.Logger.Warn("GitHub webhook check failed", "error", err)
		} else if ran {
			for _, c := range checks {
				if c.State != "ok" || c.Redelivered > 0 {
					w.Logger.Warn("GitHub webhook check", "connection", c.Connection, "state", c.State, "redelivered", c.Redelivered, "abandoned", c.Abandoned, "problems", c.Problems)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// scanContext returns the scan request parts that carry threat intelligence:
// the enabled indicator sources and the enabled YARA-X rulesets, in that order.
func (w Worker) scanContext(ctx context.Context) ([][2]string, error) {
	var parts [][2]string
	bundle, err := w.Store.ScanIndicators(ctx)
	if err != nil {
		return nil, err
	}
	if len(bundle) > 0 {
		parts = append(parts, [2]string{"indicators", string(bundle)})
	}
	rules, err := w.Store.ActiveRulePack(ctx)
	if err != nil {
		return nil, err
	}
	if len(rules) > 0 {
		parts = append(parts, [2]string{"rules", string(rules)})
	}
	return parts, nil
}

func writeContext(m *multipart.Writer, parts [][2]string) error {
	for _, p := range parts {
		if err := m.WriteField(p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
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
	intel, err := w.scanContext(ctx)
	if err != nil {
		return err
	}
	reader, writer := io.Pipe()
	// Indicators and rules go first; the image streams last as its own part.
	m := multipart.NewWriter(writer)
	type resolved struct {
		digest string
		err    error
	}
	done := make(chan resolved, 1)
	go func() {
		var d string
		err := writeContext(m, intel)
		if err == nil {
			var part io.Writer
			if part, err = m.CreateFormFile("image", "image.tar"); err == nil {
				d, err = images.ImageArchive(ctx, c, secret, a.Request.Target.Repository, a.Request.Target.Ref, digest, a.Request.Target.Platform, limit, part)
			}
		}
		if err == nil {
			err = m.Close()
		}
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
	request.Header.Set("Content-Type", m.FormDataContentType())
	client := &http.Client{Timeout: 8 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	reader.CloseWithError(errors.New("scanner request finished"))
	result := <-done
	// A busy scanner closes the stream early; report that, not the broken pipe.
	if err == nil && response.StatusCode == http.StatusTooManyRequests {
		response.Body.Close()
		return errScannerBusy
	}
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
