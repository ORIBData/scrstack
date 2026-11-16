package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/dtrack"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/sast"
)

// Component states for GET /system/status.
const (
	statusOK            = "ok"
	statusDegraded      = "degraded"
	statusDown          = "down"
	statusNotConfigured = "not_configured"
)

// statusStore is the part of the assessments store the status view reads.
type statusStore interface {
	SchedulerRuns(context.Context) ([]assessments.SchedulerRun, error)
	VulnerabilitySources(context.Context) ([]assessments.VulnSource, error)
}

// dtrackStatusStore is what the Dependency-Track component reads; the
// assessments store provides it.
type dtrackStatusStore interface {
	DTrackSettings(context.Context) (assessments.DTrackSettings, error)
	DTrackSummary(context.Context) (assessments.DTrackSummary, error)
}

// componentStatus is one dependency's state. Detail is a short fixed
// phrase; raw errors and internal addresses never appear.
type componentStatus struct {
	Status    string         `json:"status"`
	Detail    string         `json:"detail,omitempty"`
	CheckedAt time.Time      `json:"checked_at"`
	Info      map[string]any `json:"info,omitempty"`
}

// platformStatus is the GET /system/status body.
type platformStatus struct {
	Status     string                     `json:"status"`
	CheckedAt  time.Time                  `json:"checked_at"`
	Components map[string]componentStatus `json:"components"`
}

// PlatformStatus reports every component the frontend depends on. Probes run
// concurrently with their own timeouts, and the answer is cached for 10 s so
// polling clients and the monitor cannot multiply load on the backing services.
type PlatformStatus struct {
	dependencies func(context.Context) map[string]error
	store        statusStore
	sast         *sast.Client
	runner       *qa.Runner
	dtHTTP       *http.Client

	mu     sync.Mutex
	latest platformStatus
	cached []byte
	until  time.Time
}

// NewPlatformStatus builds the status view. dependencies probes PostgreSQL,
// Redis and S3 one by one (keys postgres, redis, s3; nil means healthy).
func NewPlatformStatus(dependencies func(context.Context) map[string]error, store statusStore, sastClient *sast.Client, runner *qa.Runner) *PlatformStatus {
	return &PlatformStatus{dependencies: dependencies, store: store, sast: sastClient, runner: runner}
}

// WithDependencyTrack adds the dependency_track component. private lists the
// hosts allowed to resolve to private addresses (SCRS_DTRACK_PRIVATE_HOSTS).
func (h *PlatformStatus) WithDependencyTrack(private map[string]bool) *PlatformStatus {
	h.dtHTTP = dtrack.NewHTTPClient(private)
	return h
}

// current returns the cached status, probing again when it is older than 10 s.
func (h *PlatformStatus) current(ctx context.Context) (platformStatus, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Now().After(h.until) {
		h.latest = h.collect(ctx)
		body, err := json.Marshal(h.latest)
		if err != nil {
			return h.latest, nil, err
		}
		h.cached, h.until = body, time.Now().Add(10*time.Second)
	}
	return h.latest, h.cached, nil
}

// Handler serves GET /system/status.
func (h *PlatformStatus) Handler() http.Handler { return http.HandlerFunc(h.serve) }

func (h *PlatformStatus) serve(w http.ResponseWriter, r *http.Request) {
	_, body, err := h.current(r.Context())
	if err != nil {
		writeError(w, 500, "status unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

func (h *PlatformStatus) collect(parent context.Context) platformStatus {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 4*time.Second)
	defer cancel()
	now := time.Now().UTC()
	out := platformStatus{CheckedAt: now, Components: map[string]componentStatus{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	set := func(name string, c componentStatus) {
		c.CheckedAt = time.Now().UTC()
		mu.Lock()
		out.Components[name] = c
		mu.Unlock()
	}
	out.Components["api"] = componentStatus{Status: statusOK, CheckedAt: now}
	probes := map[string]func(){
		"backing": func() {
			if h.dependencies == nil {
				for _, name := range []string{"postgres", "redis", "s3"} {
					set(name, componentStatus{Status: statusNotConfigured})
				}
				return
			}
			results := h.dependencies(ctx)
			for _, name := range []string{"postgres", "redis", "s3"} {
				if err, ok := results[name]; ok && err != nil {
					set(name, componentStatus{Status: statusDown, Detail: "unavailable"})
				} else {
					set(name, componentStatus{Status: statusOK})
				}
			}
		},
		"scheduler": func() { h.worker(ctx, set) },
		"sast":      func() { set("sast", h.sastStatus(ctx)) },
		"qa_runner": func() { set("qa_runner", h.runnerStatus(ctx)) },
		"dtrack":    func() { set("dependency_track", h.dtrackStatus(ctx)) },
	}
	for _, probe := range probes {
		wg.Add(1)
		go func(probe func()) {
			defer wg.Done()
			probe()
		}(probe)
	}
	wg.Wait()
	out.Status = overall(out.Components)
	return out
}

// worker derives the worker and scanner states from what the worker records:
// feed_monitor runs every five minutes whenever a worker is alive, and its
// failure means the scanner could not be reached or reported unhealthy feeds.
func (h *PlatformStatus) worker(ctx context.Context, set func(string, componentStatus)) {
	runs, err := h.store.SchedulerRuns(ctx)
	if err != nil {
		set("worker", componentStatus{Status: statusDown, Detail: "scheduler state unreadable"})
		set("scanner", componentStatus{Status: statusDown, Detail: "scheduler state unreadable"})
		set("feeds", componentStatus{Status: statusDown, Detail: "scheduler state unreadable"})
		return
	}
	var monitor *assessments.SchedulerRun
	for i := range runs {
		if runs[i].Job == "feed_monitor" {
			monitor = &runs[i]
		}
	}
	switch {
	case monitor == nil || monitor.LastFinishedAt == nil:
		set("worker", componentStatus{Status: statusDown, Detail: "no worker heartbeat recorded yet"})
		set("scanner", componentStatus{Status: statusDegraded, Detail: "unknown until the worker reports"})
	default:
		// Three missed five-minute passes means the worker is gone.
		age := time.Since(*monitor.LastFinishedAt)
		worker := componentStatus{Status: statusOK, Info: map[string]any{"last_heartbeat_at": monitor.LastFinishedAt}}
		if age > 15*time.Minute {
			worker.Status, worker.Detail = statusDown, "no heartbeat for over 15 minutes"
		}
		set("worker", worker)
		if monitor.LastStatus == "ok" {
			set("scanner", componentStatus{Status: statusOK})
		} else {
			set("scanner", componentStatus{Status: statusDown, Detail: "scanner unreachable or its feeds are unavailable"})
		}
	}
	sources, err := h.store.VulnerabilitySources(ctx)
	if err != nil {
		set("feeds", componentStatus{Status: statusDown, Detail: "feed state unreadable"})
		return
	}
	stale := []string{}
	enabled := 0
	for _, s := range sources {
		if !s.Enabled {
			continue
		}
		enabled++
		if s.Stale {
			stale = append(stale, s.Key)
		}
	}
	sort.Strings(stale)
	feeds := componentStatus{Status: statusOK, Info: map[string]any{"enabled_sources": enabled, "stale_sources": stale}}
	if len(stale) > 0 {
		feeds.Status, feeds.Detail = statusDegraded, "some vulnerability sources are stale; SCA coverage may be incomplete"
	}
	set("feeds", feeds)
}

func (h *PlatformStatus) sastStatus(ctx context.Context) componentStatus {
	if h.sast == nil {
		return componentStatus{Status: statusNotConfigured}
	}
	analyzers, _, err := h.sast.Analyzers(ctx)
	if err != nil {
		return componentStatus{Status: statusDown, Detail: "service unreachable"}
	}
	broken := []string{}
	enabled := 0
	for _, a := range analyzers {
		if !a.Enabled {
			continue
		}
		enabled++
		if a.Version == "unavailable" {
			broken = append(broken, a.Name)
		}
	}
	sort.Strings(broken)
	c := componentStatus{Status: statusOK, Info: map[string]any{"enabled_analyzers": enabled, "unavailable_analyzers": broken}}
	if len(broken) > 0 {
		c.Status, c.Detail = statusDegraded, "an enabled analyzer is unavailable"
	}
	return c
}

func (h *PlatformStatus) runnerStatus(ctx context.Context) componentStatus {
	if h.runner == nil {
		return componentStatus{Status: statusNotConfigured}
	}
	info, err := h.runner.Info(ctx)
	if err != nil {
		return componentStatus{Status: statusDown, Detail: "runner unreachable"}
	}
	return componentStatus{Status: statusOK, Info: map[string]any{"karate": info.Karate, "gatling": info.Gatling, "slots": info.Slots, "queued": info.Queued, "running": info.Running}}
}

// dtrackStatus reports the optional Dependency-Track export. It is not
// configured while the export is off; when on, the server's public version
// endpoint shows reachability, and the upload table shows the backlog and
// recent failures (uploads rejected, or accepted but not imported).
func (h *PlatformStatus) dtrackStatus(ctx context.Context) componentStatus {
	store, ok := h.store.(dtrackStatusStore)
	if !ok || h.dtHTTP == nil {
		return componentStatus{Status: statusNotConfigured}
	}
	settings, err := store.DTrackSettings(ctx)
	if err != nil {
		return componentStatus{Status: statusDown, Detail: "export state unreadable"}
	}
	if !settings.Enabled {
		return componentStatus{Status: statusNotConfigured, Detail: "export is off"}
	}
	summary, err := store.DTrackSummary(ctx)
	if err != nil {
		return componentStatus{Status: statusDown, Detail: "export state unreadable"}
	}
	info := map[string]any{"queued_uploads": summary.Queued, "failed_uploads_24h": summary.FailedLast24h, "import_failures_24h": summary.ProcessingFailed24h, "unverified_uploads": summary.Unverified}
	if summary.LastUploadedAt != nil {
		info["last_upload_at"] = summary.LastUploadedAt
	}
	if summary.LastProcessedAt != nil {
		info["last_import_confirmed_at"] = summary.LastProcessedAt
	}
	version, err := dtrack.Client{BaseURL: settings.URL, HTTP: h.dtHTTP}.Version(ctx)
	if err != nil {
		return componentStatus{Status: statusDown, Detail: "server unreachable", Info: info}
	}
	info["version"] = version
	c := componentStatus{Status: statusOK, Info: info}
	switch {
	case summary.FailedLast24h > 0 || summary.ProcessingFailed24h > 0:
		c.Status, c.Detail = statusDegraded, "uploads failed in the last 24 hours; see GET /integrations/dependency-track/uploads"
	case summary.OldestQueued != nil && time.Since(*summary.OldestQueued) > 15*time.Minute:
		c.Status, c.Detail = statusDegraded, "uploads have been waiting for over 15 minutes"
	}
	return c
}

// overall is down when a backing service the API needs is down, degraded when
// any other configured component is not ok, and ok otherwise.
func overall(components map[string]componentStatus) string {
	result := statusOK
	for name, c := range components {
		switch {
		case c.Status == statusOK || c.Status == statusNotConfigured:
		case c.Status == statusDown && (name == "postgres" || name == "redis" || name == "s3"):
			return statusDown
		default:
			result = statusDegraded
		}
	}
	return result
}

// StatusAnnouncer records a status change and announces it once across API
// instances (notify.Store.PlatformTransition).
type StatusAnnouncer interface {
	PlatformTransition(ctx context.Context, status string, components []map[string]any) (bool, error)
}

// Monitor watches the platform until ctx ends and announces changes as
// system.degraded and system.recovered events. A status must hold for
// confirm consecutive checks, every apart, before it is announced, so a brief
// blip or a redeploy does not alert; the first check waits grace. Announcing
// needs PostgreSQL, so an outage of PostgreSQL itself is not announced.
func (h *PlatformStatus) Monitor(ctx context.Context, announcer StatusAnnouncer, every, grace time.Duration, confirm int, logger *slog.Logger) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(grace):
	}
	acted, pending, seen := "", "", 0
	for {
		current, _, _ := h.current(ctx)
		if current.Status == pending {
			seen++
		} else {
			pending, seen = current.Status, 1
		}
		if seen >= confirm && pending != acted {
			bad := []map[string]any{}
			names := make([]string, 0, len(current.Components))
			for name := range current.Components {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if c := current.Components[name]; c.Status == statusDegraded || c.Status == statusDown {
					bad = append(bad, map[string]any{"name": name, "status": c.Status, "detail": c.Detail})
				}
			}
			emitted, err := announcer.PlatformTransition(ctx, pending, bad)
			switch {
			case err != nil && ctx.Err() == nil:
				logger.Warn("platform status change not recorded", "status", pending, "error", err)
			case err == nil:
				acted = pending
				if emitted {
					logger.Info("platform status changed", "status", pending)
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
