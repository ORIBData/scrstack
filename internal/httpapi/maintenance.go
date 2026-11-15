package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/netguard"
	"github.com/ORIBData/scrstack/internal/qa"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
)

// maintenanceHandler exposes audited admin actions (M14) and the inbound
// event log with replay (ING-008, INT-016).
type maintenanceHandler struct {
	store  *assessments.Store
	events *notify.Store
	runner *qa.Runner
}

func (h maintenanceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath)
	switch {
	case path == "/maintenance/run" && r.Method == http.MethodPost:
		report, err := h.store.Maintain(ctx, actor.ID, "manual")
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 200, report)
	case path == "/maintenance/rescan" && r.Method == http.MethodPost:
		queued, err := h.store.EnqueueRescans(ctx, 0, 500)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 202, map[string]int{"rescans_queued": queued})
	case path == "/maintenance/redeliver-dead" && r.Method == http.MethodPost:
		if h.events == nil {
			writeError(w, 503, "webhook store unavailable")
			return
		}
		n, err := h.events.RedeliverDead(ctx)
		if err != nil {
			writeError(w, 500, "redelivery failed")
			return
		}
		writeJSON(w, 202, map[string]int64{"deliveries_requeued": n})
	case path == "/maintenance/reset" && r.Method == http.MethodPost:
		var input struct {
			Scope    string    `json:"scope"`
			AssetID  uuid.UUID `json:"asset_id"`
			SourceID uuid.UUID `json:"source_id"`
			Confirm  string    `json:"confirm"`
		}
		if !readBody(w, r, &input) {
			return
		}
		if _, ok := assessments.ResetScopes[input.Scope]; !ok {
			writeJSON(w, 400, map[string]any{"error": "unknown reset scope", "scopes": assessments.ResetScopes})
			return
		}
		if input.Confirm != input.Scope {
			writeError(w, 400, "set confirm to the scope name to reset")
			return
		}
		target := input.AssetID
		if input.Scope == "indicators" {
			target = input.SourceID
		}
		removed, err := h.store.Reset(ctx, input.Scope, target, actor.ID)
		switch {
		case errors.Is(err, assessments.ErrLegalHold):
			writeError(w, 409, err.Error())
		case errors.Is(err, assessments.ErrInput):
			writeError(w, 400, "this scope needs asset_id or source_id")
		case err != nil:
			assessmentError(w, err)
		default:
			writeJSON(w, 200, map[string]any{"scope": input.Scope, "removed": removed})
		}
	case path == "/maintenance/rebuild" && r.Method == http.MethodPost:
		queued, err := h.store.Rebuild(ctx, actor.ID, 500)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 202, map[string]int{"assessments_queued": queued})
	case path == "/maintenance/update-sensors" && r.Method == http.MethodPost:
		due, err := h.store.UpdateSensors(ctx, actor.ID)
		if err != nil {
			assessmentError(w, err)
			return
		}
		sources, err := h.store.VulnerabilitySources(ctx)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"due_now": due, "sources": sources})
	case path == "/maintenance/schedule" && r.Method == http.MethodGet:
		runs, err := h.store.SchedulerRuns(ctx)
		if err != nil {
			assessmentError(w, err)
			return
		}
		sources, err := h.store.VulnerabilitySources(ctx)
		if err != nil {
			assessmentError(w, err)
			return
		}
		feeds := []map[string]any{}
		for _, src := range sources {
			if src.ManagedBy == "operator" {
				continue
			}
			feeds = append(feeds, map[string]any{"job": "source:" + src.Key, "managed_by": src.ManagedBy, "interval_seconds": src.ScheduleMinutes * 60, "enabled": src.Enabled, "last_started_at": src.LastSyncAt, "last_success_at": src.LastSuccessAt, "last_error": src.LastError, "stale": src.Stale, "next_run_at": src.NextSyncAt})
		}
		writeJSON(w, 200, map[string]any{"jobs": runs, "feeds": feeds})
	case path == "/maintenance/versions" && r.Method == http.MethodGet:
		writeJSON(w, 200, h.versions(ctx))
	case path == "/events/inbound" && r.Method == http.MethodGet:
		after, err := pageUUID(r, "cursor")
		if err != nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		items, err := h.store.InboundEvents(ctx, after, r.URL.Query().Get("actor"), r.URL.Query().Get("event_type"))
		if err != nil {
			assessmentError(w, err)
			return
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	case strings.HasPrefix(path, "/events/inbound/"):
		idPart, action, _ := strings.Cut(strings.TrimPrefix(path, "/events/inbound/"), ":")
		id, err := uuid.Parse(idPart)
		if err != nil {
			writeError(w, 404, "event not found")
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			e, err := h.store.InboundEvent(ctx, id)
			if err != nil {
				assessmentError(w, err)
				return
			}
			writeJSON(w, 200, e)
		case action == "replay" && r.Method == http.MethodPost:
			a, err := h.store.Replay(ctx, id, actor.ID, actor.Name)
			if err != nil {
				assessmentError(w, err)
				return
			}
			w.Header().Set("Location", BasePath+"/assessments/"+a.ID.String())
			writeJSON(w, 202, a)
		default:
			writeError(w, 405, "method not allowed")
		}
	default:
		writeError(w, 404, "not found")
	}
}

// versions reports what this deployment runs (MNT-004): the SCRS build,
// feed freshness, the Karate runner, and the newest published release when
// SCRS_RELEASE_FEED_URL names a JSON feed with tag_name or version.
func (h maintenanceHandler) versions(ctx context.Context) map[string]any {
	out := map[string]any{"scrs": buildVersion()}
	if sources, err := h.store.VulnerabilitySources(ctx); err == nil {
		feeds := map[string]any{}
		for _, src := range sources {
			feeds[src.Key] = map[string]any{"last_success_at": src.LastSuccessAt, "stale": src.Stale, "records": src.RecordCount}
		}
		out["feeds"] = feeds
	}
	if h.runner != nil {
		if info, err := h.runner.Info(ctx); err == nil {
			out["qa_runner"] = info
		} else {
			out["qa_runner"] = map[string]string{"error": err.Error()}
		}
	}
	if feed := os.Getenv("SCRS_RELEASE_FEED_URL"); feed != "" {
		out["latest_release"] = latestRelease(ctx, feed)
	}
	return out
}

func buildVersion() map[string]string {
	v := map[string]string{"version": os.Getenv("SCRS_VERSION")}
	if info, ok := debug.ReadBuildInfo(); ok {
		v["go"] = info.GoVersion
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" || setting.Key == "vcs.time" {
				v[setting.Key] = setting.Value
			}
		}
		if v["version"] == "" {
			v["version"] = info.Main.Version
		}
	}
	return v
}

// latestRelease reads a release feed such as the GitHub releases API.
func latestRelease(ctx context.Context, feed string) map[string]string {
	u, err := url.Parse(feed)
	if err != nil || u.Scheme != "https" {
		return map[string]string{"error": "SCRS_RELEASE_FEED_URL must be https"}
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, feed, nil)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: &http.Transport{DialContext: netguard.DialContext(nil)}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]string{"error": "release feed unreachable"}
	}
	defer resp.Body.Close()
	var body struct {
		Tag     string `json:"tag_name"`
		Version string `json:"version"`
		URL     string `json:"html_url"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) != nil {
		return map[string]string{"error": "release feed returned no release"}
	}
	return map[string]string{"version": firstNonEmpty(body.Tag, body.Version), "url": body.URL}
}
