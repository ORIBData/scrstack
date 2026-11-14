package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
)

// auditHandler serves GET /audit (OBS-002, admin).
type auditHandler struct{ store *assessments.Store }

func (h auditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := assessments.AuditFilter{Action: q.Get("action"), Limit: 100}
	var err error
	for key, dst := range map[string]*uuid.UUID{"target_id": &f.Target, "actor_id": &f.Actor} {
		if raw := q.Get(key); raw != "" {
			if *dst, err = uuid.Parse(raw); err != nil {
				writeError(w, 400, key+" must be a UUID")
				return
			}
		}
	}
	for key, dst := range map[string]**time.Time{"since": &f.Since, "until": &f.Until} {
		if raw := q.Get(key); raw != "" {
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeError(w, 400, key+" must be an RFC 3339 time")
				return
			}
			*dst = &t
		}
	}
	if raw := q.Get("cursor"); raw != "" {
		if f.Before, err = strconv.ParseInt(raw, 10, 64); err != nil || f.Before <= 0 {
			writeError(w, 400, "invalid cursor")
			return
		}
	}
	if raw := q.Get("limit"); raw != "" {
		if f.Limit, err = strconv.Atoi(raw); err != nil || f.Limit < 1 || f.Limit > 500 {
			writeError(w, 400, "limit must be 1 to 500")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	items, err := h.store.Audit(ctx, f)
	if err != nil {
		assessmentError(w, err)
		return
	}
	next := ""
	if len(items) == f.Limit {
		next = strconv.FormatInt(items[len(items)-1].ID, 10)
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

// eventSchemas serves the event JSON Schemas (OUT-008).
func eventSchemas(w http.ResponseWriter, r *http.Request) {
	eventType := r.PathValue("type")
	if eventType == "" {
		items := []map[string]any{}
		for _, t := range notify.EventTypes() {
			items = append(items, map[string]any{"type": t, "versions": []int{notify.SchemaVersion}, "link": notify.Link("/schemas/events/" + t + "/" + strconv.Itoa(notify.SchemaVersion))})
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}
	version, err := strconv.Atoi(r.PathValue("version"))
	schema, ok := notify.EventSchema(eventType, version)
	if err != nil || !ok {
		writeError(w, 404, "no schema for this event type and version")
		return
	}
	w.Header().Set("Content-Type", "application/schema+json")
	_, _ = w.Write(schema)
}
