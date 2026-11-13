package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

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
