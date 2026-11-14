package httpapi

import (
	"context"
	"fmt"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func retentionHandler(store *assessments.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		actor := r.Context().Value(principalKey{}).(connections.Token)
		path := strings.TrimPrefix(r.URL.Path, BasePath)
		if path == "/settings/retention" && r.Method == "GET" {
			p, err := store.Retention(ctx)
			if err != nil {
				assessmentError(w, err)
				return
			}
			w.Header().Set("ETag", fmt.Sprintf(`"%d"`, p.Revision))
			writeJSON(w, 200, p)
			return
		}
		if path == "/settings/retention:preview" && r.Method == "POST" {
			var input struct {
				Days    int             `json:"inbound_event_days"`
				Classes map[string]*int `json:"classes"`
			}
			if !readBody(w, r, &input) {
				return
			}
			if input.Classes != nil {
				counts, err := store.PreviewRetentionClasses(ctx, input.Classes)
				if err != nil {
					assessmentError(w, err)
					return
				}
				writeJSON(w, 200, map[string]any{"classes": counts})
				return
			}
			result, err := store.PreviewRetention(ctx, input.Days)
			if err != nil {
				assessmentError(w, err)
				return
			}
			writeJSON(w, 200, result)
			return
		}
		if (path != "/settings/retention" || r.Method != "PUT") && (path != "/settings/retention:purge" || r.Method != "POST") {
			writeError(w, 405, "method not allowed")
			return
		}
		header := r.Header.Get("If-Match")
		revision, err := strconv.ParseInt(strings.Trim(header, `"`), 10, 64)
		if err != nil || header != fmt.Sprintf(`"%d"`, revision) {
			writeError(w, 428, "If-Match policy ETag required")
			return
		}
		if path == "/settings/retention:purge" {
			purged, err := store.PurgeRetention(ctx, actor.ID, revision)
			if err != nil {
				assessmentError(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"deleted_events": purged["inbound_events"], "purged": purged})
			return
		}
		var input struct {
			Days         *int            `json:"inbound_event_days"`
			DeliveryDays *int            `json:"webhook_delivery_days"`
			Classes      map[string]*int `json:"classes"`
		}
		if !readBody(w, r, &input) {
			return
		}
		// The original fields are shorthand for their classes; classes wins.
		classes := map[string]*int{}
		if input.Days != nil {
			classes["inbound_events"] = input.Days
		}
		if input.DeliveryDays != nil {
			classes["webhook_deliveries"] = input.DeliveryDays
		}
		for k, v := range input.Classes {
			classes[k] = v
		}
		p, err := store.SetRetentionClasses(ctx, actor.ID, revision, classes)
		if err != nil {
			assessmentError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, p.Revision))
		writeJSON(w, 200, p)
	})
}
