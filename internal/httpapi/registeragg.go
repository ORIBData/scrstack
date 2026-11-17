package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/google/uuid"
)

var (
	registerStatuses   = map[string]bool{"open": true, "triaged": true, "in_progress": true, "accepted": true, "suppressed": true, "false_positive": true, "fixed": true}
	registerSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true, "unknown": true}
)

// maxRegisterExport bounds one export; narrow the filters to stay under it.
const maxRegisterExport = 50000

// registerFilter reads asset_id, status, severity and type from the query.
func registerFilter(r *http.Request) (assessments.RegisterFilter, bool) {
	q := r.URL.Query()
	var f assessments.RegisterFilter
	if raw := q.Get("asset_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return f, false
		}
		f.Asset = id
	}
	f.Status, f.Severity, f.Type = q.Get("status"), q.Get("severity"), q.Get("type")
	if (f.Status != "" && !registerStatuses[f.Status]) || (f.Severity != "" && !registerSeverities[f.Severity]) || len(f.Type) > 40 {
		return f, false
	}
	return f, true
}

// registerAggregate serves the read-only views over the whole register:
// summary, timeseries, top-assets, export and vex. It reports whether the
// path was one of them.
func (h assessmentHandler) registerAggregate(w http.ResponseWriter, r *http.Request, name string) bool {
	switch name {
	case "summary", "timeseries", "top-assets", "export", "vex":
	default:
		return false
	}
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return true
	}
	filter, ok := registerFilter(r)
	if !ok {
		writeError(w, 400, "invalid asset_id, status, severity or type")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	switch name {
	case "summary":
		out, err := h.store.RegisterSummary(ctx, filter)
		if err != nil {
			assessmentError(w, err)
			return true
		}
		writeJSON(w, 200, out)
	case "timeseries":
		days := 30
		if raw := r.URL.Query().Get("days"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 366 {
				writeError(w, 400, "days must be 1 to 366")
				return true
			}
			days = n
		}
		points, err := h.store.RegisterTimeseries(ctx, filter, days)
		if err != nil {
			assessmentError(w, err)
			return true
		}
		writeJSON(w, 200, map[string]any{"days": days, "items": points})
	case "top-assets":
		limit := 10
		if raw := r.URL.Query().Get("limit"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 100 {
				writeError(w, 400, "limit must be 1 to 100")
				return true
			}
			limit = n
		}
		items, err := h.store.TopAssets(ctx, filter, limit)
		if err != nil {
			assessmentError(w, err)
			return true
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case "vex":
		doc, err := h.store.RegisterVEX(ctx, filter)
		if err != nil {
			if err == assessments.ErrInput {
				writeError(w, 422, "more than 50000 statements; narrow with asset_id")
				return true
			}
			assessmentError(w, err)
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="register.vex.json"`)
		_, _ = w.Write(doc)
	case "export":
		h.registerExport(ctx, w, r, filter)
	}
	return true
}

func (h assessmentHandler) registerExport(ctx context.Context, w http.ResponseWriter, r *http.Request, filter assessments.RegisterFilter) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeError(w, 400, "format must be csv or json")
		return
	}
	var after uuid.UUID
	sent, total := false, 0
	var out *csv.Writer
	for {
		items, err := h.store.FindingsFiltered(ctx, filter, after)
		if err != nil {
			if !sent {
				assessmentError(w, err)
			}
			return
		}
		more := len(items) > 100
		if more {
			items = items[:100]
		}
		if !sent {
			sent = true
			if format == "csv" {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Disposition", `attachment; filename="register.csv"`)
				out = csv.NewWriter(w)
				_ = out.Write([]string{"id", "asset_id", "ref", "type", "advisory_id", "title", "severity", "score", "status", "component", "version", "purl", "first_seen", "last_seen", "waiver_until"})
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", `attachment; filename="register.json"`)
				_, _ = w.Write([]byte(`{"items":[`))
			}
		}
		for _, f := range items {
			if total == maxRegisterExport {
				break
			}
			if format == "csv" {
				until := ""
				if f.WaiverUntil != nil {
					until = f.WaiverUntil.UTC().Format(time.RFC3339)
				}
				_ = out.Write([]string{f.ID.String(), f.AssetID.String(), csvSafe(f.Ref), f.Type, csvSafe(f.AdvisoryID), csvSafe(f.Title), f.Severity, strconv.Itoa(f.Score), f.Status, csvSafe(f.Component.Name), csvSafe(f.Component.Version), csvSafe(f.Component.PURL), f.FirstSeen.UTC().Format(time.RFC3339), f.LastSeen.UTC().Format(time.RFC3339), until})
			} else {
				if total > 0 {
					_, _ = w.Write([]byte(","))
				}
				raw, _ := json.Marshal(f)
				_, _ = w.Write(raw)
			}
			total++
		}
		if !more || total == maxRegisterExport {
			break
		}
		after = items[len(items)-1].ID
	}
	if format == "csv" {
		out.Flush()
		return
	}
	truncated := total == maxRegisterExport
	_, _ = w.Write([]byte(`],"truncated":` + strconv.FormatBool(truncated) + `}`))
}
