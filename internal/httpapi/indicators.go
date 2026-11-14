package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
)

// sourceHandler manages indicator sources (TIF) with the ruleset permission
// model: write may create, import into and change hunt sources; promoting to
// alert or block, and changing a source that gates verdicts, needs admin.
type sourceHandler struct{ store *assessments.Store }

type sourceInput struct {
	Name          string                 `json:"name"`
	Kind          string                 `json:"kind"`
	Description   string                 `json:"description"`
	Mode          string                 `json:"mode"`
	Severity      string                 `json:"severity"`
	MinConfidence int                    `json:"min_confidence"`
	Enabled       *bool                  `json:"enabled"`
	Origin        assessments.RuleOrigin `json:"origin"`
}

var errEnforcingSource = errors.New("indicator sources in alert or block mode gate verdicts; admin scope required")

func readSourceBody(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid request body")
		return false
	}
	return true
}

func sourceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errEnforcingSource):
		writeError(w, 403, err.Error())
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "indicator source not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "indicator source name exists or revision is stale; reload and retry")
	case errors.Is(err, assessments.ErrIndicatorLimit):
		writeError(w, 422, err.Error())
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid indicator source: name is lower-case letters, digits and underscores; kind manual; mode hunt, alert or block; severity critical, high, medium, low or info; min_confidence 0 to 100; origin url https")
	default:
		writeError(w, 500, "indicator source operation failed")
	}
}

func (h sourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath+"/intel/indicator-sources")
	if r.Method != http.MethodGet && !principal.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	switch {
	case path == "" && r.Method == http.MethodGet:
		items, err := h.store.IndicatorSources(ctx)
		if err != nil {
			sourceError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "" && r.Method == http.MethodPost:
		var input sourceInput
		if !readSourceBody(w, r, &input) {
			return
		}
		record := assessments.IndicatorSource{Name: input.Name, Kind: input.Kind, Description: input.Description, Mode: input.Mode, Severity: input.Severity, MinConfidence: input.MinConfidence, Enabled: input.Enabled == nil || *input.Enabled, Origin: input.Origin}
		if record.Kind == "" {
			record.Kind = "manual"
		}
		if record.Mode == "" {
			record.Mode = "hunt"
		}
		if record.Severity == "" {
			record.Severity = "high"
		}
		if enforcing(record.Mode) && !principal.Allows("admin") {
			sourceError(w, errEnforcingSource)
			return
		}
		created, err := h.store.CreateIndicatorSource(ctx, record, principal.ID)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, created.Revision))
		w.Header().Set("Location", BasePath+"/intel/indicator-sources/"+created.ID.String())
		writeJSON(w, 201, created)
	case strings.HasPrefix(path, "/"):
		rest := strings.TrimPrefix(path, "/")
		idPart, sub, _ := strings.Cut(rest, "/")
		idPart, action, _ := strings.Cut(idPart, ":")
		id, err := uuid.Parse(idPart)
		if err != nil || (sub != "" && (sub != "indicators" || action != "")) {
			writeError(w, 404, "indicator source not found")
			return
		}
		if sub == "indicators" {
			action = "indicators"
		}
		h.item(ctx, w, r, principal, id, action)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h sourceHandler) item(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, action string) {
	allowed := func(before, after assessments.IndicatorSource) error {
		if (enforcing(before.Mode) || enforcing(after.Mode)) && !principal.Allows("admin") {
			return errEnforcingSource
		}
		return nil
	}
	same := func(record assessments.IndicatorSource) error { return allowed(record, record) }
	switch {
	case action == "" && r.Method == http.MethodGet:
		record, err := h.store.IndicatorSourceByID(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, record.Revision))
		writeJSON(w, 200, record)
	case action == "" && r.Method == http.MethodPatch:
		revision, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var change assessments.IndicatorSourceChange
		if !readSourceBody(w, r, &change) {
			return
		}
		updated, err := h.store.UpdateIndicatorSource(ctx, id, revision, change, principal.ID, allowed)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
		writeJSON(w, 200, updated)
	case action == "" && r.Method == http.MethodDelete:
		if err := h.store.DeleteIndicatorSource(ctx, id, principal.ID, same); err != nil {
			sourceError(w, err)
			return
		}
		w.WriteHeader(204)
	case action == "indicators" && r.Method == http.MethodGet:
		bundle, err := h.store.SourceIndicators(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		writeJSON(w, 200, bundle)
	case action == "indicators" && r.Method == http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, intelligence.MaxImportBytes))
		if err != nil {
			writeError(w, 413, "indicator bundle too large")
			return
		}
		bundle, err := intelligence.Parse(body)
		if err != nil {
			writeError(w, 400, "invalid indicator bundle: "+err.Error())
			return
		}
		updated, err := h.store.ImportSourceIndicators(ctx, id, bundle, principal.ID, same)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
		writeJSON(w, 200, updated)
	case action == "hunt" && r.Method == http.MethodPost:
		// Retro-hunt: rescan the default branch of every in-scope repository
		// so the source's indicators are checked against current code.
		record, err := h.store.IndicatorSourceByID(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		if !record.Enabled {
			writeError(w, 409, "enable the indicator source before hunting")
			return
		}
		queued, err := h.store.EnqueueRescans(ctx, 0, 500)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 202, map[string]int{"rescans_queued": queued})
	default:
		writeError(w, 405, "method not allowed")
	}
}
