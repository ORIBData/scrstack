package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/google/uuid"
)

// aiSummaryHandler serves AI advisories and summaries and the asset
// chronicle: POST and GET /assessments/{id}/summaries, GET /summary-jobs/{id}
// and GET /assets/{id}/chronicle.
type aiSummaryHandler struct {
	store *assessments.Store
}

func aiSummaryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrAISummaryProvider):
		writeError(w, 409, err.Error())
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "the assessment has not succeeded, so there is nothing to summarise yet")
	case errors.Is(err, assessments.ErrNotFound), errors.Is(err, knowledge.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, assessments.ErrInput), errors.Is(err, knowledge.ErrInput):
		writeError(w, 400, "invalid request")
	default:
		writeError(w, 500, "operation failed")
	}
}

func (h aiSummaryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	path := r.URL.Path
	switch {
	case r.Method == http.MethodPost && path == BasePath+"/assessments/"+id.String()+"/summaries":
		var input struct {
			ProviderID uuid.UUID `json:"provider_id"`
			assessments.AISummaryOptions
		}
		if !readBody(w, r, &input) {
			return
		}
		if input.ProviderID == uuid.Nil {
			writeError(w, 400, "provider_id is required (see GET /llm/providers)")
			return
		}
		job, err := h.store.EnqueueAISummary(ctx, id, input.ProviderID, input.AISummaryOptions, principal.Name)
		if err != nil {
			aiSummaryError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/summary-jobs/"+job.ID.String())
		writeJob(w, 202, job.ID, job)
	case r.Method == http.MethodGet && path == BasePath+"/assessments/"+id.String()+"/summaries":
		items, err := h.store.AISummaries(ctx, id, 50)
		if err != nil {
			aiSummaryError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case r.Method == http.MethodGet && path == BasePath+"/summary-jobs/"+id.String():
		job, err := h.store.AISummaryByID(ctx, id)
		if err != nil {
			aiSummaryError(w, err)
			return
		}
		writeJSON(w, 200, job)
	case r.Method == http.MethodGet && path == BasePath+"/assets/"+id.String()+"/chronicle":
		h.chronicle(ctx, w, r, id)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h aiSummaryHandler) chronicle(ctx context.Context, w http.ResponseWriter, r *http.Request, asset uuid.UUID) {
	q := r.URL.Query()
	query := knowledge.ChronicleQuery{AssetID: asset, IncludeSuperseded: q.Get("include_superseded") == "true"}
	if kind := q.Get("kind"); kind != "" {
		for _, k := range strings.Split(kind, ",") {
			query.Kinds = append(query.Kinds, strings.TrimSpace(k))
		}
	}
	for name, target := range map[string]**uuid.UUID{"finding_id": &query.FindingID, "assessment_id": &query.AssessmentID} {
		if raw := q.Get(name); raw != "" {
			v, err := uuid.Parse(raw)
			if err != nil {
				writeError(w, 400, "invalid "+name)
				return
			}
			*target = &v
		}
	}
	if raw := q.Get("since"); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, 400, "since must be an RFC 3339 time")
			return
		}
		query.Since = &since
	}
	query.Limit = 50
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeError(w, 400, "limit must be 1 to 200")
			return
		}
		query.Limit = n
	}
	docs, err := h.store.Knowledge().Chronicle(ctx, query)
	if err != nil {
		aiSummaryError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": docs})
}
