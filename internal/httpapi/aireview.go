package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/google/uuid"
)

// aiReviewHandler serves the AI code review: POST and GET
// /assets/{id}/ai-reviews and GET /ai-reviews/{id}.
type aiReviewHandler struct {
	store *assessments.Store
	// hosts are the self-hosted model servers (SCRS_LLM_PRIVATE_HOSTS).
	// allowSource is the platform switch for hosted providers
	// (SCRS_LLM_ALLOW_SOURCE_TO_HOSTED). A review is accepted for a
	// self-hosted provider, or a hosted one that was acknowledged.
	hosts       map[string]bool
	allowSource bool
}

func aiReviewError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrAIReviewProvider), errors.Is(err, assessments.ErrAIReviewSource):
		writeError(w, 409, err.Error())
	default:
		qaError(w, err)
	}
}

func (h aiReviewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	switch {
	case r.Method == http.MethodPost && r.PathValue("id") != "" && r.URL.Path == BasePath+"/assets/"+id.String()+"/ai-reviews":
		var input struct {
			ProviderID uuid.UUID `json:"provider_id"`
			assessments.AIReviewOptions
		}
		if !readBody(w, r, &input) {
			return
		}
		if input.ProviderID == uuid.Nil {
			writeError(w, 400, "provider_id is required: the model that will read the code (see GET /llm/providers; source_allowed must be true)")
			return
		}
		policy := llm.SourcePolicy{Private: h.hosts, AllowHosted: h.allowSource}
		review, err := h.store.EnqueueAIReview(ctx, id, input.ProviderID, input.AIReviewOptions, principal.Name, func(p assessments.LLMProvider) (string, bool) {
			return policy.Check(llmSettings(p), p.SourceAckAt != nil)
		})
		if err != nil {
			aiReviewError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/ai-reviews/"+review.ID.String())
		writeJSON(w, 202, review)
	case r.Method == http.MethodGet && r.URL.Path == BasePath+"/assets/"+id.String()+"/ai-reviews":
		items, err := h.store.AIReviews(ctx, id, 50)
		if err != nil {
			aiReviewError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case r.Method == http.MethodGet && r.URL.Path == BasePath+"/ai-reviews/"+id.String():
		review, err := h.store.AIReviewByID(ctx, id)
		if err != nil {
			aiReviewError(w, err)
			return
		}
		writeJSON(w, 200, review)
	default:
		writeError(w, 405, "method not allowed")
	}
}
