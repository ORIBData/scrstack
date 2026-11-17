package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
)

// dependencyPolicyHandler serves GET and PUT /policies/dependencies.
type dependencyPolicyHandler struct{ store *assessments.Store }

func (h dependencyPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		policy, err := h.store.DependencyPolicy(r.Context())
		if err != nil {
			writeError(w, 500, "policy unavailable")
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(policy.Revision, 10)+`"`)
		writeJSON(w, 200, policy)
	case http.MethodPut:
		principal, _ := r.Context().Value(principalKey{}).(connections.Token)
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		expected, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var input struct {
			MinReleaseAgeDays int  `json:"min_release_age_days"`
			Typosquat         bool `json:"typosquat"`
		}
		if !readBody(w, r, &input) {
			return
		}
		policy, err := h.store.SetDependencyPolicy(r.Context(), expected, input.MinReleaseAgeDays, input.Typosquat, principal.ID)
		switch {
		case errors.Is(err, assessments.ErrInput):
			writeError(w, 400, "min_release_age_days must be between 0 and "+strconv.Itoa(assessments.MaxMinReleaseAgeDays))
		case errors.Is(err, assessments.ErrConflict):
			writeError(w, 409, "the policy changed; reload and retry")
		case err != nil:
			writeError(w, 500, "policy update failed")
		default:
			w.Header().Set("ETag", `"`+strconv.FormatInt(policy.Revision, 10)+`"`)
			writeJSON(w, 200, policy)
		}
	default:
		writeError(w, 405, "method not allowed")
	}
}
