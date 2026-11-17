package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
)

// integrityPolicyHandler serves GET and PUT /policies/integrity.
type integrityPolicyHandler struct{ store *assessments.Store }

func (h integrityPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		policy, err := h.store.IntegrityPolicy(r.Context())
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
			AuthorNewDays  int   `json:"author_new_days"`
			OffHours       bool  `json:"off_hours"`
			PusherDiffers  bool  `json:"pusher_differs"`
			LargeFileBytes int64 `json:"large_file_bytes"`
			CIGrowthBytes  int64 `json:"ci_growth_bytes"`
		}
		if !readBody(w, r, &input) {
			return
		}
		policy, err := h.store.SetIntegrityPolicy(r.Context(), expected, assessments.IntegrityPolicy{AuthorNewDays: input.AuthorNewDays, OffHours: input.OffHours, PusherDiffers: input.PusherDiffers, LargeFileBytes: input.LargeFileBytes, CIGrowthBytes: input.CIGrowthBytes}, principal.ID)
		switch {
		case errors.Is(err, assessments.ErrInput):
			writeError(w, 400, "author_new_days must be 0 to 3650; large_file_bytes and ci_growth_bytes 0 to 1073741824")
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
