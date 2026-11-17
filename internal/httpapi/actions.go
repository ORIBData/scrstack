package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ORIBData/scrstack/internal/actionscheck"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/google/uuid"
)

// actionsHandler serves GET /assets/{id}/actions and POST
// /assets/{id}/actions:check (INT-014, INT-015).
type actionsHandler struct {
	checker actionscheck.Checker
	slots   chan struct{}
}

func (h actionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "asset not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if r.Method == http.MethodGet {
		state, err := h.checker.Store.ActionsState(ctx, id)
		if err != nil {
			actionsError(w, err)
			return
		}
		writeJSON(w, 200, state)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "provider operation capacity reached")
		return
	}
	state, err := h.checker.Check(ctx, id)
	if err != nil {
		actionsError(w, err)
		return
	}
	writeJSON(w, 200, state)
}

func actionsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "no Actions inventory for this asset yet; POST /assets/{id}/actions:check reads one")
	case errors.Is(err, actionscheck.ErrNotGitHub):
		writeError(w, 409, err.Error())
	default:
		writeError(w, 502, "reading GitHub Actions failed: "+err.Error())
	}
}
