package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// findingNoteError maps comment and assignment failures.
func findingNoteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "register entry or comment not found")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid input: comment text is 1 to 4000 characters, assignee and on_behalf_of at most 100 without control characters")
	default:
		writeError(w, 500, "register operation failed")
	}
}

// assignee serves PUT /register/{id}/assignee.
func (h assessmentHandler) assignee(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID) {
	if r.Method != http.MethodPut {
		writeError(w, 405, "method not allowed")
		return
	}
	if !principal.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	var input struct {
		Assignee   string `json:"assignee"`
		OnBehalfOf string `json:"on_behalf_of"`
	}
	if !readBody(w, r, &input) {
		return
	}
	if err := h.store.Assign(ctx, id, principal.ID, principal.Name, input.Assignee, input.OnBehalfOf); err != nil {
		findingNoteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// comments serves /register/{id}/comments and /register/{id}/comments/{comment}.
func (h assessmentHandler) comments(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		after := uuid.Nil
		if raw := r.URL.Query().Get("cursor"); raw != "" {
			parsed, err := uuid.Parse(raw)
			if err != nil {
				writeError(w, 400, "invalid cursor")
				return
			}
			after = parsed
		}
		items, err := h.store.Comments(ctx, id, after)
		if err != nil {
			findingNoteError(w, err)
			return
		}
		next := ""
		if len(items) > 200 {
			items = items[:200]
			next = items[199].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	case len(rest) == 0 && r.Method == http.MethodPost:
		if !principal.Allows("write") {
			writeError(w, 403, "write scope required")
			return
		}
		var input struct {
			Body       string `json:"body"`
			OnBehalfOf string `json:"on_behalf_of"`
		}
		if !readBodyLimit(w, r, &input, 16<<10) {
			return
		}
		c, err := h.store.AddComment(ctx, id, principal.ID, principal.Name, input.OnBehalfOf, input.Body)
		if err != nil {
			findingNoteError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/register/"+id.String()+"/comments/"+c.ID.String())
		writeJSON(w, 201, c)
	case len(rest) == 1 && r.Method == http.MethodDelete:
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		comment, err := uuid.Parse(strings.TrimSpace(rest[0]))
		if err != nil {
			writeError(w, 404, "comment not found")
			return
		}
		if err := h.store.DeleteComment(ctx, id, comment, principal.ID, principal.Name); err != nil {
			findingNoteError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, 405, "method not allowed")
	}
}
