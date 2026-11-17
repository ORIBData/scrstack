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

// assetLinkHandler serves /assets/{id}/links (CON-012).
type assetLinkHandler struct{ store *assessments.Store }

func (h assetLinkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	principal, _ := r.Context().Value(principalKey{}).(connections.Token)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "asset not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		links, err := h.store.AssetLinks(r.Context(), id)
		if err != nil {
			linkError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": links})
	case http.MethodPost:
		h.add(r.Context(), w, r, principal, id)
	case http.MethodDelete:
		to, err := uuid.Parse(r.PathValue("to"))
		if err != nil {
			writeError(w, 404, "link not found")
			return
		}
		if kind := r.URL.Query().Get("kind"); kind != "" && kind != assessments.LinkKindBuiltFrom {
			writeError(w, 400, "kind must be built_from")
			return
		}
		if err := h.store.RemoveLink(r.Context(), id, to, principal.ID); err != nil {
			linkError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h assetLinkHandler) add(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, from uuid.UUID) {
	var input struct {
		Kind       string     `json:"kind"`
		ToAssetID  *uuid.UUID `json:"to_asset_id"`
		Repository string     `json:"repository"`
		Provider   string     `json:"provider"`
	}
	if !readBody(w, r, &input) {
		return
	}
	if input.Kind != assessments.LinkKindBuiltFrom || (input.ToAssetID == nil) == (strings.TrimSpace(input.Repository) == "") || (input.Provider != "" && input.Provider != "github" && input.Provider != "gitlab") {
		writeError(w, 400, "send kind built_from and exactly one of to_asset_id and repository (with an optional provider)")
		return
	}
	to := uuid.Nil
	if input.ToAssetID != nil {
		to = *input.ToAssetID
	} else {
		resolved, err := h.store.ResolveRepository(ctx, input.Provider, strings.TrimSpace(input.Repository))
		if err != nil {
			linkError(w, err)
			return
		}
		to = resolved
	}
	link, created, err := h.store.AddLink(ctx, from, to, assessments.LinkSourceManual, principal.ID)
	if err != nil {
		linkError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, link)
}

func linkError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "asset or link not found")
	case errors.Is(err, assessments.ErrAmbiguous):
		writeError(w, 409, "several repositories have that path; set provider or use to_asset_id")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "an image is built from a GitHub, GitLab or uploaded source, and cannot link to itself")
	default:
		writeError(w, 500, "link operation failed")
	}
}
