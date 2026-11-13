package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

type assetAdmin interface {
	CreateOwner(context.Context, connections.Owner, uuid.UUID) (connections.Owner, error)
	Owners(context.Context) ([]connections.Owner, error)
	UpdateOwner(context.Context, uuid.UUID, int64, connections.Owner, uuid.UUID) (connections.Owner, error)
	Asset(context.Context, uuid.UUID) (connections.Asset, error)
	UpdateAsset(context.Context, uuid.UUID, int64, connections.AssetChange, uuid.UUID) (connections.Asset, error)
}

// assetHandler serves owners and operator-owned asset attributes (AST-002, AST-003).
type assetHandler struct{ store assetAdmin }

func ifMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	revision, err := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"`), 10, 64)
	if err != nil {
		writeError(w, 428, "If-Match revision ETag required")
		return 0, false
	}
	return revision, true
}

func assetStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, connections.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, connections.ErrConflict):
		writeError(w, 409, "name exists or revision is stale; reload and retry")
	case errors.Is(err, connections.ErrInvalidChange):
		writeError(w, 400, "invalid owner or asset attributes")
	default:
		writeError(w, 500, "asset operation failed")
	}
}

func (h assetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if strings.HasPrefix(r.URL.Path, BasePath+"/owners") {
		rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, BasePath+"/owners"), "/")
		switch {
		case rest == "" && r.Method == http.MethodGet:
			items, err := h.store.Owners(ctx)
			if err != nil {
				assetStoreError(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
		case rest == "" && r.Method == http.MethodPost:
			if !actor.Allows("write") {
				writeError(w, 403, "write scope required")
				return
			}
			var o connections.Owner
			if !readBody(w, r, &o) {
				return
			}
			created, err := h.store.CreateOwner(ctx, o, actor.ID)
			if err != nil {
				assetStoreError(w, err)
				return
			}
			w.Header().Set("ETag", fmt.Sprintf(`"%d"`, created.Revision))
			writeJSON(w, 201, created)
		case rest != "" && r.Method == http.MethodPatch:
			if !actor.Allows("write") {
				writeError(w, 403, "write scope required")
				return
			}
			id, err := uuid.Parse(rest)
			if err != nil {
				writeError(w, 404, "not found")
				return
			}
			revision, ok := ifMatch(w, r)
			if !ok {
				return
			}
			var o connections.Owner
			if !readBody(w, r, &o) {
				return
			}
			updated, err := h.store.UpdateOwner(ctx, id, revision, o, actor.ID)
			if err != nil {
				assetStoreError(w, err)
				return
			}
			w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
			writeJSON(w, 200, updated)
		default:
			writeError(w, 405, "method not allowed")
		}
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	if r.Method == http.MethodGet {
		a, err := h.store.Asset(ctx, id)
		if err != nil {
			assetStoreError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, a.Revision))
		writeJSON(w, 200, a)
		return
	}
	if !actor.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	revision, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var change connections.AssetChange
	if !readBody(w, r, &change) {
		return
	}
	a, err := h.store.UpdateAsset(ctx, id, revision, change, actor.ID)
	if err != nil {
		assetStoreError(w, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, a.Revision))
	writeJSON(w, 200, a)
}
