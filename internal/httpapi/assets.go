package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

type assetAdmin interface {
	CreateOwner(context.Context, connections.Owner, uuid.UUID) (connections.Owner, error)
	Owners(context.Context) ([]connections.Owner, error)
	UpdateOwner(context.Context, uuid.UUID, int64, connections.Owner, uuid.UUID) (connections.Owner, error)
	Asset(context.Context, uuid.UUID) (connections.Asset, error)
	UpdateAsset(context.Context, uuid.UUID, int64, connections.AssetChange, uuid.UUID) (connections.Asset, error)
	AddAssets(context.Context, string, []connections.NewAsset, uuid.UUID) ([]connections.AssetResult, error)
	DeleteAsset(context.Context, uuid.UUID, uuid.UUID) error
}

// assetHandler serves owners and operator-owned asset attributes (AST-002, AST-003).
type assetHandler struct {
	store assetAdmin
	// uploads deletes `uploaded` assets with their archives; nil when no
	// assessment store is configured.
	uploads interface {
		DeleteUploadedAsset(ctx context.Context, asset, actor uuid.UUID) error
	}
}

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
	case errors.Is(err, connections.ErrNotManual):
		writeError(w, 409, "the asset was discovered by its connection; narrow the connection scope instead")
	case errors.Is(err, connections.ErrAssetInUse):
		writeError(w, 409, "the asset is under legal hold or has assessments, findings or settings")
	default:
		writeError(w, 500, "asset operation failed")
	}
}

func (h assetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if r.URL.Path == BasePath+"/assets" || r.URL.Path == BasePath+"/assets:import" {
		h.register(ctx, w, r, actor)
		return
	}
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
	if r.Method == http.MethodDelete {
		if !actor.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		if h.uploads != nil {
			if a, err := h.store.Asset(ctx, id); err == nil && a.Type == connections.UploadAssetType {
				switch err := h.uploads.DeleteUploadedAsset(ctx, id, actor.ID); {
				case err == nil:
					w.WriteHeader(204)
				case errors.Is(err, assessments.ErrConflict):
					writeError(w, 409, "the asset is under legal hold or has assessments, findings or settings; delete its uploads, or let the uploaded_archives retention class remove them")
				case errors.Is(err, assessments.ErrNotFound):
					writeError(w, 404, "not found")
				default:
					writeError(w, 500, "asset operation failed")
				}
				return
			}
		}
		if err := h.store.DeleteAsset(ctx, id, actor.ID); err != nil {
			assetStoreError(w, err)
			return
		}
		w.WriteHeader(204)
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
	if change.Distribution != nil && !actor.Allows("admin") {
		writeError(w, 403, "distribution needs admin scope: it selects the licence policy")
		return
	}
	if change.LegalHold != nil && !actor.Allows("admin") {
		writeError(w, 403, "legal_hold needs admin scope")
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

// assetInput is one asset to register: where it lives and, optionally, the
// attributes an operator would otherwise set with PATCH.
type assetInput struct {
	Locator string `json:"locator"`
	Type    string `json:"type"`
	connections.AssetChange
}

func (in assetInput) asset() connections.NewAsset {
	return connections.NewAsset{Locator: in.Locator, Type: in.Type, Change: in.AssetChange}
}

// maxAssetImport bounds one POST /assets:import.
const maxAssetImport = 500

// register serves POST /assets and POST /assets:import (AST-001).
func (h assetHandler) register(ctx context.Context, w http.ResponseWriter, r *http.Request, actor connections.Token) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	if !actor.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	bulk := r.URL.Path == BasePath+"/assets:import"
	var body struct {
		Connection string       `json:"connection"`
		Items      []assetInput `json:"items"`
		assetInput
	}
	if !readBody(w, r, &body) {
		return
	}
	items := body.Items
	if !bulk {
		items = []assetInput{body.assetInput}
	}
	if body.Connection == "" || len(items) == 0 || len(items) > maxAssetImport || (!bulk && len(body.Items) > 0) {
		writeError(w, 400, "connection and one asset, or 1 to 500 items for an import, are required")
		return
	}
	for _, item := range items {
		if (item.Distribution != nil || item.LegalHold != nil) && !actor.Allows("admin") {
			writeError(w, 403, "distribution and legal_hold need admin scope")
			return
		}
	}
	list := make([]connections.NewAsset, len(items))
	for i, item := range items {
		list[i] = item.asset()
	}
	results, err := h.store.AddAssets(ctx, body.Connection, list, actor.ID)
	if err != nil {
		assetStoreError(w, err)
		return
	}
	if bulk {
		writeJSON(w, 207, map[string]any{"items": results})
		return
	}
	res := results[0]
	switch res.Status {
	case "invalid":
		writeError(w, 400, res.Error)
	case "exists":
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, res.Asset.Revision))
		writeJSON(w, 200, res.Asset)
	default:
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, res.Asset.Revision))
		w.Header().Set("Location", BasePath+"/assets/"+res.Asset.ID.String())
		writeJSON(w, 201, res.Asset)
	}
}
