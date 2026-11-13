package httpapi

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// MirrorReader opens stored git bundles for download.
type MirrorReader interface {
	OpenMirror(context.Context, string) (io.ReadCloser, int64, error)
}

// mirrorHandler serves git history mirrors of repository assets (INT-006).
type mirrorHandler struct {
	store   *assessments.Store
	bundles MirrorReader
}

func (h mirrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	asset, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "asset unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if raw := r.PathValue("mirror"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, 404, "mirror unavailable")
			return
		}
		h.download(w, r, asset, id)
		return
	}
	if r.Method == http.MethodPost {
		principal := r.Context().Value(principalKey{}).(connections.Token)
		m, created, err := h.store.RequestMirror(ctx, asset, principal.Name)
		if err != nil {
			if err == assessments.ErrScope {
				writeError(w, 404, "asset is not an in-scope GitHub or GitLab repository")
				return
			}
			assessmentError(w, err)
			return
		}
		status := 202
		if !created {
			status = 200
		}
		writeJSON(w, status, m)
		return
	}
	items, err := h.store.Mirrors(ctx, asset)
	if err != nil {
		assessmentError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// download streams a bundle. The recorded SHA-256 is sent in a header so
// clients verify the file; the object store is not trusted blindly.
func (h mirrorHandler) download(w http.ResponseWriter, r *http.Request, asset, id uuid.UUID) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	m, err := h.store.GetMirror(ctx, asset, id)
	if err != nil {
		assessmentError(w, err)
		return
	}
	if m.Status != "succeeded" || h.bundles == nil {
		writeError(w, 409, "mirror bundle not available (status "+m.Status+")")
		return
	}
	body, size, err := h.bundles.OpenMirror(ctx, m.ObjectKey)
	if err != nil {
		writeError(w, 502, "mirror retrieval failed")
		return
	}
	defer body.Close()
	if size != m.SizeBytes {
		writeError(w, 502, "mirror object size does not match its record")
		return
	}
	// Bundles outlast the server's default write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
	w.Header().Set("Content-Type", "application/x-git-bundle")
	w.Header().Set("Content-Disposition", `attachment; filename="`+m.ID.String()+`.bundle"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Content-SHA256", m.SHA256)
	_, _ = io.Copy(w, body)
}
