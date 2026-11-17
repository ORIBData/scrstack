package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
)

// uploadAssets creates the `uploaded` asset an archive belongs to and reads
// assets; *connections.Store implements it.
type uploadAssets interface {
	UploadAsset(context.Context, string, uuid.UUID) (connections.Asset, bool, error)
	Asset(context.Context, uuid.UUID) (connections.Asset, error)
}

// uploadFormOverhead is room in the request for the form fields around the
// archive.
const uploadFormOverhead = 1 << 20

// uploadHandler serves POST /uploads and GET /assets/{id}/uploads.
type uploadHandler struct {
	assets    uploadAssets
	store     *assessments.Store
	artifacts any // must provide PutUpload; absent when object storage is not configured
}

type uploadPutter interface {
	PutUpload(context.Context, []byte) (string, error)
}

func (h uploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodPost:
		h.create(w, r)
	case http.MethodDelete:
		h.remove(w, r)
	default:
		h.list(w, r)
	}
}

func (h uploadHandler) create(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalKey{}).(connections.Token)
	putter, ok := h.artifacts.(uploadPutter)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "uploads need object storage, which is not configured")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		writeError(w, http.StatusUnsupportedMediaType, "send multipart/form-data with name and file")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, storage.MaxUploadBytes+uploadFormOverhead)
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, 400, "invalid multipart body")
		return
	}
	fields := map[string]string{}
	var archive []byte
	var filename string
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			uploadReadError(w, err)
			return
		}
		switch part.FormName() {
		case "file":
			if archive != nil {
				writeError(w, 400, "send one file")
				return
			}
			filename = part.FileName()
			archive, err = io.ReadAll(io.LimitReader(part, storage.MaxUploadBytes+1))
			if err != nil {
				uploadReadError(w, err)
				return
			}
			if len(archive) > storage.MaxUploadBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "archive is larger than "+strconv.Itoa(storage.MaxUploadBytes>>20)+" MiB")
				return
			}
		case "name", "ref", "assess":
			value, err := io.ReadAll(io.LimitReader(part, 257))
			if err != nil || len(value) > 256 {
				writeError(w, 400, "field "+part.FormName()+" is too long")
				return
			}
			fields[part.FormName()] = strings.TrimSpace(string(value))
		default:
			writeError(w, 400, "unknown field "+part.FormName())
			return
		}
	}
	name := strings.ToLower(fields["name"])
	if name == "" || len(archive) == 0 {
		writeError(w, 400, "name and file are required")
		return
	}
	if !validSourceArchive(archive) {
		writeError(w, http.StatusUnprocessableEntity, "file must be a gzip-compressed tar archive (.tar.gz) with at least one entry")
		return
	}
	assess := fields["assess"] != "false"
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	asset, _, err := h.assets.UploadAsset(ctx, name, principal.ID)
	if err != nil {
		if errors.Is(err, connections.ErrUploadName) {
			writeError(w, 400, err.Error())
			return
		}
		writeError(w, 500, "upload asset failed")
		return
	}
	key, err := putter.PutUpload(ctx, archive)
	if err != nil {
		writeError(w, 502, "storing the archive failed")
		return
	}
	sum := sha256.Sum256(archive)
	upload, created, err := h.store.RecordUpload(ctx, assessments.Upload{AssetID: asset.ID, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(archive)), Filename: truncate(filename, 200), Label: fields["ref"], ObjectKey: key}, principal.Name)
	if err != nil {
		writeError(w, 500, "recording the upload failed")
		return
	}
	result := map[string]any{"asset": asset, "upload": upload}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	if assess {
		request := assessments.Request{Target: assessments.Target{Type: "upload", Repository: asset.Locator, Commit: upload.Commit, Ref: fields["ref"]}}
		request.Trigger.Origin = "upload"
		request.Trigger.Event = "archive.uploaded"
		request.Trigger.Actor = principal.Name
		a, _, err := h.store.Enqueue(ctx, request, principal.ID, principal.Name, r.Header.Get("Idempotency-Key"))
		if err != nil {
			// The archive is kept; queue it later with POST /assessments.
			result["assessment_error"] = uploadAssessmentError(err)
		} else {
			result["assessment"] = a
			w.Header().Set("Location", BasePath+"/assessments/"+a.ID.String())
		}
	}
	writeJSON(w, status, result)
}

func (h uploadHandler) list(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "asset not found")
		return
	}
	asset, err := h.assets.Asset(r.Context(), id)
	if err != nil || asset.Type != connections.UploadAssetType {
		writeError(w, 404, "uploaded asset not found")
		return
	}
	items, err := h.store.Uploads(r.Context(), id, 200)
	if err != nil {
		writeError(w, 500, "upload list failed")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func uploadReadError(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "request is larger than the archive limit")
		return
	}
	writeError(w, 400, "invalid multipart body")
}

func uploadAssessmentError(err error) string {
	switch {
	case errors.Is(err, assessments.ErrBusy):
		return "asset has a running assessment; queue this archive later with POST /assessments"
	case errors.Is(err, assessments.ErrCapacity):
		return "assessment queue full; queue this archive later with POST /assessments"
	default:
		return "assessment was not queued; use POST /assessments with target type upload"
	}
}

// validSourceArchive reports whether data is a gzip stream whose first entry
// reads as a tar header. The scanner checks the contents again.
func validSourceArchive(data []byte) bool {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer gz.Close()
	_, err = tar.NewReader(gz).Next()
	return err == nil
}

func (h uploadHandler) remove(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalKey{}).(connections.Token)
	asset, errAsset := uuid.Parse(r.PathValue("id"))
	upload, errUpload := uuid.Parse(r.PathValue("upload"))
	if errAsset != nil || errUpload != nil {
		writeError(w, 404, "upload not found")
		return
	}
	switch err := h.store.DeleteUpload(r.Context(), asset, upload, principal.ID); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "upload not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "the asset is under legal hold")
	case errors.Is(err, assessments.ErrBusy):
		w.Header().Set("Retry-After", "30")
		writeError(w, 409, "an assessment of this archive is queued or running; retry when it finishes")
	default:
		writeError(w, 500, "upload delete failed")
	}
}
