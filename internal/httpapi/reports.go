package httpapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/compliance"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/license"
	"github.com/google/uuid"
)

// reportHandler serves framework packs and compliance evidence reports
// (CMP-001 to CMP-006).
type reportHandler struct {
	store     *assessments.Store
	artifacts any
}

func (h reportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath)
	switch {
	case path == "/reports/frameworks" && r.Method == http.MethodGet:
		packs, err := h.store.FrameworkPacks(ctx)
		if err != nil {
			licenseError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": packs})
	case path == "/reports/frameworks" && r.Method == http.MethodPost:
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeError(w, 413, "pack too large")
			return
		}
		pack, err := compliance.ParsePack(raw)
		if err != nil {
			licenseError(w, err)
			return
		}
		if err := h.store.SaveFrameworkPack(ctx, pack, principal.ID); err != nil {
			licenseError(w, err)
			return
		}
		writeJSON(w, 201, pack)
	case strings.HasPrefix(path, "/frameworks/"):
		// One pack: /frameworks/{id} (/reports/{id} names report jobs).
		id := strings.TrimPrefix(path, "/frameworks/")
		switch r.Method {
		case http.MethodGet:
			pack, err := h.store.FrameworkPack(ctx, id)
			if err != nil {
				licenseError(w, err)
				return
			}
			writeJSON(w, 200, pack)
		case http.MethodDelete:
			if !principal.Allows("admin") {
				writeError(w, 403, "admin scope required")
				return
			}
			if _, builtin := compliance.BuiltinPack(id); builtin {
				writeError(w, 409, "shipped packs cannot be deleted")
				return
			}
			if err := h.store.DeleteFrameworkPack(ctx, id, principal.ID); err != nil {
				licenseError(w, err)
				return
			}
			w.WriteHeader(204)
		default:
			writeError(w, 405, "method not allowed")
		}
	case path == "/reports" && r.Method == http.MethodPost:
		if !principal.Allows("write") {
			writeError(w, 403, "write scope required")
			return
		}
		var input assessments.ReportRequest
		if !readBody(w, r, &input) {
			return
		}
		job, err := h.store.CreateReport(ctx, input, principal.ID)
		if err != nil {
			if err == assessments.ErrInput {
				writeError(w, 400, "framework, scope (asset, owner or portfolio), format (json, csv, md) and a window of at most 366 days are required")
				return
			}
			licenseError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/reports/"+job.ID.String())
		w.Header().Set("Retry-After", "5")
		writeJSON(w, 202, job)
	case path == "/reports" && r.Method == http.MethodGet:
		before, err := pageUUID(r, "cursor")
		if err != nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		items, err := h.store.Reports(ctx, before, 50)
		if err != nil {
			licenseError(w, err)
			return
		}
		next := ""
		if len(items) > 50 {
			items = items[:50]
			next = items[49].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	case strings.HasPrefix(path, "/reports/") && r.Method == http.MethodGet:
		rest := strings.TrimPrefix(path, "/reports/")
		raw, download := strings.CutSuffix(rest, "/download")
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, 404, "not found")
			return
		}
		job, err := h.store.Report(ctx, id)
		if err != nil {
			licenseError(w, err)
			return
		}
		if !download {
			if job.Status == "queued" || job.Status == "running" {
				w.Header().Set("Retry-After", "5")
			}
			writeJSON(w, 200, job)
			return
		}
		if job.Status != "succeeded" || job.Key == "" {
			writeError(w, 409, "report not ready")
			return
		}
		store, ok := h.artifacts.(interface {
			GetReport(context.Context, string) ([]byte, error)
		})
		if !ok {
			writeError(w, 503, "artifact storage unavailable")
			return
		}
		data, err := store.GetReport(ctx, job.Key)
		if err != nil {
			writeError(w, 502, "report retrieval failed")
			return
		}
		w.Header().Set("Content-Type", compliance.ContentType(job.Format))
		w.Header().Set("ETag", `"`+job.SHA256+`"`)
		w.Header().Set("X-SCRS-Report-SHA256", job.SHA256)
		w.Header().Set("Content-Disposition", `attachment; filename="`+job.Framework+"-"+job.ID.String()[:8]+"."+job.Format+`"`)
		_, _ = w.Write(data)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// schemaDocuments serves the licence policy and framework pack schemas.
func schemaDocuments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/schema+json")
	switch r.PathValue("name") {
	case "license-policy":
		_, _ = w.Write(license.Schema())
	case "framework-pack":
		_, _ = w.Write(compliance.Schema())
	default:
		writeError(w, 404, "not found")
	}
}
