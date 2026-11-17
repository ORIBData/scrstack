package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/advisory"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// vulnHandler serves the vulnerability-source registry (VUL-001), advisory
// lookups (VUL-002, VUL-004) and VEX imports (VUL-009).
type vulnHandler struct{ store *assessments.Store }

var advisoryID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:-]{2,127}$`)

func vulnError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrSourceManaged), errors.Is(err, assessments.ErrTermsNotAcknowledged):
		writeError(w, 409, err.Error())
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "revision is stale or the document was already imported")
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "schedule_minutes must be 15 to 10080")
	default:
		writeError(w, 500, "vulnerability source operation failed")
	}
}

func (h vulnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath+"/intel/")
	switch {
	case path == "vulnerability-sources" && r.Method == http.MethodGet:
		items, err := h.store.VulnerabilitySources(ctx)
		if err != nil {
			vulnError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case strings.HasPrefix(path, "vulnerability-sources/"):
		key, action, _ := strings.Cut(strings.TrimPrefix(path, "vulnerability-sources/"), ":")
		h.source(ctx, w, r, principal, key, action)
	case strings.HasPrefix(path, "vulnerabilities/") && r.Method == http.MethodGet:
		id := strings.TrimPrefix(path, "vulnerabilities/")
		if !advisoryID.MatchString(id) {
			writeError(w, 404, "not found")
			return
		}
		if !strings.HasPrefix(id, "x_") {
			id = strings.ToUpper(id[:3]) + id[3:]
		}
		view, err := h.store.Advisory(ctx, id, r.URL.Query().Get("purl"))
		if err != nil {
			vulnError(w, err)
			return
		}
		writeJSON(w, 200, view)
	case path == "vex-documents" && r.Method == http.MethodGet:
		items, err := h.store.VEXDocuments(ctx)
		if err != nil {
			vulnError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "vex-documents" && r.Method == http.MethodPost:
		if !principal.Allows("write") {
			writeError(w, 403, "write scope required")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, advisory.MaxVEXBytes))
		if err != nil {
			writeError(w, 413, "VEX document is over 16 MiB")
			return
		}
		doc, err := advisory.ParseVEX(body)
		if err != nil {
			writeError(w, 400, "invalid VEX document: "+err.Error())
			return
		}
		saved, err := h.store.ImportVEX(ctx, doc, assessments.Hash(body), principal.Name)
		if err != nil {
			vulnError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/intel/vex-documents/"+saved.ID.String())
		writeJSON(w, 201, saved)
	case strings.HasPrefix(path, "vex-documents/") && r.Method == http.MethodDelete:
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		id, err := uuid.Parse(strings.TrimPrefix(path, "vex-documents/"))
		if err != nil {
			writeError(w, 404, "not found")
			return
		}
		if err := h.store.DeleteVEXDocument(ctx, id, principal.Name); err != nil {
			vulnError(w, err)
			return
		}
		w.WriteHeader(204)
	case path == "vex-statements" && r.Method == http.MethodGet:
		q := r.URL.Query()
		if len(q.Get("vulnerability")) > 128 || len(q.Get("purl")) > 1024 {
			writeError(w, 400, "vulnerability or purl too long")
			return
		}
		items, err := h.store.VendorStatements(ctx, q.Get("vulnerability"), q.Get("purl"))
		if err != nil {
			vulnError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h vulnHandler) source(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, key, action string) {
	if r.Method != http.MethodGet && !principal.Allows("admin") {
		writeError(w, 403, "admin scope required")
		return
	}
	switch action + " " + r.Method {
	case " GET":
		v, err := h.store.VulnerabilitySource(ctx, key)
		if err != nil {
			vulnError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, v.Revision))
		writeJSON(w, 200, v)
	case " PATCH":
		revision, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var input struct {
			Enabled          *bool `json:"enabled"`
			ScheduleMinutes  *int  `json:"schedule_minutes"`
			AcknowledgeTerms bool  `json:"acknowledge_terms"`
		}
		if !readBody(w, r, &input) {
			return
		}
		v, err := h.store.UpdateVulnerabilitySource(ctx, key, revision, input.Enabled, input.ScheduleMinutes, input.AcknowledgeTerms, principal.ID)
		if err != nil {
			vulnError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, v.Revision))
		writeJSON(w, 200, v)
	case "sync POST":
		if err := h.store.SyncVulnerabilitySourceNow(ctx, key); err != nil {
			vulnError(w, err)
			return
		}
		writeJSON(w, 202, map[string]bool{"queued": true})
	default:
		writeError(w, 405, "method not allowed")
	}
}
