package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

type assessmentHandler struct {
	remediationEnabled bool
	store              *assessments.Store
	artifacts          interface {
		GetSBOM(context.Context, string) ([]byte, error)
	}
}

func assessmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrAmbiguous):
		writeError(w, 422, "multiple connections match; specify connection")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid assessment request")
	case errors.Is(err, assessments.ErrScope), errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "asset or assessment unavailable")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "request conflicts with existing state")
	case errors.Is(err, assessments.ErrCapacity):
		w.Header().Set("Retry-After", "30")
		writeError(w, 429, "assessment queue full")
	default:
		writeError(w, 500, "assessment operation failed")
	}
}
func readBody(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid request body")
		return false
	}
	return true
}
func pageUUID(r *http.Request, key string) (uuid.UUID, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(raw)
}
func (h assessmentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if r.URL.Path == BasePath+"/assessments:batch" {
		h.batch(ctx, w, r, principal)
		return
	}
	if r.URL.Path == BasePath+"/assessments:import" {
		h.importReport(w, r, principal)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/last-known-good") {
		asset, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, 404, "asset unavailable")
			return
		}
		a, err := h.store.LastKnownGood(ctx, asset, r.URL.Query().Get("ref"))
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"asset_id": asset, "ref": r.URL.Query().Get("ref"), "commit": a.Commit, "assessment": a})
		return
	}
	if r.URL.Path == BasePath+"/assessments/latest" {
		q := r.URL.Query()
		asset, err := pageUUID(r, "asset_id")
		if err != nil {
			writeError(w, 400, "invalid asset")
			return
		}
		actor := uuid.Nil
		if !principal.Allows("read") && !principal.Allows("write") {
			actor = principal.ID
		}
		a, err := h.store.Latest(ctx, asset, q.Get("repository"), q.Get("commit"), actor)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 200, a)
		return
	}
	if r.URL.Path == BasePath+"/remediation/capabilities" {
		writeJSON(w, 200, map[string]any{"enabled": h.remediationEnabled, "capabilities": []map[string]any{{"ecosystem": "npm", "manifest": "package-lock.json", "strategies": []string{"in-place"}, "supported": h.remediationEnabled}, {"ecosystem": "Maven", "manifest": "pom.xml", "strategies": []string{"override"}, "supported": h.remediationEnabled}}, "repository_writes": false})
		return
	}
	if strings.HasPrefix(r.URL.Path, BasePath+"/assets/") {
		if !h.remediationEnabled {
			writeError(w, 503, "remediation sandbox disabled")
			return
		}
		asset, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, 404, "asset unavailable")
			return
		}
		var input struct {
			AssessmentID uuid.UUID `json:"assessment_id"`
			Manifest     string    `json:"manifest"`
			Strategy     string    `json:"strategy"`
		}
		if !readBody(w, r, &input) {
			return
		}
		a, replayed, err := h.store.EnqueuePlan(ctx, input.AssessmentID, asset, principal.ID, principal.Name, r.Header.Get("Idempotency-Key"), input.Manifest, input.Strategy)
		if err != nil {
			assessmentError(w, err)
			return
		}
		status := 202
		if replayed {
			status = 200
			w.Header().Set("Idempotent-Replayed", "true")
		}
		w.Header().Set("Location", BasePath+"/assessments/"+a.ID.String())
		writeJSON(w, status, a)
		return
	}
	if r.URL.Path == BasePath+"/assessments" {
		if r.Method == "POST" {
			var input assessments.Request
			if !readBody(w, r, &input) {
				return
			}
			if input.Remediation != nil {
				writeError(w, 400, "use the scoped remediation endpoint")
				return
			}
			if reservedOrigin.MatchString(input.Trigger.Origin) {
				writeError(w, 400, "trigger.origin is reserved; use your own system name")
				return
			}
			input.AutoRemediation = h.remediationEnabled
			a, replayed, err := h.store.Enqueue(ctx, input, principal.ID, principal.Name, r.Header.Get("Idempotency-Key"))
			if err != nil {
				assessmentError(w, err)
				return
			}
			status := 202
			if replayed {
				status = 200
				w.Header().Set("Idempotent-Replayed", "true")
			}
			w.Header().Set("Location", BasePath+"/assessments/"+a.ID.String())
			w.Header().Set("Retry-After", "5")
			writeJSON(w, status, a)
			return
		}
		q := r.URL.Query()
		filter := assessments.ListFilter{Status: q.Get("status"), Verdict: q.Get("verdict"), Ref: q.Get("ref"), Commit: q.Get("commit"), Actor: q.Get("actor")}
		var err error
		if filter.After, err = pageUUID(r, "cursor"); err != nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		if filter.Asset, err = pageUUID(r, "asset_id"); err != nil {
			writeError(w, 400, "invalid asset")
			return
		}
		for key, target := range map[string]**time.Time{"created_after": &filter.Since, "created_before": &filter.Until} {
			if raw := q.Get(key); raw != "" {
				parsed, err := time.Parse(time.RFC3339, raw)
				if err != nil {
					writeError(w, 400, key+" must be RFC 3339")
					return
				}
				*target = &parsed
			}
		}
		if !principal.Allows("read") && !principal.Allows("write") {
			filter.ActorID = principal.ID
		}
		items, err := h.store.List(ctx, filter)
		if err != nil {
			assessmentError(w, err)
			return
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		return
	}
	if strings.HasPrefix(r.URL.Path, BasePath+"/register") {
		h.register(ctx, w, r, principal)
		return
	}
	segment := strings.TrimPrefix(r.URL.Path, BasePath+"/assessments/")
	parts := strings.Split(segment, "/")
	id, err := uuid.Parse(parts[0])
	if err != nil || len(parts) > 2 {
		writeError(w, 404, "not found")
		return
	}
	a, err := h.store.Get(ctx, id)
	if err != nil {
		assessmentError(w, err)
		return
	}
	if !principal.Allows("read") && !principal.Allows("write") && a.ActorID != principal.ID {
		writeError(w, 404, "not found")
		return
	}
	if r.Method == "DELETE" && len(parts) == 1 {
		if !principal.Allows("write") && !(principal.Allows("trigger") && a.ActorID == principal.ID) {
			writeError(w, 403, "insufficient scope")
			return
		}
		if err := h.store.Cancel(ctx, id, principal.ID); err != nil {
			assessmentError(w, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}
	// TRG-009 long-poll: wait up to 60 s for a queued or running assessment.
	if raw := r.URL.Query().Get("wait"); raw != "" && len(parts) == 1 {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 0 || seconds > 60 {
			writeError(w, 400, "wait must be 0 to 60 seconds")
			return
		}
		deadline := time.Now().Add(time.Duration(seconds) * time.Second)
		for (a.Status == "queued" || a.Status == "running") && time.Now().Before(deadline) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
			pollCtx, pollCancel := context.WithTimeout(r.Context(), 5*time.Second)
			next, err := h.store.Get(pollCtx, id)
			pollCancel()
			if err != nil {
				assessmentError(w, err)
				return
			}
			a = next
		}
	}
	if a.Status == "queued" || a.Status == "running" {
		w.Header().Set("Retry-After", "5")
	}
	if len(parts) == 1 {
		writeJSON(w, 200, a)
		return
	}
	switch parts[1] {
	case "context":
		profile := r.URL.Query().Get("profile")
		if profile == "" {
			profile = "full"
		}
		doc, err := h.store.ContextDocument(ctx, id, profile, principal.Allows("admin") && r.URL.Query().Get("include_contacts") == "true")
		if err != nil {
			assessmentError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	case "remediations":
		plans, err := h.store.AutomaticPlans(ctx, id)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 200, plans)
	case "files":
		data, err := h.store.Files(ctx, id)
		if err != nil {
			writeError(w, 409, "file evidence unavailable")
			return
		}
		writeJSON(w, 200, data)
	case "components":
		after := -1
		if raw := r.URL.Query().Get("cursor"); raw != "" {
			after, err = strconv.Atoi(raw)
			if err != nil || after < 0 {
				writeError(w, 400, "invalid cursor")
				return
			}
		}
		items, err := h.store.Components(ctx, id, after)
		if err != nil {
			assessmentError(w, err)
			return
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = strconv.Itoa(after + 100)
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	case "findings":
		after, err := pageUUID(r, "cursor")
		if err != nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		items, err := h.store.Findings(ctx, id, uuid.Nil, after)
		if err != nil {
			assessmentError(w, err)
			return
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	case "remediation":
		artifacts, ok := h.artifacts.(interface {
			GetPlan(context.Context, string) ([]byte, error)
		})
		if !ok {
			writeError(w, 503, "artifact storage unavailable")
			return
		}
		key, err := h.store.PlanKey(ctx, id)
		if err != nil {
			writeError(w, 409, "plan not available")
			return
		}
		data, err := artifacts.GetPlan(ctx, key)
		if err != nil {
			writeError(w, 502, "plan retrieval failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	case "mbom":
		doc, err := h.store.MBOM(ctx, id)
		if err != nil {
			if errors.Is(err, assessments.ErrConflict) {
				writeError(w, 409, "MBOM available only for succeeded assessments")
				return
			}
			assessmentError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		_, _ = w.Write(doc)
	case "vex":
		doc, err := h.store.VEX(ctx, id)
		if err != nil {
			assessmentError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	case "snapshot":
		// Source archives can contain secrets committed to the repository: admin only.
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		store, ok := h.artifacts.(interface {
			GetSnapshot(context.Context, string) ([]byte, error)
		})
		if a.SnapshotKey == "" || !ok {
			writeError(w, 409, "source snapshot not available; set SCRS_SNAPSHOT_ARCHIVES=true")
			return
		}
		data, err := store.GetSnapshot(ctx, a.SnapshotKey)
		if err != nil {
			writeError(w, 502, "snapshot retrieval failed")
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+a.Commit+`.tar.gz"`)
		_, _ = w.Write(data)
	case "sbom":
		if a.SBOMKey == "" {
			writeError(w, 409, "SBOM not available")
			return
		}
		if format := r.URL.Query().Get("format"); format != "" && format != "cyclonedx-json" {
			writeError(w, 400, "supported format: cyclonedx-json")
			return
		}
		if h.artifacts == nil {
			writeError(w, 503, "artifact storage unavailable")
			return
		}
		data, err := h.artifacts.GetSBOM(ctx, a.SBOMKey)
		if err != nil {
			writeError(w, 502, "SBOM retrieval failed")
			return
		}
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		w.Header().Set("ETag", `"`+a.SBOMSHA256+`"`)
		w.WriteHeader(200)
		_, _ = w.Write(data)
	case "report":
		if r.URL.Query().Get("format") == "md" {
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = fmt.Fprintf(w, "# SCRS assessment %s\n\nStatus: %s\nVerdict: %s\nRevision: %s\n\nFindings: %d\n\nAn incomplete result is not a clean security assessment.\n", a.ID, a.Status, a.Verdict, a.Commit, a.Counts["total"])
		} else {
			writeJSON(w, 200, a)
		}
	default:
		writeError(w, 404, "not found")
	}
}
func (h assessmentHandler) register(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token) {
	if r.URL.Path == BasePath+"/register" {
		if r.Method != "GET" {
			writeError(w, 405, "method not allowed")
			return
		}
		after, err := pageUUID(r, "cursor")
		if err != nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		asset, err := pageUUID(r, "asset_id")
		if err != nil {
			writeError(w, 400, "invalid asset")
			return
		}
		items, err := h.store.Findings(ctx, uuid.Nil, asset, after)
		if err != nil {
			assessmentError(w, err)
			return
		}
		next := ""
		if len(items) > 100 {
			items = items[:100]
			next = items[99].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, BasePath+"/register/"), "/")
	id, err := uuid.Parse(parts[0])
	if err != nil || len(parts) > 2 {
		writeError(w, 404, "not found")
		return
	}
	if r.Method == "GET" && len(parts) == 2 && parts[1] == "events" {
		events, err := h.store.FindingHistory(ctx, id)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 200, events)
		return
	}
	if r.Method != "PATCH" || len(parts) != 1 {
		writeError(w, 405, "method not allowed")
		return
	}
	if !principal.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	var input struct {
		Status    string     `json:"status"`
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !readBody(w, r, &input) {
		return
	}
	if (input.Status == "accepted" || input.Status == "suppressed" || input.Status == "false_positive") && !principal.Allows("admin") {
		writeError(w, 403, "admin approval required")
		return
	}
	if err := h.store.Transition(ctx, id, principal.ID, input.Status, input.Reason, input.ExpiresAt); err != nil {
		assessmentError(w, err)
		return
	}
	w.WriteHeader(204)
}

// batch admits up to 100 targets, each with its own idempotency key, and
// reports a per-item result (TRG-011). One item failing never fails the rest.
func (h assessmentHandler) batch(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token) {
	var input struct {
		Items []struct {
			IdempotencyKey string              `json:"idempotency_key"`
			Request        assessments.Request `json:"request"`
		} `json:"items"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.Items) == 0 || len(input.Items) > 100 {
		writeError(w, 400, "batch requires 1 to 100 items")
		return
	}
	batchCtx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	results := make([]map[string]any, 0, len(input.Items))
	for i, item := range input.Items {
		if item.Request.Remediation != nil {
			results = append(results, map[string]any{"index": i, "status": 400, "error": "use the scoped remediation endpoint"})
			continue
		}
		if reservedOrigin.MatchString(item.Request.Trigger.Origin) {
			results = append(results, map[string]any{"index": i, "status": 400, "error": "trigger.origin is reserved; use your own system name"})
			continue
		}
		item.Request.AutoRemediation = h.remediationEnabled
		a, replayed, err := h.store.Enqueue(batchCtx, item.Request, principal.ID, principal.Name, item.IdempotencyKey)
		if err != nil {
			rec := &statusRecorder{header: http.Header{}}
			assessmentError(rec, err)
			results = append(results, map[string]any{"index": i, "status": rec.status, "error": rec.message()})
			continue
		}
		status := 202
		if replayed {
			status = 200
		}
		results = append(results, map[string]any{"index": i, "status": status, "assessment_id": a.ID, "location": BasePath + "/assessments/" + a.ID.String()})
	}
	writeJSON(w, 207, map[string]any{"items": results})
}

var importSlots = make(chan struct{}, 2)

// reservedOrigin matches trigger origins SCRS assigns itself. API callers may
// not claim them, so the audit trail can tell a provider event from a request.
var reservedOrigin = regexp.MustCompile(`^(github|gitlab|registry|import)_|^(replay|scheduler)$`)

// importReport records a Trivy or SARIF report as a completed assessment.
func (h assessmentHandler) importReport(w http.ResponseWriter, r *http.Request, principal connections.Token) {
	var input struct {
		Target     assessments.Target `json:"target"`
		Connection string             `json:"connection"`
		Format     string             `json:"format"`
		Notify     []string           `json:"notify"`
		Replace    bool               `json:"replace_previous"`
		Report     json.RawMessage    `json:"report"`
	}
	// Each import holds its report (up to 16 MiB) several times in memory.
	select {
	case importSlots <- struct{}{}:
		defer func() { <-importSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		writeError(w, 429, "import capacity exceeded; retry shortly")
		return
	}
	// Reports up to 16 MiB need longer than the server's default read timeout.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(60 * time.Second))
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(new(any)) != io.EOF || len(input.Report) == 0 {
		writeError(w, 400, "import requires target, format and report (max 16 MiB)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	request := assessments.Request{Target: input.Target, Connection: input.Connection, Notify: input.Notify}
	a, replayed, err := h.store.Import(ctx, request, principal.ID, principal.Name, r.Header.Get("Idempotency-Key"), input.Format, input.Replace, input.Report)
	if err != nil {
		if errors.Is(err, assessments.ErrInput) && err != assessments.ErrInput {
			writeError(w, 400, err.Error())
			return
		}
		assessmentError(w, err)
		return
	}
	status := 201
	if replayed {
		status = 200
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Location", BasePath+"/assessments/"+a.ID.String())
	writeJSON(w, status, a)
}

// statusRecorder captures assessmentError output for per-item batch results.
type statusRecorder struct {
	header http.Header
	status int
	body   []byte
}

func (s *statusRecorder) Header() http.Header  { return s.header }
func (s *statusRecorder) WriteHeader(code int) { s.status = code }
func (s *statusRecorder) Write(b []byte) (int, error) {
	s.body = append(s.body, b...)
	return len(b), nil
}
func (s *statusRecorder) message() string {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(s.body, &v)
	return v.Error
}
