package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/google/uuid"
)

// QAReportReader opens stored runner reports.
type QAReportReader interface {
	GetQAReport(context.Context, string) ([]byte, error)
}

// qaHandler serves the E2E QA module: per-asset profiles, runs, coverage,
// generations and the review of generated suites.
type qaHandler struct {
	store   *assessments.Store
	secrets Sealer
	reports QAReportReader
	runner  *qa.Runner
}

var errQAAdmin = errors.New("admin scope required")

func qaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errQAAdmin):
		writeError(w, 403, err.Error())
	case errors.Is(err, errNoSealer):
		writeError(w, 503, err.Error())
	case errors.Is(err, assessments.ErrQAProfile), errors.Is(err, assessments.ErrQANoAssessment), errors.Is(err, assessments.ErrQABlocked), errors.Is(err, assessments.ErrQAProvider):
		writeError(w, 409, err.Error())
	case errors.Is(err, assessments.ErrQAState):
		writeError(w, 409, "not allowed in the current state")
	case errors.Is(err, assessments.ErrScope):
		writeError(w, 404, "asset is not an in-scope GitHub or GitLab repository")
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "revision is stale or the name exists; reload and retry")
	case errors.Is(err, assessments.ErrInput):
		lines := strings.Split(err.Error(), "\n")
		writeError(w, 400, "invalid QA request: "+lines[len(lines)-1])
	default:
		writeError(w, 500, "QA operation failed")
	}
}

func (h qaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if raw := r.PathValue("id"); raw != "" && !strings.HasPrefix(r.URL.Path, BasePath+"/qa/") {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, 404, "not found")
			return
		}
		if strings.HasPrefix(r.URL.Path, BasePath+"/assessments/") {
			items, err := h.store.QARuns(ctx, assessments.QARunFilter{Assessment: id, Limit: 200})
			if err != nil {
				qaError(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
			return
		}
		h.asset(ctx, w, r, principal, id)
		return
	}
	h.item(ctx, w, r, principal)
}

// asset serves /assets/{id}/qa/...
func (h qaHandler) asset(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, asset uuid.UUID) {
	section := strings.TrimPrefix(r.URL.Path, BasePath+"/assets/"+r.PathValue("id")+"/qa/")
	query := r.URL.Query()
	switch section + " " + r.Method {
	case "profile GET":
		p, err := h.store.QAProfileFor(ctx, asset)
		if err != nil {
			qaError(w, err)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(p.Revision, 10)))
		writeJSON(w, 200, p)
	case "profile PUT":
		h.putProfile(ctx, w, r, principal, asset)
	case "profile DELETE":
		if err := h.store.DeleteQAProfile(ctx, asset, principal.ID); err != nil {
			qaError(w, err)
			return
		}
		w.WriteHeader(204)
	case "runs POST":
		var input struct {
			Kind          string     `json:"kind"`
			AssessmentID  *uuid.UUID `json:"assessment_id"`
			IncludeDrafts bool       `json:"include_drafts"`
		}
		if !readBody(w, r, &input) {
			return
		}
		if input.Kind == "" {
			input.Kind = qa.KindFunctional
		}
		if input.IncludeDrafts && !principal.Allows("admin") {
			qaError(w, errQAAdmin)
			return
		}
		run, err := h.store.EnqueueQARun(ctx, asset, input.AssessmentID, input.Kind, input.IncludeDrafts, principal.Name)
		if err != nil {
			qaError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/qa/runs/"+run.ID.String())
		writeJSON(w, 202, run)
	case "runs GET":
		filter := assessments.QARunFilter{Asset: asset, Kind: query.Get("kind"), Status: query.Get("status"), Limit: 50}
		if raw := query.Get("before"); raw != "" {
			before, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				writeError(w, 400, "before must be an RFC 3339 time")
				return
			}
			filter.Before = &before
		}
		items, err := h.store.QARuns(ctx, filter)
		if err != nil {
			qaError(w, err)
			return
		}
		next := ""
		if len(items) == filter.Limit {
			next = items[len(items)-1].CreatedAt.Format(time.RFC3339Nano)
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_before": next})
	case "coverage GET":
		limit, _ := strconv.Atoi(query.Get("limit"))
		items, err := h.store.QACoverageHistory(ctx, asset, query.Get("ref"), limit)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case "generations POST":
		var input struct {
			Kind string `json:"kind"`
			assessments.QAGenerationOptions
		}
		if !readBody(w, r, &input) {
			return
		}
		g, err := h.store.EnqueueQAGeneration(ctx, asset, input.Kind, input.QAGenerationOptions, principal.Name)
		if err != nil {
			qaError(w, err)
			return
		}
		w.Header().Set("Location", BasePath+"/qa/generations/"+g.ID.String())
		writeJSON(w, 202, g)
	case "generations GET":
		items, err := h.store.QAGenerations(ctx, asset, 50)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case "suites GET":
		items, err := h.store.QASuites(ctx, assessments.QASuiteFilter{Asset: asset, Kind: query.Get("kind"), Status: query.Get("status")})
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	default:
		writeError(w, 405, "method not allowed")
	}
}

// profileInput is a full profile; omitted fields take defaults. Variables
// are write-only: when omitted, the stored values and names are kept.
type profileInput struct {
	Enabled           *bool               `json:"enabled"`
	AutoRun           *bool               `json:"auto_run"`
	Refs              []string            `json:"refs"`
	BaseURL           string              `json:"base_url"`
	Environment       string              `json:"environment"`
	Tags              []string            `json:"tags"`
	Threads           int                 `json:"threads"`
	TimeoutSeconds    int                 `json:"timeout_seconds"`
	TestPath          *string             `json:"test_path"`
	OpenAPIPath       string              `json:"openapi_path"`
	Auth              assessments.QAAuth  `json:"auth"`
	Variables         map[string]string   `json:"variables"`
	Perf              *assessments.QAPerf `json:"perf"`
	LLMProviderID     *uuid.UUID          `json:"llm_provider_id"`
	AllowSourceUpload bool                `json:"allow_source_upload"`
}

func (h qaHandler) putProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, asset uuid.UUID) {
	var input profileInput
	if !readSourceBody(w, r, &input) {
		return
	}
	existing, err := h.store.QAProfileFor(ctx, asset)
	expected := int64(0)
	switch {
	case err == nil:
		revision, ok := ifMatch(w, r)
		if !ok {
			return
		}
		expected = revision
	case !errors.Is(err, assessments.ErrNotFound):
		qaError(w, err)
		return
	}
	p := assessments.QAProfile{AssetID: asset, Enabled: true, AutoRun: true, Refs: input.Refs, BaseURL: input.BaseURL, Environment: input.Environment, Tags: input.Tags, Threads: input.Threads, TimeoutSeconds: input.TimeoutSeconds, TestPath: "karate", OpenAPIPath: input.OpenAPIPath, Auth: input.Auth, Perf: input.Perf, LLMProviderID: input.LLMProviderID, AllowSourceUpload: input.AllowSourceUpload, VariableNames: existing.VariableNames}
	if input.Enabled != nil {
		p.Enabled = *input.Enabled
	}
	if input.AutoRun != nil {
		p.AutoRun = *input.AutoRun
	}
	if input.TestPath != nil {
		p.TestPath = strings.Trim(*input.TestPath, "/")
	}
	if p.Threads == 0 {
		p.Threads = 1
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 900
	}
	var sealed []byte
	if input.Variables != nil {
		if err := qa.ValidVariables(input.Variables); err != nil {
			qaError(w, errors.Join(assessments.ErrInput, err))
			return
		}
		if h.secrets == nil {
			qaError(w, errNoSealer)
			return
		}
		p.VariableNames = make([]string, 0, len(input.Variables))
		for name := range input.Variables {
			p.VariableNames = append(p.VariableNames, name)
		}
		sort.Strings(p.VariableNames)
		plain, _ := json.Marshal(input.Variables)
		if sealed, err = h.secrets.Seal(plain, assessments.QAAAD(asset)); err != nil {
			qaError(w, err)
			return
		}
	}
	saved, err := h.store.PutQAProfile(ctx, p, expected, sealed, principal.ID)
	if err != nil {
		qaError(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(saved.Revision, 10)))
	status := 200
	if expected == 0 {
		status = 201
	}
	writeJSON(w, status, saved)
}

// item serves /qa/runner, /qa/runs/{id}..., /qa/generations/{id}... and
// /qa/suites/{id}...
func (h qaHandler) item(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token) {
	rest := strings.TrimPrefix(r.URL.Path, BasePath+"/qa/")
	if rest == "runner" && r.Method == http.MethodGet {
		if h.runner == nil {
			writeJSON(w, 200, map[string]any{"configured": false})
			return
		}
		info, err := h.runner.Info(ctx)
		if err != nil {
			writeJSON(w, 502, map[string]any{"configured": true, "reachable": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"configured": true, "reachable": true, "runner": info})
		return
	}
	collection, tail, _ := strings.Cut(rest, "/")
	raw, sub, _ := strings.Cut(tail, "/")
	raw, action, _ := strings.Cut(raw, ":")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	if r.Method != http.MethodGet && !principal.Allows("write") && !(collection == "runs" && action == "cancel" && principal.Allows("trigger")) {
		writeError(w, 403, "write scope required")
		return
	}
	switch collection + "/" + sub + ":" + action + " " + r.Method {
	case "runs/: GET":
		run, err := h.store.QARunByID(ctx, id)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, run)
	case "runs/scenarios: GET":
		after := -1
		if raw := r.URL.Query().Get("cursor"); raw != "" {
			if after, err = strconv.Atoi(raw); err != nil || after < 0 {
				writeError(w, 400, "invalid cursor")
				return
			}
		}
		if _, err := h.store.QARunByID(ctx, id); err != nil {
			qaError(w, err)
			return
		}
		items, next, err := h.store.QAScenarios(ctx, id, after, r.URL.Query().Get("status"))
		if err != nil {
			qaError(w, err)
			return
		}
		cursor := ""
		if next >= 0 {
			cursor = strconv.Itoa(next)
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": cursor})
	case "runs/coverage: GET":
		body, err := h.store.QARunCoverage(ctx, id)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, body)
	case "runs/report: GET":
		h.report(ctx, w, id)
	case "runs/:cancel POST":
		run, err := h.store.CancelQARun(ctx, id, principal.Name)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, run)
	case "generations/: GET":
		g, err := h.store.QAGenerationByID(ctx, id)
		if err != nil {
			qaError(w, err)
			return
		}
		suites, err := h.store.QASuites(ctx, assessments.QASuiteFilter{Generation: id})
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"generation": g, "suites": suites})
	case "generations/files: GET":
		h.files(ctx, w, id)
	case "suites/: GET":
		s, err := h.store.QASuiteByID(ctx, id)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, s)
	case "suites/:approve POST", "suites/:reject POST":
		approve := action == "approve"
		// Approved API features run against the target on the runner.
		if approve && !principal.Allows("admin") {
			qaError(w, errQAAdmin)
			return
		}
		var input struct {
			Note string `json:"note"`
		}
		if !readBody(w, r, &input) {
			return
		}
		s, err := h.store.ReviewQASuite(ctx, id, approve, principal.Name, input.Note)
		if err != nil {
			qaError(w, err)
			return
		}
		writeJSON(w, 200, s)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// report streams a run's stored report archive with its digest.
func (h qaHandler) report(ctx context.Context, w http.ResponseWriter, id uuid.UUID) {
	run, err := h.store.QARunByID(ctx, id)
	if err != nil {
		qaError(w, err)
		return
	}
	if run.ReportKey == "" || h.reports == nil {
		writeError(w, 409, "run has no stored report (status "+run.Status+")")
		return
	}
	data, err := h.reports.GetQAReport(ctx, run.ReportKey)
	if err != nil {
		writeError(w, 502, "report retrieval failed")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="qa-`+id.String()+`.tar.gz"`)
	w.Header().Set("X-Content-SHA256", run.ReportSHA256)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

// files packs a generation's files with a manifest of status and problems,
// for developers to review and commit.
func (h qaHandler) files(ctx context.Context, w http.ResponseWriter, id uuid.UUID) {
	if _, err := h.store.QAGenerationByID(ctx, id); err != nil {
		qaError(w, err)
		return
	}
	suites, err := h.store.QASuites(ctx, assessments.QASuiteFilter{Generation: id, Content: true})
	if err != nil {
		qaError(w, err)
		return
	}
	type entry struct {
		Path     string   `json:"path"`
		Source   string   `json:"source"`
		Status   string   `json:"status"`
		Problems []string `json:"problems"`
		SHA256   string   `json:"sha256"`
	}
	manifest := []entry{}
	var files []qa.File
	seen := map[string]bool{}
	for _, s := range suites {
		manifest = append(manifest, entry{s.Path, s.Source, s.Status, s.Problems, s.SHA256})
		target := "files/" + s.Path
		if s.Status == "rejected" || s.Status == "superseded" {
			target = s.Status + "/" + s.ID.String() + "/" + s.Path
		}
		if seen[target] {
			continue
		}
		seen[target] = true
		files = append(files, qa.File{Path: target, Data: []byte(s.Content)})
	}
	data, _ := json.MarshalIndent(map[string]any{"generation_id": id, "files": manifest}, "", " ")
	files = append(files, qa.File{Path: "MANIFEST.json", Data: data})
	archive, err := qa.Pack(files)
	if err != nil {
		writeError(w, 500, "a generated path is unsafe; download files individually")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="qa-generation-`+id.String()+`.tar.gz"`)
	w.WriteHeader(200)
	_, _ = w.Write(archive)
}
