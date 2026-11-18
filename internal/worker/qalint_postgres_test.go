package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/qarunner"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lintSource serves a Python repository; clean drops the offending file.
type lintSource struct {
	syntheticSource
	clean bool
}

func (s lintSource) Snapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error) {
	files := []qa.File{
		{Path: "org-repo-ccc/pyproject.toml", Data: []byte("[tool.ruff]\n")},
		{Path: "org-repo-ccc/README.md", Data: []byte("docs")},
	}
	if s.clean {
		files = append(files, qa.File{Path: "org-repo-ccc/clean/ok.py", Data: []byte("x = 1\n")})
	} else {
		files = append(files, qa.File{Path: "org-repo-ccc/app/main.py", Data: []byte("import os  # SOURCE-LINE-MUST-NOT-REACH-THE-MODEL\n")})
	}
	archive, err := qa.Pack(files)
	return archive, qaCommit, false, err
}

// fakeRuffQA writes one F401 issue (or none when a clean/ directory exists)
// to --output-file, exiting 1 on issues like the real tool.
const fakeRuffQA = `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in --output-file) out="$2"; shift;; esac
  shift
done
if [ -d clean ]; then echo '[]' > "$out"; exit 0; fi
printf '[{"code":"F401","filename":"%s/app/main.py","fix":{"applicability":"safe"},"location":{"row":1,"column":8},"message":"os imported but unused"}]\n' "$(pwd)" > "$out"
exit 1
`

// triageModel answers QA triage prompts and records what it was shown.
func triageModel(t *testing.T) (*httptest.Server, func() string) {
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer model-key" || len(body.Messages) != 2 {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		seen = append(seen, body.Messages[0].Content+"\n"+body.Messages[1].Content)
		mu.Unlock()
		ids := regexp.MustCompile(`finding_id: ([0-9a-f-]{36})`).FindAllStringSubmatch(body.Messages[1].Content, -1)
		var answer []byte
		if strings.Contains(body.Messages[0].Content, "summary of one QA run") {
			priorities := []any{}
			if len(ids) > 0 {
				priorities = append(priorities, map[string]any{"finding_id": ids[0][1], "action": "Remove the unused import", "why": "The linter flags it"})
			}
			answer, _ = json.Marshal(map[string]any{"headline": "One lint rule is broken", "risk_level": "low", "summary": "Ruff reports an unused import.", "priorities": priorities, "progress_note": ""})
		} else {
			advisories := []any{}
			for _, m := range ids {
				advisories = append(advisories, map[string]any{"finding_id": m[1], "explanation": "The import is never used.", "recommended_action": "Delete the import or run ruff check --fix.", "urgency": "scheduled"})
			}
			answer, _ = json.Marshal(map[string]any{"advisories": advisories})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "fake-1", "choices": []any{map[string]any{"message": map[string]any{"content": string(answer)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 120, "completion_tokens": 40}})
	}))
	t.Cleanup(server.Close)
	return server, func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(seen, "\n---\n")
	}
}

// A lint run from profile to register to AI triage, against a real runner
// process with a stand-in ruff and a stand-in self-hosted model.
func TestPostgresQALintAndTriage(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	schema := "ql_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: db, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, db)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, c.Name, syntheticSource{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.webhook_subscriptions(id,name,url,secret_ciphertext,events) VALUES($1,'assign-events','https://hooks.example.com/a','\x00','["finding.assigned"]')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	scan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(scanner.Output{Stages: []assessments.Stage{{Name: "integrity", Status: "ok"}}})
	}))
	defer scan.Close()
	w := Worker{Store: jobs, Connections: providers, Source: lintSource{}, Artifacts: &artifactSink{}, ScannerURL: scan.URL + "/scan", ScannerToken: strings.Repeat("s", 40), Logger: slog.Default(), LLMPrivateHosts: map[string]bool{"127.0.0.1": true}}
	assess := func() assessments.Assessment {
		t.Helper()
		if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}, uuid.New(), "tester", uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		job, err := jobs.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.run(ctx, &job); err != nil {
			t.Fatal(err)
		}
		done, _ := jobs.Get(ctx, job.ID)
		return done
	}
	first := assess()

	// The provider and a profile with lint and AI triage on.
	model, shown := triageModel(t)
	key, _ := json.Marshal(map[string]string{"api_key": "model-key"})
	provider, err := jobs.CreateLLMProvider(ctx, assessments.LLMProvider{Name: "local-model", Kind: "openai_compatible", BaseURL: model.URL + "/v1", Model: "fake-1", MaxTokens: 4096, Enabled: true}, uuid.Nil, func(id uuid.UUID) ([]byte, error) { return providers.Seal(key, assessments.LLMAAD(id)) })
	if err != nil {
		t.Fatal(err)
	}
	vars, _ := json.Marshal(map[string]string{})
	sealed, _ := providers.Seal(vars, assessments.QAAAD(first.AssetID))
	profile := assessments.QAProfile{AssetID: first.AssetID, Enabled: true, AutoRun: true, Functional: true, Refs: []string{"main"}, BaseURL: "https://staging.example.com", Threads: 1, TimeoutSeconds: 600, TestPath: "karate", LLMProviderID: &provider.ID, Lint: &qa.Lint{Tools: []string{"ruff"}}, AITriage: true}
	saved, err := jobs.PutQAProfile(ctx, profile, 0, sealed, uuid.Nil)
	if err != nil || saved.Lint == nil || !saved.AITriage {
		t.Fatal(saved, err)
	}
	if got, err := jobs.QAProfileFor(ctx, first.AssetID); err != nil || got.Lint == nil || got.Lint.Tools[0] != "ruff" || !got.AITriage {
		t.Fatal("profile round trip", got, err)
	}
	bad := profile
	bad.Lint = &qa.Lint{Tools: []string{"rm"}}
	if _, err := jobs.PutQAProfile(ctx, bad, saved.Revision, nil, uuid.Nil); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("unknown linter accepted", err)
	}
	noProvider := profile
	noProvider.LLMProviderID = nil
	if _, err := jobs.PutQAProfile(ctx, noProvider, saved.Revision, nil, uuid.Nil); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("ai_triage without a provider accepted", err)
	}

	// The runner, with a stand-in ruff.
	script := filepath.Join(t.TempDir(), "ruff")
	if err := os.WriteFile(script, []byte(fakeRuffQA), 0o755); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("r", 40)
	server, err := qarunner.New(qarunner.Config{Token: token, WorkDir: t.TempDir(), Slots: 2, Lint: map[string]string{"ruff": script}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	runnerCtx, stop := context.WithCancel(ctx)
	defer stop()
	go server.Run(runnerCtx)
	runnerHTTP := httptest.NewServer(server.Handler())
	defer runnerHTTP.Close()
	w.QARunner, _ = qa.NewRunner(runnerHTTP.URL, token, "", true)
	w.QAReports = &reportSink{keys: map[string][]byte{}}
	drive := func(id uuid.UUID) assessments.QARun {
		t.Helper()
		for i := 0; i < 300; i++ {
			if _, err := w.QAOnce(ctx); err != nil {
				t.Fatal(err)
			}
			run, _ := jobs.QARunByID(ctx, id)
			switch run.Status {
			case "passed", "failed", "error", "cancelled", "skipped":
				return run
			}
			_, _ = pool.Exec(ctx, `UPDATE `+schema+`.qa_runs SET run_after=clock_timestamp()`)
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal("run did not finish")
		return assessments.QARun{}
	}
	lintRunOf := func(a assessments.Assessment) assessments.QARun {
		t.Helper()
		runs, _ := jobs.QARuns(ctx, assessments.QARunFilter{Assessment: a.ID, Kind: qa.KindLint})
		if len(runs) != 1 || runs[0].Trigger != "assessment" {
			t.Fatalf("lint runs %+v", runs)
		}
		return runs[0]
	}

	// An assessment queues a lint run next to the functional one.
	second := assess()
	run := drive(lintRunOf(second).ID)
	if run.Status != "failed" || run.Summary.Lint == nil || run.Summary.Lint.Issues != 1 || run.Summary.Lint.ByTool["ruff"] != 1 || run.ReportSHA256 == "" {
		t.Fatalf("lint run %+v %+v", run, run.Summary.Lint)
	}
	all, _ := jobs.Findings(ctx, second.ID, uuid.Nil, uuid.Nil)
	var lintFinding assessments.Finding
	for _, f := range all {
		if f.Type == "qa_lint" {
			lintFinding = f
		}
	}
	if lintFinding.ID == uuid.Nil || lintFinding.Component.Path != "app/main.py#ruff/F401" || lintFinding.Severity != "low" || !strings.Contains(string(lintFinding.Evidence), run.ID.String()) {
		t.Fatalf("lint finding %+v", lintFinding)
	}
	if after, _ := jobs.Get(ctx, second.ID); after.Verdict != second.Verdict {
		t.Fatal("a lint run changed the assessment verdict")
	}

	// The profile asked for AI triage, so one was queued without a request.
	triages, err := jobs.QATriages(ctx, run.ID)
	if err != nil || len(triages) != 1 || triages[0].Status != "queued" || triages[0].Options.QARunID == nil {
		t.Fatal("automatic triage", triages, err)
	}
	if worked, err := w.AISummaryOnce(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	done, _ := jobs.AISummaryByID(ctx, triages[0].ID)
	if done.Status != "succeeded" || done.Advisories != 1 || done.SummaryDocumentID == nil || done.Incomplete != "" {
		t.Fatalf("triage %+v", done)
	}
	var kind, body string
	_ = pool.QueryRow(ctx, `SELECT kind,body FROM `+schema+`.knowledge_documents WHERE id=$1`, *done.SummaryDocumentID).Scan(&kind, &body)
	if kind != "qa_summary" || !strings.Contains(body, "One lint rule is broken") || !strings.Contains(body, "not verified") {
		t.Fatalf("summary document %s %q", kind, body)
	}
	var advisory string
	if err := pool.QueryRow(ctx, `SELECT body FROM `+schema+`.knowledge_documents WHERE kind='advisory' AND finding_id=$1`, lintFinding.ID).Scan(&advisory); err != nil || !strings.Contains(advisory, "ruff check --fix") {
		t.Fatalf("advisory for the lint entry %q %v", advisory, err)
	}
	prompt := shown()
	for _, want := range []string{"F401", "app/main.py", "<untrusted-data"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("model prompt lacks %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "SOURCE-LINE-MUST-NOT-REACH-THE-MODEL") {
		t.Fatal("source code reached the model")
	}
	// A second request while one exists is refused only when it is active;
	// a hosted provider is never sent QA text.
	policy := w.sourcePolicy()
	allow := func(p assessments.LLMProvider) bool {
		_, ok := policy.Check(llmSettingsOf(p), p.SourceAckAt != nil)
		return ok
	}
	hosted, err := jobs.CreateLLMProvider(ctx, assessments.LLMProvider{Name: "hosted", Kind: "openai_compatible", BaseURL: "https://api.example.com/v1", Model: "m", MaxTokens: 4096, Enabled: true}, uuid.Nil, func(id uuid.UUID) ([]byte, error) { return providers.Seal(key, assessments.LLMAAD(id)) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.EnqueueQATriage(ctx, run.ID, hosted.ID, "tester", allow); !errors.Is(err, assessments.ErrQASource) {
		t.Fatal("a hosted provider was queued for QA triage:", err)
	}
	if _, err := jobs.EnqueueQATriage(ctx, run.ID, uuid.New(), "tester", allow); !errors.Is(err, assessments.ErrAISummaryProvider) {
		t.Fatal("unknown provider:", err)
	}
	again, err := jobs.EnqueueQATriage(ctx, run.ID, provider.ID, "tester", allow)
	if err != nil || again.Status != "queued" {
		t.Fatal("manual re-triage", again, err)
	}
	if _, err := jobs.EnqueueQATriage(ctx, run.ID, provider.ID, "tester", allow); !errors.Is(err, assessments.ErrConflict) {
		t.Fatal("two triages of one run at once:", err)
	}
	if _, err := jobs.EnqueueQATriage(ctx, uuid.New(), provider.ID, "tester", allow); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("unknown run:", err)
	}

	// Once the source is clean, the next lint run closes the entry.
	w.Source = lintSource{clean: true}
	third := assess()
	clean := drive(lintRunOf(third).ID)
	var status string
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE id=$1`, lintFinding.ID).Scan(&status)
	if clean.Status != "passed" || status != "fixed" {
		t.Fatalf("clean lint run %s closed the entry as %q", clean.Status, status)
	}

	// A profile that only lints needs no base_url and queues no Karate run.
	current, _ := jobs.QAProfileFor(ctx, first.AssetID)
	lintOnly := current
	lintOnly.Functional, lintOnly.BaseURL = false, ""
	if _, err := jobs.PutQAProfile(ctx, lintOnly, current.Revision, nil, uuid.Nil); err != nil {
		t.Fatal("lint-only profile:", err)
	}
	fourth := assess()
	kinds, _ := jobs.QARuns(ctx, assessments.QARunFilter{Assessment: fourth.ID})
	if len(kinds) != 1 || kinds[0].Kind != qa.KindLint {
		t.Fatalf("a lint-only profile queued %+v", kinds)
	}
	if _, err := jobs.EnqueueQARun(ctx, first.AssetID, nil, qa.KindFunctional, false, "tester"); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("a functional run needs a deployed target:", err)
	}

	// Assigning an entry emits finding.assigned once, and only on change.
	if err := jobs.Assign(ctx, lintFinding.ID, uuid.Nil, "tester", "platform-team", ""); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Assign(ctx, lintFinding.ID, uuid.Nil, "tester", "platform-team", ""); err != nil {
		t.Fatal(err)
	}
	var assigned int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.webhook_deliveries WHERE event_type='finding.assigned'`).Scan(&assigned)
	if assigned != 1 {
		t.Fatal("finding.assigned deliveries:", assigned)
	}
}

func llmSettingsOf(p assessments.LLMProvider) llm.Provider {
	return llm.Provider{Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model, MaxTokens: p.MaxTokens, Temperature: p.Temperature}
}
