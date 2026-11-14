package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/qarunner"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const qaCommit = "cccccccccccccccccccccccccccccccccccccccc"

const qaSpec = `openapi: 3.0.3
info: {title: Users, version: "1"}
paths:
  /users:
    get: {operationId: listUsers, responses: {"200": {description: ok}}}
    post: {operationId: createUser, responses: {"201": {description: created}}}
  /users/{id}:
    get: {operationId: getUser, responses: {"200": {description: ok}}}
`

// qaSource serves a repository with a Karate project, an OpenAPI document
// and a Go file without tests.
type qaSource struct{ syntheticSource }

func (qaSource) Snapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error) {
	archive, err := qa.Pack([]qa.File{
		{Path: "org-repo-ccc/karate/users/users.feature", Data: []byte("Feature: users\nScenario: get user\n* url baseUrl\n")},
		{Path: "org-repo-ccc/karate/karate-config.js", Data: []byte("function fn() { return { baseUrl: java.lang.System.getenv('SCRS_BASE_URL') }; }")},
		{Path: "org-repo-ccc/karate/.karate/karate-cli.json", Data: []byte(`{"karate_version":"latest"}`)},
		{Path: "org-repo-ccc/api/openapi.yaml", Data: []byte(qaSpec)},
		{Path: "org-repo-ccc/pkg/math.go", Data: []byte("package pkg\n\n// Add adds.\nfunc Add(a, b int) int { return a + b }\n" + strings.Repeat("// padding line for a realistic file\n", 10))},
	})
	return archive, qaCommit, false, err
}

// fakeKarateQA writes Karate 2 events for each suite: the repository suite
// has a passing GET /users/1 and a failing GET /users tagged high; the
// generated suite passes a POST /users. It refuses to run without the
// secret or, for the generated suite, without SCRS's karate-config.js.
const fakeKarateQA = `#!/bin/sh
out=""; dir=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift;; -w) dir="$2"; shift;; esac
  shift
done
[ -n "$QA_API_TOKEN" ] || exit 4
[ -d "$dir/.karate" ] && exit 5
mkdir -p "$out/karate-json"
case "$dir" in
*generated)
  grep -q "QA_API_TOKEN" "$dir/karate-config.js" || exit 3
  printf '{"type":"SCENARIO_EXIT","data":{"feature":"users/create.feature","name":"create user","line":4,"tags":["scrs-generated"],"passed":true,"skipped":false,"durationMillis":3}}\n{"type":"FEATURE_EXIT","data":{"stepLog":"1 > Authorization: Bearer %s\\n1 < 201 POST %s/users (1 ms)\\n"}}\n' "$QA_API_TOKEN" "$SCRS_BASE_URL" > "$out/karate-json/karate-events.jsonl"
  exit 0;;
esac
printf '{"type":"SUITE_ENTER","data":{"version":"2.1.4"}}\n{"type":"SCENARIO_EXIT","data":{"feature":"users/users.feature","name":"get user","line":2,"tags":[],"passed":true,"skipped":false,"durationMillis":5}}\n{"type":"SCENARIO_EXIT","data":{"feature":"users/users.feature","name":"list users","line":9,"tags":["severity=high"],"passed":false,"skipped":false,"durationMillis":5,"errorReason":"expected status: 200, actual: 500"}}\n{"type":"FEATURE_EXIT","data":{"stepLog":"1 < 200 GET %s/users/1 (1 ms)\\n1 < 500 GET %s/users (2 ms)\\n"}}\n' "$SCRS_BASE_URL" "$SCRS_BASE_URL" > "$out/karate-json/karate-events.jsonl"
exit 1
`

type reportSink struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func (r *reportSink) PutQAReport(_ context.Context, data []byte) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	digest := assessments.Hash(data)
	r.keys["qa/"+digest+".tar.gz"] = data
	return "qa/" + digest + ".tar.gz", digest, nil
}

// fakeModel answers chat completions: Karate features for API prompts (one
// valid, one using karate.exec) and a Go test for unit prompts.
func fakeModel(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer model-key" || len(body.Messages) != 2 {
			w.WriteHeader(401)
			return
		}
		text := "=== FILE: pkg/math_test.go ===\npackage pkg\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"add\")\n\t}\n}\n=== END FILE ==="
		if strings.Contains(body.Messages[0].Content, "Karate") {
			if !strings.Contains(body.Messages[1].Content, "POST /users") {
				t.Errorf("untested operation not requested first: %s", body.Messages[1].Content)
			}
			text = "=== FILE: users/create.feature ===\n@scrs-generated\nFeature: create\nBackground:\n* url baseUrl\n@op=createUser\nScenario: create user\nGiven path 'users'\nAnd request { name: 'Ada' }\nWhen method post\nThen status 201\n=== END FILE ===\n=== FILE: users/evil.feature ===\nFeature: evil\nBackground:\n* url baseUrl\nScenario: x\n* def out = karate.exec('id')\n=== END FILE ==="
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "fake-1", "choices": []any{map[string]any{"message": map[string]any{"content": text}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestPostgresQAPipeline(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: db, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, db)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
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
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.webhook_subscriptions(id,name,url,secret_ciphertext,events) VALUES($1,'qa-events','https://hooks.example.com/qa','\x00','["qa.completed","qa.failed"]')`, uuid.New()); err != nil {
		t.Fatal(err)
	}

	// The scanner reports the OpenAPI document, and malware when asked.
	malware := false
	scan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := scanner.Output{Files: []assessments.FileEvidence{{Path: "api/openapi.yaml", SHA256: strings.Repeat("d", 64)}}, Stages: []assessments.Stage{{Name: "integrity", Status: "ok"}}}
		if malware {
			out.Findings = []assessments.Finding{{Type: "malware", AdvisoryID: "EICAR", Title: "test", Severity: "critical", Score: 100, Component: assessments.Component{Path: "x"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)}}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer scan.Close()
	token := strings.Repeat("s", 40)
	w := Worker{Store: jobs, Connections: providers, Source: qaSource{}, Artifacts: &artifactSink{}, ScannerURL: scan.URL + "/scan", ScannerToken: token, Logger: slog.Default(), LLMPrivateHosts: map[string]bool{"127.0.0.1": true}}
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

	// Without a profile, an API repository gets a report-only finding.
	first := assess()
	findings, _ := jobs.Findings(ctx, first.ID, uuid.Nil, uuid.Nil)
	if len(findings) != 1 || findings[0].Type != "qa_unconfigured" || first.Verdict == "fail" || first.Counts["qa"] != 1 {
		t.Fatalf("unconfigured finding %+v %+v", findings, first)
	}
	if runs, _ := jobs.QARuns(ctx, assessments.QARunFilter{Asset: first.AssetID}); len(runs) != 0 {
		t.Fatal("run queued without a profile")
	}

	// An LLM provider and the profile.
	model := fakeModel(t)
	plainKey, _ := json.Marshal(map[string]string{"api_key": "model-key"})
	provider, err := jobs.CreateLLMProvider(ctx, assessments.LLMProvider{Name: "fake", Kind: "openai_compatible", BaseURL: model.URL + "/v1", Model: "fake-1", MaxTokens: 4096, Enabled: true}, uuid.Nil, func(id uuid.UUID) ([]byte, error) { return providers.Seal(plainKey, assessments.LLMAAD(id)) })
	if err != nil || !provider.HasKey {
		t.Fatal(provider, err)
	}
	vars, _ := json.Marshal(map[string]string{"API_TOKEN": "qa-secret-value"})
	sealed, _ := providers.Seal(vars, assessments.QAAAD(first.AssetID))
	profile := assessments.QAProfile{AssetID: first.AssetID, Enabled: true, AutoRun: true, Refs: []string{"main"}, BaseURL: "https://staging.example.com", Environment: "staging", Threads: 2, TimeoutSeconds: 600, TestPath: "karate", Auth: assessments.QAAuth{Header: "Authorization", Variable: "API_TOKEN", Prefix: "Bearer "}, VariableNames: []string{"API_TOKEN"}, LLMProviderID: &provider.ID, AllowSourceUpload: true}
	if _, err := jobs.PutQAProfile(ctx, profile, 0, sealed, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.PutQAProfile(ctx, profile, 0, sealed, uuid.Nil); err != assessments.ErrConflict {
		t.Fatal("second create must conflict", err)
	}

	// The runner with a stand-in Karate.
	script := filepath.Join(t.TempDir(), "karate")
	if err := os.WriteFile(script, []byte(fakeKarateQA), 0o755); err != nil {
		t.Fatal(err)
	}
	runnerToken := strings.Repeat("r", 40)
	server, err := qarunner.New(qarunner.Config{Token: runnerToken, WorkDir: t.TempDir(), Slots: 2, Karate: []string{script}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	runnerCtx, stopRunner := context.WithCancel(ctx)
	defer stopRunner()
	go server.Run(runnerCtx)
	runnerHTTP := httptest.NewServer(server.Handler())
	defer runnerHTTP.Close()
	w.QARunner, _ = qa.NewRunner(runnerHTTP.URL, runnerToken, "", true)
	sink := &reportSink{keys: map[string][]byte{}}
	w.QAReports = sink

	// drive steps a run until it finishes, skipping poll delays.
	drive := func(id uuid.UUID) assessments.QARun {
		t.Helper()
		for i := 0; i < 200; i++ {
			if _, err := w.QAOnce(ctx); err != nil {
				t.Fatal(err)
			}
			run, _ := jobs.QARunByID(ctx, id)
			switch run.Status {
			case "passed", "failed", "error", "cancelled", "skipped":
				return run
			}
			_, _ = pool.Exec(ctx, `UPDATE `+schema+`.qa_runs SET run_after=clock_timestamp()`)
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("run did not finish")
		return assessments.QARun{}
	}

	// A successful assessment of main queues a functional run.
	second := assess()
	runs, _ := jobs.QARuns(ctx, assessments.QARunFilter{Assessment: second.ID})
	if len(runs) != 1 || runs[0].Trigger != "assessment" || runs[0].Commit != qaCommit || runs[0].Status != "queued" {
		t.Fatalf("queued run %+v", runs)
	}
	run := drive(runs[0].ID)
	if run.Status != "failed" || run.Summary.Passed != 1 || run.Summary.Failed != 1 || run.Coverage == nil || run.Coverage.Total != 3 || run.Coverage.Covered != 2 || run.ReportSHA256 == "" || run.Coverage.Spec != "api/openapi.yaml" {
		t.Fatalf("finished run %+v %+v", run, run.Coverage)
	}
	report := sink.keys["qa/"+run.ReportSHA256+".tar.gz"]
	if report == nil || bytes.Contains(report, []byte("qa-secret-value")) {
		t.Fatal("report not stored")
	}
	failed, _, err := jobs.QAScenarios(ctx, run.ID, -1, "failed")
	if err != nil || len(failed) != 1 || failed[0].Name != "list users" || failed[0].Suite != "repo" {
		t.Fatal("scenarios", failed, err)
	}
	byType := func(a assessments.Assessment) map[string][]assessments.Finding {
		all, _ := jobs.Findings(ctx, a.ID, uuid.Nil, uuid.Nil)
		out := map[string][]assessments.Finding{}
		for _, f := range all {
			out[f.Type] = append(out[f.Type], f)
		}
		return out
	}
	got := byType(second)
	if len(got["qa_failure"]) != 1 || got["qa_failure"][0].Severity != "high" || len(got["qa_untested"]) != 1 || got["qa_untested"][0].Component.Name != "POST /users" || len(got["qa_config"]) != 0 {
		t.Fatalf("QA findings %+v", got)
	}
	if after, _ := jobs.Get(ctx, second.ID); after.Verdict != second.Verdict {
		t.Fatal("a QA run changed the assessment verdict")
	}
	var events int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.webhook_deliveries WHERE event_type='qa.completed'`).Scan(&events)
	if events != 1 {
		t.Fatal("qa.completed not emitted", events)
	}

	// Phase 2: an API generation drafts features for the untested operation.
	gen, err := jobs.EnqueueQAGeneration(ctx, second.AssetID, "api", assessments.QAGenerationOptions{MaxOperations: 1}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := w.GenerateOnce(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	gen, _ = jobs.QAGenerationByID(ctx, gen.ID)
	suites, _ := jobs.QASuites(ctx, assessments.QASuiteFilter{Generation: gen.ID})
	if gen.Status != "succeeded" || gen.Accepted != 1 || gen.Rejected != 1 || gen.InputTokens != 100 || len(suites) != 2 {
		t.Fatalf("generation %+v suites %+v", gen, suites)
	}
	var draft, rejected assessments.QASuite
	for _, s := range suites {
		if s.Status == "draft" {
			draft = s
		} else if s.Path != "users/evil.feature" || len(s.Problems) == 0 {
			t.Fatalf("unsafe feature not rejected %+v", s)
		} else {
			rejected = s
		}
	}
	if draft.Path != "users/create.feature" || draft.Source != "POST /users" {
		t.Fatalf("draft %+v", draft)
	}
	if _, err := jobs.ReviewQASuite(ctx, rejected.ID, true, "admin", ""); err != assessments.ErrQAState {
		t.Fatal("rejected file approved", err)
	}
	if _, err := jobs.ReviewQASuite(ctx, draft.ID, true, "admin", "looks right"); err != nil {
		t.Fatal(err)
	}

	// The approved feature runs as the generated suite and covers POST /users.
	manual, err := jobs.EnqueueQARun(ctx, second.AssetID, nil, "functional", false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	manual = drive(manual.ID)
	if manual.Coverage == nil || manual.Coverage.Covered != 3 || manual.Summary.Scenarios != 3 {
		t.Fatalf("generated suite not run %+v %+v", manual, manual.Coverage)
	}
	// The register (not the assessment's snapshot) shows the closure.
	status := func(f assessments.Finding) string {
		var s string
		_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE fingerprint=$1`, f.Fingerprint).Scan(&s)
		return s
	}
	if status(got["qa_untested"][0]) != "fixed" || status(got["qa_failure"][0]) != "open" {
		t.Fatal("untested finding not closed by the run that covered it")
	}

	// Phase 3: a unit-test generation drafts a Go test for the untested file.
	unit, err := jobs.EnqueueQAGeneration(ctx, second.AssetID, "unit", assessments.QAGenerationOptions{MaxFiles: 2}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.GenerateOnce(ctx); err != nil {
		t.Fatal(err)
	}
	unitSuites, _ := jobs.QASuites(ctx, assessments.QASuiteFilter{Generation: unit.ID, Content: true})
	if len(unitSuites) != 1 || unitSuites[0].Path != "pkg/math_test.go" || unitSuites[0].Source != "pkg/math.go" || unitSuites[0].Status != "draft" || !strings.Contains(unitSuites[0].Content, "TestAdd") {
		t.Fatalf("unit suites %+v", unitSuites)
	}

	// Cancelling an active run removes the runner job.
	cancelled, _ := jobs.EnqueueQARun(ctx, second.AssetID, nil, "functional", false, "tester")
	if _, err := w.QAOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.CancelQARun(ctx, cancelled.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.QAOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var cleanup bool
	_ = pool.QueryRow(ctx, `SELECT cleanup FROM `+schema+`.qa_runs WHERE id=$1`, cancelled.ID).Scan(&cleanup)
	if _, err := w.QARunner.Status(ctx, cancelled.ID.String()); err != qa.ErrUnknownJob || cleanup {
		t.Fatal("cancelled job left on the runner", err, cleanup)
	}
	if _, err := jobs.CancelQARun(ctx, cancelled.ID, "tester"); err != assessments.ErrQAState {
		t.Fatal("finished run cancelled again", err)
	}

	// A commit that fails its security gate is never sent to the runner.
	malware = true
	blocked := assess()
	skipped, _ := jobs.QARuns(ctx, assessments.QARunFilter{Assessment: blocked.ID})
	if blocked.Verdict != "fail" || len(skipped) != 1 || skipped[0].Status != "skipped" {
		t.Fatalf("blocked commit %+v %+v", blocked.Verdict, skipped)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.webhook_deliveries WHERE event_type='qa.failed'`).Scan(&events)
	if events != 1 {
		t.Fatal("qa.failed not emitted for the skipped run", events)
	}
	if _, err := jobs.EnqueueQARun(ctx, blocked.AssetID, &blocked.ID, "functional", false, "tester"); err != assessments.ErrQABlocked {
		t.Fatal("manual run of a failed commit", err)
	}
	history, err := jobs.QACoverageHistory(ctx, second.AssetID, "main", 10)
	if err != nil || len(history) != 2 || history[0].Covered != 2 || history[1].Covered != 3 {
		t.Fatalf("coverage history %+v %v", history, err)
	}
	fmt.Fprintln(io.Discard, history)
}
