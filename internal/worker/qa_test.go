package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/llm"
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

// reviewLog records the code-review requests the fake model received, and
// reviewAnswer says what it reports ("full" or "lint_only").
// summaryPrompts records every advisory and summary prompt the fake model saw.
var (
	summaryMu      sync.Mutex
	summaryPrompts []string
)

var (
	reviewMu     sync.Mutex
	reviewSeen   []string
	reviewAnswer = "full"
)

func reviewFinding(category, severity string, line int, title, explanation string) map[string]any {
	return map[string]any{"category": category, "severity": severity, "confidence": "high", "title": title, "explanation": explanation, "suggested_fix": "Handle the case explicitly.", "line_start": line, "line_end": line}
}

// fakeModel answers chat completions: Karate features for API prompts (one
// valid, one using karate.exec), a Go test for unit prompts, and JSON
// findings for code-review prompts.
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
		if strings.Contains(body.Messages[0].Content, "assessment summary") || strings.Contains(body.Messages[0].Content, "Write one advisory for each finding") {
			summaryMu.Lock()
			summaryPrompts = append(summaryPrompts, body.Messages[0].Content+"\n"+body.Messages[1].Content)
			summaryMu.Unlock()
			findingIDs := regexp.MustCompile(`finding_id: ([0-9a-f-]{36})`).FindAllStringSubmatch(body.Messages[1].Content, -1)
			var answer []byte
			if strings.Contains(body.Messages[0].Content, "assessment summary") {
				priorities := []any{}
				if len(findingIDs) > 0 {
					priorities = append(priorities, map[string]any{"finding_id": findingIDs[0][1], "action": "Upgrade the package to its fixed version", "why": "It is known to be exploited. See https://evil.example/x"})
				}
				priorities = append(priorities, map[string]any{"finding_id": uuid.NewString(), "action": "Invented", "why": "dropped"})
				answer, _ = json.Marshal(map[string]any{"headline": "One critical issue needs a fix", "risk_level": "high", "summary": "The most serious finding is a command injection in a popular package.", "priorities": priorities, "progress_note": "Nothing fixed since the last summary."})
			} else {
				advisories := []any{}
				for _, m := range findingIDs {
					advisories = append(advisories, map[string]any{"finding_id": m[1], "explanation": "An attacker can run commands through this package.", "recommended_action": "Upgrade to the fixed version.", "urgency": "immediate"})
				}
				answer, _ = json.Marshal(map[string]any{"advisories": advisories})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"model": "fake-1", "choices": []any{map[string]any{"message": map[string]any{"content": string(answer)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 300, "completion_tokens": 90}})
			return
		}
		if strings.Contains(body.Messages[0].Content, "reviewing one source file") {
			reviewMu.Lock()
			reviewSeen = append(reviewSeen, body.Messages[1].Content)
			mode := reviewAnswer
			reviewMu.Unlock()
			awsKey := strings.Join([]string{"AK", "IA", "IOSFODNN7", "EXAMPLE"}, "")
			findings := []any{
				reviewFinding("lint", "low", 3, "Comment does not describe the function", "The doc comment says nothing about overflow."),
				reviewFinding("poetry", "low", 5, "Unknown category", "dropped"),
				reviewFinding("lint", "low", 999, "Outside the file", "dropped"),
			}
			if mode == "full" {
				findings = append([]any{reviewFinding("production_risk", "high", 4, "Add can overflow", "Adding two large ints overflows silently. Rotate "+awsKey+" ![x](https://evil.example/c?d=1)")}, findings...)
			}
			answer, _ := json.Marshal(map[string]any{"findings": findings})
			_ = json.NewEncoder(w).Encode(map[string]any{"model": "fake-1", "choices": []any{map[string]any{"message": map[string]any{"content": string(answer)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 400, "completion_tokens": 120}})
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

	// ---- AI code review: source goes only to a self-hosted model ----
	policy := llm.SourcePolicy{Private: w.LLMPrivateHosts}
	local := func(p assessments.LLMProvider) (string, bool) {
		return policy.Check(llm.Provider{Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model}, p.SourceAckAt != nil)
	}
	hosted, err := jobs.CreateLLMProvider(ctx, assessments.LLMProvider{Name: "hosted", Kind: "openai_compatible", BaseURL: "https://api.example.com/v1", Model: "m", MaxTokens: 4096, Enabled: true}, uuid.Nil, func(id uuid.UUID) ([]byte, error) { return providers.Seal(plainKey, assessments.LLMAAD(id)) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.EnqueueAIReview(ctx, second.AssetID, hosted.ID, assessments.AIReviewOptions{}, "tester", local); !errors.Is(err, assessments.ErrAIReviewSource) {
		t.Fatal("a hosted provider must never be queued for code review:", err)
	}
	if _, err := jobs.EnqueueAIReview(ctx, second.AssetID, provider.ID, assessments.AIReviewOptions{}, "tester", nil); !errors.Is(err, assessments.ErrAIReviewSource) {
		t.Fatal("without a locality check nothing is queued:", err)
	}
	if _, err := jobs.EnqueueAIReview(ctx, second.AssetID, uuid.New(), assessments.AIReviewOptions{}, "tester", local); !errors.Is(err, assessments.ErrAIReviewProvider) {
		t.Fatal("unknown provider:", err)
	}
	if _, err := jobs.EnqueueAIReview(ctx, second.AssetID, provider.ID, assessments.AIReviewOptions{MaxFiles: 99}, "tester", local); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("file limit:", err)
	}
	verdictBefore, _ := jobs.Get(ctx, *unit.AssessmentID)

	review1, err := jobs.EnqueueAIReview(ctx, second.AssetID, provider.ID, assessments.AIReviewOptions{}, "tester", local)
	if err != nil || review1.Status != "queued" || review1.Options.MaxFiles != 10 || review1.Ref != "main" {
		t.Fatal(review1, err)
	}
	if worked, err := w.AIReviewOnce(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	done, err := jobs.AIReviewByID(ctx, review1.ID)
	if err != nil || done.Status != "succeeded" || done.FilesReviewed != 2 || done.Findings != 2 || done.InputTokens != 800 || done.OutputTokens != 240 || done.Incomplete != "" {
		t.Fatalf("review %+v %v", done, err)
	}
	if done.Redactions["aws_access_key"] != 2 || done.Redactions["image"] != 2 || done.DocumentID == nil {
		t.Fatalf("what the guard removed and the chronicle link: %+v", done)
	}
	reviewMu.Lock()
	sentToModel := strings.Join(reviewSeen, "\n")
	reviewMu.Unlock()
	if !strings.Contains(sentToModel, "4: func Add(a, b int) int") || !strings.Contains(sentToModel, `<untrusted-data label="source_pkg_math.go">`) {
		t.Fatalf("code must reach the model numbered and wrapped as data:\n%s", sentToModel)
	}
	var entries int
	var severity, evidence, guidance string
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.findings WHERE type='ai_review' AND asset_id=$1`, second.AssetID).Scan(&entries)
	if err := pool.QueryRow(ctx, `SELECT severity,evidence::text,guidance::text FROM `+schema+`.findings WHERE type='ai_review' AND title LIKE '%can overflow'`).Scan(&severity, &evidence, &guidance); err != nil {
		t.Fatal(err)
	}
	if entries != 2 || severity != "high" || !strings.Contains(evidence, `"unverified": true`) || !strings.Contains(evidence, "pkg/math.go") || !strings.Contains(guidance, "not verified") {
		t.Fatalf("entries %d %s %s %s", entries, severity, evidence, guidance)
	}
	for _, leak := range []string{"func Add", "AKIA", "evil.example"} {
		if strings.Contains(evidence+guidance, leak) {
			t.Fatalf("%q must not be stored in an entry", leak)
		}
	}
	if verdictAfter, _ := jobs.Get(ctx, *unit.AssessmentID); verdictAfter.Verdict != verdictBefore.Verdict {
		t.Fatal("an AI review must never change an assessment's verdict")
	}
	var detected int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.finding_events e JOIN `+schema+`.findings f ON f.id=e.finding_id WHERE f.type='ai_review' AND e.action='detected'`).Scan(&detected)
	var documentBody, documentKind string
	_ = pool.QueryRow(ctx, `SELECT kind,body FROM `+schema+`.knowledge_documents WHERE id=$1`, *done.DocumentID).Scan(&documentKind, &documentBody)
	var ledger int64
	_ = pool.QueryRow(ctx, `SELECT COALESCE(sum(input_tokens),0) FROM `+schema+`.llm_usage WHERE purpose='code_review' AND assessment_id=$1`, *done.AssessmentID).Scan(&ledger)
	if detected != 2 || documentKind != "code_review" || !strings.Contains(documentBody, "Add can overflow") || strings.Contains(documentBody, "func Add") || !strings.Contains(documentBody, "not verified") || ledger != 800 {
		t.Fatalf("history %d, document %s %q, ledger %d", detected, documentKind, documentBody, ledger)
	}

	// A later review that no longer reports the production risk closes it,
	// and keeps the one it still reports.
	reviewMu.Lock()
	reviewAnswer = "lint_only"
	reviewMu.Unlock()
	review2, _ := jobs.EnqueueAIReview(ctx, second.AssetID, provider.ID, assessments.AIReviewOptions{Paths: []string{"pkg/math.go"}}, "tester", local)
	if _, err := w.AIReviewOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var overflowStatus, lintStatus string
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE title LIKE 'AI review: Add can overflow'`).Scan(&overflowStatus)
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE title LIKE 'AI review: Comment does not%'`).Scan(&lintStatus)
	var closedEvents int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.finding_events WHERE action='fixed_by_ai_review'`).Scan(&closedEvents)
	if got, _ := jobs.AIReviewByID(ctx, review2.ID); got.Status != "succeeded" || got.Findings != 1 || overflowStatus != "fixed" || lintStatus != "open" || closedEvents != 1 {
		t.Fatalf("second review %+v: overflow %s, lint %s, closed events %d", got, overflowStatus, lintStatus, closedEvents)
	}

	// The worker checks again that the provider is still self-hosted: a
	// provider edited to a hosted endpoint after queueing is refused and the
	// model is never called.
	callsBefore := len(reviewSeen)
	review3, _ := jobs.EnqueueAIReview(ctx, second.AssetID, provider.ID, assessments.AIReviewOptions{}, "tester", local)
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.llm_providers SET base_url='https://api.example.com/v1' WHERE id=$1`, provider.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.AIReviewOnce(ctx); err != nil {
		t.Fatal(err)
	}
	blockedReview, _ := jobs.AIReviewByID(ctx, review3.ID)
	reviewMu.Lock()
	calls := len(reviewSeen)
	reviewMu.Unlock()
	if blockedReview.Status != "failed" || !strings.Contains(blockedReview.Error, "self-hosted") || calls != callsBefore {
		t.Fatalf("hosted at run time: %+v, model calls %d -> %d", blockedReview, callsBefore, calls)
	}
	// Unit-test generation sends source too, so it follows the same rule.
	unitHosted, err := jobs.EnqueueQAGeneration(ctx, second.AssetID, "unit", assessments.QAGenerationOptions{MaxFiles: 1}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.GenerateOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := jobs.QAGenerationByID(ctx, unitHosted.ID); got.Status != "failed" || !strings.Contains(got.Error, "self-hosted") {
		t.Fatalf("unit generation to a hosted provider: %+v", got)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.llm_providers SET base_url=$2 WHERE id=$1`, provider.ID, model.URL+"/v1"); err != nil {
		t.Fatal(err)
	}

	// The assessment's token budget: a review that cannot start says so.
	t.Setenv("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", "1000")
	review4, _ := jobs.EnqueueAIReview(ctx, second.AssetID, provider.ID, assessments.AIReviewOptions{}, "tester", local)
	if _, err := w.AIReviewOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := jobs.AIReviewByID(ctx, review4.ID); got.Status != "failed" || !strings.Contains(got.Error, "token budget") {
		t.Fatalf("budget: %+v", got)
	}
	t.Setenv("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", "")
	list, err := jobs.AIReviews(ctx, second.AssetID, 10)
	if err != nil || len(list) != 4 || list[0].ID != review4.ID {
		t.Fatalf("list %d %v", len(list), err)
	}

	// ---- Hosted code review: opt-in by the platform switch and an acknowledgement ----
	openPolicy := llm.SourcePolicy{Private: w.LLMPrivateHosts, AllowHosted: true}
	open := func(p assessments.LLMProvider) (string, bool) {
		return openPolicy.Check(llm.Provider{Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model}, p.SourceAckAt != nil)
	}
	if _, err := jobs.EnqueueAIReview(ctx, second.AssetID, hosted.ID, assessments.AIReviewOptions{}, "tester", open); !errors.Is(err, assessments.ErrAIReviewSource) {
		t.Fatal("with the switch on but no acknowledgement, a hosted provider must be refused:", err)
	}
	if _, err := jobs.SetLLMSourceAck(ctx, hosted.ID, true, "short", "tester", uuid.Nil); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("an acknowledgement needs a real note:", err)
	}
	if _, err := jobs.SetLLMSourceAck(ctx, hosted.ID, true, "Zero-retention agreement signed 2026", "tester", uuid.Nil); err != nil {
		t.Fatal(err)
	}
	hostedReview, err := jobs.EnqueueAIReview(ctx, second.AssetID, hosted.ID, assessments.AIReviewOptions{}, "tester", open)
	if err != nil || hostedReview.Locality != "hosted" {
		t.Fatal("an acknowledged hosted provider with the switch on is accepted and recorded as hosted:", hostedReview, err)
	}
	if _, err := jobs.EnqueueAIReview(ctx, second.AssetID, hosted.ID, assessments.AIReviewOptions{}, "tester", local); !errors.Is(err, assessments.ErrAIReviewSource) {
		t.Fatal("with the switch off, an acknowledgement alone is not enough:", err)
	}
	// The worker checks again: the switch is off in this worker, so the queued
	// review fails before any source is fetched or sent.
	if worked, err := w.AIReviewOnce(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	if got, _ := jobs.AIReviewByID(ctx, hostedReview.ID); got.Status != "failed" || !strings.Contains(got.Error, "may not receive source code") {
		t.Fatalf("a worker without the switch must refuse hosted source: %+v", got)
	}
	// Monthly cap: a hosted provider's spend stops at its cap; a self-hosted
	// one has none.
	kn := jobs.Knowledge()
	if err := kn.RecordUsage(ctx, knowledge.Usage{Purpose: "code_review", Provider: "hosted", Model: "m", InputTokens: 5000, OutputTokens: 100, Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRS_LLM_MONTHLY_INPUT_TOKENS", "4000")
	hostedSettings := llm.Provider{Kind: hosted.Kind, BaseURL: hosted.BaseURL, Model: hosted.Model}
	if err := kn.ReserveMonth(ctx, w.budgetFor(hosted, hostedSettings), 10, 10); !errors.Is(err, knowledge.ErrMonthlyCap) || !errors.Is(err, knowledge.ErrBudget) {
		t.Fatal("monthly cap should stop a hosted provider:", err)
	}
	if err := kn.ReserveMonth(ctx, w.budgetFor(provider, llm.Provider{Kind: provider.Kind, BaseURL: provider.BaseURL, Model: provider.Model}), 10, 10); err != nil {
		t.Fatal("a self-hosted provider has no monthly cap:", err)
	}
	t.Setenv("SCRS_LLM_MONTHLY_INPUT_TOKENS", "0")
	if err := kn.ReserveMonth(ctx, w.budgetFor(hosted, hostedSettings), 10, 10); err != nil {
		t.Fatal("0 removes the cap:", err)
	}
	t.Setenv("SCRS_LLM_MONTHLY_INPUT_TOKENS", "")

	// ---- AI advisories and summaries: only the allowlist reaches the model ----
	assessmentID := *unit.AssessmentID
	addFinding := func(findingType, advisory, title, severity, status, change string, guidance map[string]any, evidence string) uuid.UUID {
		t.Helper()
		f := assessments.Finding{ID: uuid.New(), AssetID: second.AssetID, Ref: "main", Type: findingType, AdvisoryID: advisory, Title: title, Severity: severity, Score: 40, Status: status, Change: change, Component: assessments.Component{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.20", Path: "package-lock.json"}}
		f.Fingerprint = assessments.Hash([]byte(f.ID.String()))
		f.Guidance, _ = json.Marshal(guidance)
		f.Evidence = json.RawMessage(evidence)
		component, _ := json.Marshal(f.Component)
		snapshot, _ := json.Marshal(f)
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,status,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,'main',$4,$5,$6,$7,40,$8,$9,$10,$11,$12)`, f.ID, f.AssetID, f.Fingerprint, findingType, advisory, title, severity, status, component, f.Evidence, f.Guidance, assessmentID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.assessment_findings(assessment_id,finding_id,snapshot) VALUES($1,$2,$3)`, assessmentID, f.ID, snapshot); err != nil {
			t.Fatal(err)
		}
		return f.ID
	}
	critical := addFinding("vulnerability", "GHSA-TEST-0001", "Command injection in lodash template", "critical", "open", "new", map[string]any{"aliases": []string{"CVE-2099-0001"}, "fixed_versions": []string{"4.17.21"}, "kev": true, "epss": 0.9}, `{"source":"osv"}`)
	addFinding("vulnerability", "GHSA-TEST-0002", "Prototype pollution in minimist", "low", "open", "existing", map[string]any{"fixed_versions": []string{"1.2.6"}}, `{}`)
	addFinding("vulnerability", "GHSA-TEST-0003", "Already fixed issue", "high", "fixed", "existing", map[string]any{}, `{}`)
	// None of these may reach a model: code-derived text, paths, secrets.
	addFinding("sast", "gosec:G101", "SAST-DECOY-TITLE hardcoded credential", "high", "open", "new", map[string]any{}, `{"path":"decoy-sast-path/secret.go","snippet":"super-secret-evidence"}`)
	addFinding("secret", "SCRS-SECRET", "SECRET-DECOY-TITLE api key in config", "critical", "open", "new", map[string]any{}, `{"path":"decoy-secret-path/.env"}`)
	addFinding("ai_review", "SCRS-AI-REVIEW:lint:decoy", "AI-REVIEW-DECOY title about func Add", "medium", "open", "new", map[string]any{}, `{"path":"pkg/math.go"}`)
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.advisory_records(origin,id,cve,record,raw) VALUES('osv','GHSA-TEST-0001','CVE-2099-0001','{"summary":"Lodash template command injection","details":"Versions before 4.17.21 allow command injection through the template function."}','{}')`); err != nil {
		t.Fatal(err)
	}

	// A self-hosted embedding server, as the worker reaches it.
	var embedded int
	var embedMu sync.Mutex
	embedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/v1/embeddings" || r.Header.Get("Authorization") != "Bearer embed-key" {
			w.WriteHeader(401)
			return
		}
		embedMu.Lock()
		embedded += len(req.Input)
		embedMu.Unlock()
		data := make([]map[string]any, len(req.Input))
		for i := range req.Input {
			v := make([]float64, 8)
			v[i%8], v[(i+1)%8] = 1, 2
			data[i] = map[string]any{"index": i, "embedding": v}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer embedServer.Close()
	t.Setenv("SCRS_EMBED_URL", embedServer.URL+"/v1")
	t.Setenv("SCRS_EMBED_MODEL", "bge-small-en-v1.5")
	t.Setenv("SCRS_EMBED_DIM", "8")
	t.Setenv("SCRS_EMBED_API_KEY", "embed-key")
	t.Setenv("SCRS_EMBED_PRIVATE_HOSTS", "127.0.0.1")

	// Any provider may be used: a hosted one is accepted, because only the
	// allowlist is sent. (Not run: it has no real endpoint.)
	hostedJob, err := jobs.EnqueueAISummary(ctx, assessmentID, hosted.ID, assessments.AISummaryOptions{}, "tester")
	if err != nil || hostedJob.Options.MaxAdvisories != 10 {
		t.Fatal("a hosted provider is allowed for summaries:", hostedJob, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM `+schema+`.ai_summaries WHERE id=$1`, hostedJob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.EnqueueAISummary(ctx, assessmentID, uuid.New(), assessments.AISummaryOptions{}, "tester"); !errors.Is(err, assessments.ErrAISummaryProvider) {
		t.Fatal("unknown provider:", err)
	}
	if _, err := jobs.EnqueueAISummary(ctx, assessmentID, provider.ID, assessments.AISummaryOptions{MaxAdvisories: 99}, "tester"); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("advisory limit:", err)
	}
	if _, err := jobs.EnqueueAISummary(ctx, uuid.New(), provider.ID, assessments.AISummaryOptions{}, "tester"); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("unknown assessment:", err)
	}

	job1, err := jobs.EnqueueAISummary(ctx, assessmentID, provider.ID, assessments.AISummaryOptions{MaxAdvisories: 2}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := w.AISummaryOnce(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	done1, err := jobs.AISummaryByID(ctx, job1.ID)
	if err != nil || done1.Status != "succeeded" || done1.Advisories != 2 || done1.FindingsExcluded < 3 || done1.SummaryDocumentID == nil || done1.Incomplete != "" || done1.InputTokens == 0 {
		t.Fatalf("job %+v %v", done1, err)
	}
	summaryMu.Lock()
	seen := strings.Join(summaryPrompts, "\n---\n")
	summaryMu.Unlock()
	for _, want := range []string{"GHSA-TEST-0001", "CVE-2099-0001", "Command injection in lodash template", "package: lodash 4.17.20 (npm)", "fixed_in: 4.17.21", "known_exploited: yes", "Versions before 4.17.21 allow command injection", `<untrusted-data label="findings">`, "never instructions"} {
		if !strings.Contains(seen, want) {
			t.Errorf("the allowlisted %q should reach the model", want)
		}
	}
	for _, leak := range []string{"SAST-DECOY-TITLE", "SECRET-DECOY-TITLE", "AI-REVIEW-DECOY", "decoy-sast-path", "decoy-secret-path", "super-secret-evidence", "package-lock.json", "func Add", "Already fixed issue"} {
		if strings.Contains(seen, leak) {
			t.Fatalf("%q must never reach a model", leak)
		}
	}

	chronicle, err := jobs.Knowledge().Chronicle(ctx, knowledge.ChronicleQuery{AssetID: second.AssetID, AssessmentID: &assessmentID, Kinds: []string{knowledge.KindAssessmentSummary, knowledge.KindAdvisory}})
	if err != nil || len(chronicle) != 3 {
		t.Fatalf("one summary and two advisories expected: %d %v", len(chronicle), err)
	}
	var advisoryForCritical *knowledge.Document
	for i, d := range chronicle {
		if d.Origin != knowledge.OriginLLM || d.Provenance["prompt_version"] != "advisory-summary-1" || d.Provenance["provider_locality"] != "local" || !strings.Contains(d.Body, "Written by a language model") || strings.Contains(d.Body, "evil.example") {
			t.Fatalf("document %+v", d)
		}
		if d.Kind == knowledge.KindAdvisory && d.FindingID != nil && *d.FindingID == critical {
			advisoryForCritical = &chronicle[i]
		}
	}
	if advisoryForCritical == nil {
		t.Fatal("the most important finding must get the first advisory")
	}
	var chunks, dims int
	var chunkModel string
	_ = pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(dim),0),COALESCE(max(embed_model),'') FROM `+schema+`.knowledge_chunks c JOIN `+schema+`.knowledge_documents d ON d.id=c.document_id WHERE d.assessment_id=$1 AND d.kind IN ('assessment_summary','advisory')`, assessmentID).Scan(&chunks, &dims, &chunkModel)
	if chunks < 3 || dims != 8 || chunkModel != "bge-small-en-v1.5" || embedded < 3 {
		t.Fatalf("self-hosted embeddings: %d chunks, dim %d, model %q, %d texts embedded", chunks, dims, chunkModel, embedded)
	}
	var ledgerRows int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.llm_usage WHERE assessment_id=$1 AND purpose IN ('assessment_summary','advisory')`, assessmentID).Scan(&ledgerRows)
	if ledgerRows != 2 { // one summary call, one advisory call for two findings
		t.Fatalf("ledger rows %d", ledgerRows)
	}

	// A second job supersedes the first summary and the advisory of the same
	// finding, keeps the old ones, and tells the model what was said before.
	job2, _ := jobs.EnqueueAISummary(ctx, assessmentID, provider.ID, assessments.AISummaryOptions{MaxAdvisories: 1}, "tester")
	if _, err := w.AISummaryOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := jobs.AISummaryByID(ctx, job2.ID); got.Status != "succeeded" || got.Advisories != 1 {
		t.Fatalf("second job %+v", got)
	}
	summaryMu.Lock()
	secondPrompts := strings.Join(summaryPrompts[len(summaryPrompts)-2:], "\n")
	summaryMu.Unlock()
	if !strings.Contains(secondPrompts, `<untrusted-data label="previous_summary">`) || !strings.Contains(secondPrompts, "One critical issue needs a fix") {
		t.Fatal("the previous summary should be given as context:\n", secondPrompts)
	}
	summaryHistory, _ := jobs.Knowledge().Chronicle(ctx, knowledge.ChronicleQuery{AssetID: second.AssetID, Kinds: []string{knowledge.KindAssessmentSummary}, IncludeSuperseded: true})
	summaryCurrent, _ := jobs.Knowledge().Chronicle(ctx, knowledge.ChronicleQuery{AssetID: second.AssetID, Kinds: []string{knowledge.KindAssessmentSummary}})
	if len(summaryHistory) != 2 || len(summaryCurrent) != 1 || summaryHistory[0].SupersededAt == nil || summaryCurrent[0].Supersedes == nil || *summaryCurrent[0].Supersedes != summaryHistory[0].ID {
		t.Fatalf("summary chain: %d total, %d summaryCurrent", len(summaryHistory), len(summaryCurrent))
	}
	critAdvisories, _ := jobs.Knowledge().Chronicle(ctx, knowledge.ChronicleQuery{AssetID: second.AssetID, FindingID: &critical, IncludeSuperseded: true})
	if len(critAdvisories) != 2 || critAdvisories[0].SupersededAt == nil || critAdvisories[1].Supersedes == nil {
		t.Fatalf("advisory chain for the finding: %d", len(critAdvisories))
	}

	// The assessment's token budget stops a job and says so.
	t.Setenv("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", "1000")
	job3, _ := jobs.EnqueueAISummary(ctx, assessmentID, provider.ID, assessments.AISummaryOptions{}, "tester")
	if _, err := w.AISummaryOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := jobs.AISummaryByID(ctx, job3.ID); got.Status != "failed" || !strings.Contains(got.Error, "budget") {
		t.Fatalf("budget: %+v", got)
	}
	t.Setenv("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", "")
	if list, err := jobs.AISummaries(ctx, assessmentID, 10); err != nil || len(list) != 3 || list[0].ID != job3.ID {
		t.Fatalf("list %d %v", len(list), err)
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
