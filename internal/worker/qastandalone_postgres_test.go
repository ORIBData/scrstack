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

// refRecordingSource notes the ref and commit each snapshot asked for.
type refRecordingSource struct {
	lintSource
	mu    *sync.Mutex
	calls *[][2]string
}

func (s refRecordingSource) Snapshot(ctx context.Context, c connections.Connection, secret json.RawMessage, repository, ref, commit string) ([]byte, string, bool, error) {
	s.mu.Lock()
	*s.calls = append(*s.calls, [2]string{ref, commit})
	s.mu.Unlock()
	return s.lintSource.Snapshot(ctx, c, secret, repository, ref, commit)
}

// QA without a security assessment: the profile's gate, a run of the head of a
// ref, a full run, and an assessment that is exempt from QA.
func TestPostgresQAWithoutAssessment(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	schema := "qs_" + uuid.NewString()[:8]
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
	var assetID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator='org/repo'`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls [][2]string
	scan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(scanner.Output{Stages: []assessments.Stage{{Name: "integrity", Status: "ok"}}})
	}))
	defer scan.Close()
	w := Worker{Store: jobs, Connections: providers, Source: refRecordingSource{mu: &mu, calls: &calls}, Artifacts: &artifactSink{}, ScannerURL: scan.URL + "/scan", ScannerToken: strings.Repeat("s", 40), Logger: slog.Default()}
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
	assess := func(skip bool) assessments.Assessment {
		t.Helper()
		if _, _, err := jobs.Enqueue(ctx, assessments.Request{SkipQA: skip, Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}, uuid.New(), "tester", uuid.NewString()); err != nil {
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

	// A lint-only profile with the default gate: no assessment, no run.
	vars, _ := json.Marshal(map[string]string{})
	sealed, _ := providers.Seal(vars, assessments.QAAAD(assetID))
	profile := assessments.QAProfile{AssetID: assetID, Enabled: true, AutoRun: true, Functional: false, Refs: []string{"main", "release/*"}, Threads: 1, TimeoutSeconds: 600, TestPath: "karate", Lint: &qa.Lint{Tools: []string{"ruff"}}}
	saved, err := jobs.PutQAProfile(ctx, profile, 0, sealed, uuid.Nil)
	if err != nil || saved.Gate != assessments.QAGateAssessment {
		t.Fatal("default gate", saved.Gate, err)
	}
	if _, err := jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: qa.KindLint, By: "ci"}); !errors.Is(err, assessments.ErrQANoAssessment) {
		t.Fatal("a gated profile ran without an assessment", err)
	}
	profile.Gate = "open"
	if _, err := jobs.PutQAProfile(ctx, profile, saved.Revision, nil, uuid.Nil); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("unknown gate accepted", err)
	}

	// Gate none: the run needs no assessment and tests the head of the ref.
	profile.Gate = assessments.QAGateNone
	saved, err = jobs.PutQAProfile(ctx, profile, saved.Revision, nil, uuid.Nil)
	if err != nil || saved.Gate != assessments.QAGateNone {
		t.Fatal(saved.Gate, err)
	}
	if got, _ := jobs.QAProfileFor(ctx, assetID); got.Gate != assessments.QAGateNone {
		t.Fatal("gate not stored", got.Gate)
	}
	if _, err := jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: qa.KindLint, Ref: "feature/x", By: "ci"}); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("a ref outside the profile's refs was accepted", err)
	}
	other := uuid.New()
	if _, err := jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Assessment: &other, Kind: qa.KindLint, Ref: "main", By: "ci"}); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("ref with an assessment was accepted", err)
	}
	runs, err := jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: qa.KindLint, Ref: "main", By: "qa-pipeline"})
	if err != nil || len(runs) != 1 {
		t.Fatal(runs, err)
	}
	queued := runs[0]
	if queued.AssessmentID != nil || queued.Commit != "" || queued.Ref != "main" || queued.RequestedBy != "qa-pipeline" || queued.Trigger != "manual" {
		t.Fatalf("queued run %+v", queued)
	}
	done := drive(queued.ID)
	if done.Status == "error" || done.Commit != qaCommit || done.AssessmentID != nil {
		t.Fatalf("finished run %+v", done)
	}
	mu.Lock()
	first := calls[0]
	mu.Unlock()
	if first != [2]string{"main", ""} {
		t.Fatalf("snapshot asked for ref %q commit %q; a run without an assessment resolves the ref", first[0], first[1])
	}
	// The run's lint findings are recorded without an assessment.
	var entries int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.findings WHERE type='qa_lint' AND asset_id=$1`, assetID).Scan(&entries); err != nil || entries == 0 {
		t.Fatal("no qa_lint entries for a run without an assessment", entries, err)
	}

	// AI triage files its texts under an assessment, so it says so plainly.
	if _, err := jobs.EnqueueQATriage(ctx, done.ID, uuid.New(), "ci", func(assessments.LLMProvider) bool { return true }); !errors.Is(err, assessments.ErrQATriageUnassessed) {
		t.Fatal("triage of a run without an assessment", err)
	}
	w.autoTriage(ctx, done, assessments.QAOutcome{Status: qa.StateFailed}) // must not panic or queue

	// An empty ref is the repository's default branch.
	runs, err = jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: qa.KindLint, By: "qa-pipeline"})
	if err != nil {
		t.Fatal(err)
	}
	drive(runs[0].ID)
	mu.Lock()
	last := calls[len(calls)-1]
	mu.Unlock()
	if last != [2]string{"", ""} {
		t.Fatalf("empty ref asked for %q", last)
	}

	// Full QA runs what the profile configures and nothing else.
	if _, err := jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: assessments.QAKindFull, By: "ci"}); err != nil {
		t.Fatal("lint-only profile cannot run full", err)
	}
	profile.Functional, profile.BaseURL = true, "https://staging.example.com"
	saved, err = jobs.PutQAProfile(ctx, profile, saved.Revision, nil, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	runs, err = jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: assessments.QAKindFull, Ref: "main", By: "ci"})
	if err != nil || len(runs) != 2 || runs[0].Kind != qa.KindFunctional || runs[1].Kind != qa.KindLint {
		t.Fatalf("full runs %+v %v", runs, err)
	}
	profile.Lint, profile.Functional, profile.BaseURL = nil, false, ""
	if _, err := jobs.PutQAProfile(ctx, profile, saved.Revision, nil, uuid.Nil); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("a profile that runs nothing was accepted", err)
	}

	// The default gate still refuses a commit that failed its assessment.
	profile.Lint, profile.Gate = &qa.Lint{Tools: []string{"ruff"}}, assessments.QAGateAssessment
	saved, _ = jobs.QAProfileFor(ctx, assetID)
	if saved, err = jobs.PutQAProfile(ctx, profile, saved.Revision, nil, uuid.Nil); err != nil {
		t.Fatal(err)
	}

	// An assessment queues QA unless it is exempt.
	withQA := assess(false)
	if got, _ := jobs.QARuns(ctx, assessments.QARunFilter{Assessment: withQA.ID}); len(got) != 1 || got[0].Kind != qa.KindLint {
		t.Fatalf("assessment queued %+v", got)
	}
	exempt := assess(true)
	if got, _ := jobs.QARuns(ctx, assessments.QARunFilter{Assessment: exempt.ID}); len(got) != 0 {
		t.Fatalf("an exempt assessment queued QA: %+v", got)
	}
	// With the gate in place a manual run tests the assessed commit.
	runs, err = jobs.EnqueueQA(ctx, assessments.QAEnqueue{Asset: assetID, Kind: qa.KindLint, By: "ci"})
	if err != nil || runs[0].AssessmentID == nil || runs[0].Commit != qaCommit {
		t.Fatalf("gated run %+v %v", runs, err)
	}
}
