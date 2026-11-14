package assessments_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Workflow change records must not come from an interrupted file walk: a
// path a partial walk did not reach is unknown, not added or deleted. An
// import also cannot start while a scan of the same asset is running.
func TestPostgresWorkflowDiffIgnoresPartialWalksAndImportWaits(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: url, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, url, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, c.Name, inventory{}); err != nil {
		t.Fatal(err)
	}
	s, err := assessments.Open(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	commit := strings.Repeat("c", 40)
	file := func(path, digit string) assessments.FileEvidence {
		return assessments.FileEvidence{Path: path, SHA256: strings.Repeat(digit, 64), Malware: "clean"}
	}
	run := 0
	// complete runs one scan of main and returns its workflow change records.
	complete := func(integrity string, files ...assessments.FileEvidence) []string {
		t.Helper()
		run++
		request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
		if _, _, err := s.Enqueue(ctx, request, uuid.New(), "tester", "diff-"+string(rune('a'+run))); err != nil {
			t.Fatal(err)
		}
		a, err := s.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "integrity", Status: integrity}}
		if err := s.Complete(ctx, a, assessments.Result{Commit: commit, Files: files, Stages: stages}); err != nil {
			t.Fatal(err)
		}
		findings, err := s.Findings(ctx, a.ID, uuid.Nil, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		var changed []string
		for _, f := range findings {
			if f.AdvisoryID == "SCRS-WORKFLOW-CHANGE" {
				var evidence struct{ Path, Change string }
				_ = json.Unmarshal(f.Evidence, &evidence)
				changed = append(changed, evidence.Path+":"+evidence.Change)
			}
		}
		sort.Strings(changed)
		return changed
	}
	a, b, cw := ".github/workflows/a.yml", ".github/workflows/b.yml", ".github/workflows/c.yml"
	if got := complete("ok", file(a, "1"), file(b, "2")); len(got) != 0 {
		t.Fatal("first scan has no baseline", got)
	}
	if got := complete("partial", file(a, "1")); len(got) != 0 {
		t.Fatal("partial walk reported unreached workflows as deleted", got)
	}
	if got := complete("ok", file(a, "1"), file(b, "2"), file(cw, "3")); len(got) != 0 {
		t.Fatal("paths a partial prior walk missed reported as added", got)
	}
	got := complete("ok", file(a, "9"))
	want := []string{a + ":added_or_modified", b + ":deleted", cw + ":deleted"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatal("complete walks must still report real changes", got)
	}

	// An import cannot run while a scan of the asset is running: 409, not 500.
	request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
	if _, _, err := s.Enqueue(ctx, request, uuid.New(), "tester", "running-scan"); err != nil {
		t.Fatal(err)
	}
	running, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	importRequest := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main", Commit: commit}}
	report := []byte(`{"SchemaVersion":2,"Results":[]}`)
	if _, _, err := s.Import(ctx, importRequest, uuid.New(), "ci", "import-busy", "trivy", false, report); !errors.Is(err, assessments.ErrBusy) {
		t.Fatal("import during a running scan", err)
	}
	if err := s.Cancel(ctx, running.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Import(ctx, importRequest, uuid.New(), "ci", "import-free", "trivy", false, report); err != nil {
		t.Fatal("import after the scan ended", err)
	}
}
