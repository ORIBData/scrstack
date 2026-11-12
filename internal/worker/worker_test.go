package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type syntheticSource struct{}

func (syntheticSource) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return []connections.Resource{{Type: "github_repo", Locator: "org/repo"}}, nil
}
func (syntheticSource) GitHubSnapshot(_ context.Context, _ connections.Connection, _ json.RawMessage, _, _, _ string) ([]byte, string, bool, error) {
	return []byte("synthetic archive"), strings.Repeat("a", 40), false, nil
}

type artifactSink struct{ saved []byte }

func (s *artifactSink) PutSBOM(_ context.Context, b []byte) (string, string, error) {
	s.saved = append([]byte{}, b...)
	digest := assessments.Hash(b)
	return "sbom/" + digest + ".cdx.json", digest, nil
}
func (s *artifactSink) PutPlan(_ context.Context, b []byte) (string, string, error) {
	s.saved = append([]byte{}, b...)
	digest := assessments.Hash(b)
	return "remediation/" + digest + ".json", digest, nil
}
func TestPostgresWorkerPublishesAndRejectsRevokedScope(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: db, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic-secret-must-not-reach-scanner"}`), false); err != nil {
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
	actor := uuid.New()
	req := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
	if _, _, err := jobs.Enqueue(ctx, req, actor, "tester", "assessment"); err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != "synthetic archive" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("scanner boundary violated")
		}
		_ = json.NewEncoder(w).Encode(scanner.Output{Components: []assessments.Component{{Name: "pkg", Version: "1", Ecosystem: "npm", PURL: "pkg:npm/pkg@1", Path: "package-lock.json"}}, SBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), Stages: []assessments.Stage{{Name: "malware", Status: "skipped"}}})
	}))
	defer server.Close()
	sink := &artifactSink{}
	w := Worker{Store: jobs, Connections: providers, Source: syntheticSource{}, Artifacts: sink, ScannerURL: server.URL + "/scan", ScannerToken: token, Logger: slog.Default()}
	if err := w.run(ctx, &job); err != nil {
		t.Fatal(err)
	}
	result, err := jobs.Get(ctx, job.ID)
	if err != nil || result.Status != "succeeded" || result.Verdict != "incomplete" || result.Commit != strings.Repeat("a", 40) || len(sink.saved) == 0 {
		t.Fatal("worker result not persisted", result, err)
	}
	if _, _, err := jobs.Enqueue(ctx, req, actor, "tester", "revocation"); err != nil {
		t.Fatal(err)
	}
	revoked, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a scope/credential revision after admission; no scanner result may publish.
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".connections SET configuration_revision=configuration_revision+1 WHERE id=$1", revoked.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx, &revoked); err != assessments.ErrScope {
		t.Fatal("revoked configuration accepted", err)
	}
}
