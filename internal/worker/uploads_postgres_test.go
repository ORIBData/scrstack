package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type uploadObjects map[string][]byte

func (u uploadObjects) GetUpload(_ context.Context, key string) ([]byte, error) {
	if b, ok := u[key]; ok {
		return b, nil
	}
	return nil, errors.New("missing object")
}

// failingSource proves an upload assessment never asks a git host for source.
type failingSource struct{ t *testing.T }

func (f failingSource) Snapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error) {
	f.t.Error("an upload assessment fetched source from a provider")
	return nil, "", false, errors.New("unexpected fetch")
}

// An uploaded archive goes to the scanner as it was stored, under the commit
// its SHA-256 names, without touching a provider.
func TestPostgresWorkerAssessesUploadedArchive(t *testing.T) {
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	actor := uuid.New()
	asset, created, err := providers.UploadAsset(ctx, "vendor-drop", actor)
	if err != nil || !created || asset.Type != "uploaded" {
		t.Fatalf("upload asset: %+v %v", asset, err)
	}
	again, created, err := providers.UploadAsset(ctx, "vendor-drop", actor)
	if err != nil || created || again.ID != asset.ID {
		t.Fatalf("a second call must return the same asset: %+v %v", again, err)
	}
	archive := []byte("synthetic gzip archive bytes")
	sum := sha256.Sum256(archive)
	digest := hex.EncodeToString(sum[:])
	key := "uploads/" + digest + ".tar.gz"
	record, _, err := jobs.RecordUpload(ctx, assessments.Upload{AssetID: asset.ID, SHA256: digest, Size: int64(len(archive)), ObjectKey: key}, "tester")
	if err != nil || record.Commit != digest[:40] {
		t.Fatalf("record: %+v %v", record, err)
	}
	request := assessments.Request{Target: assessments.Target{Type: "upload", Repository: "upload/vendor-drop", Commit: record.Commit}}
	if _, _, err := jobs.Enqueue(ctx, request, actor, "tester", "upload-assessment"); err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 40)
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(scanner.Output{Components: []assessments.Component{{Name: "pkg", Version: "1", Ecosystem: "npm", PURL: "pkg:npm/pkg@1", Path: "package-lock.json"}}, Stages: []assessments.Stage{{Name: "inventory", Status: "ok"}, {Name: "malware", Status: "skipped"}}})
	}))
	defer server.Close()
	w := Worker{Store: jobs, Connections: providers, Source: failingSource{t}, Uploads: uploadObjects{key: archive}, Artifacts: &artifactSink{}, ScannerURL: server.URL + "/scan", ScannerToken: token, Logger: slog.Default()}
	if err := w.run(ctx, &job); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, archive) {
		t.Fatalf("the scanner received %q", received)
	}
	result, err := jobs.Get(ctx, job.ID)
	if err != nil || result.Status != "succeeded" || result.Commit != record.Commit {
		t.Fatalf("result not persisted under the upload's commit: %+v %v", result, err)
	}

	// A worker without an upload store fails the job rather than fetching anything.
	if _, _, err := jobs.Enqueue(ctx, request, actor, "tester", "upload-assessment-2"); err != nil {
		t.Fatal(err)
	}
	next, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.Uploads = nil
	if err := w.run(ctx, &next); err == nil {
		t.Fatal("a worker with no upload store must not assess an upload")
	}
	// An archive the database does not know is out of scope, not an error to retry.
	w.Uploads = uploadObjects{}
	unknown := next
	unknown.Request.Target.Commit = strings.Repeat("0", 40)
	if err := w.run(ctx, &unknown); !errors.Is(err, assessments.ErrScope) {
		t.Fatalf("an unknown revision answered %v", err)
	}
}
