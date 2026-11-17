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
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// labelRegistry is a registry that reports a source label with the image.
type labelRegistry struct {
	mu     sync.Mutex
	digest string
	label  string
}

func (r *labelRegistry) set(label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.label = label
}

func (r *labelRegistry) ImageArchiveInfo(_ context.Context, _ connections.Connection, _ json.RawMessage, _, _, _, _ string, _ int64, w io.Writer) (connections.ImageInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := io.WriteString(w, "synthetic image archive")
	return connections.ImageInfo{Digest: r.digest, SourceLabel: r.label}, err
}

func (r *labelRegistry) ImageArchive(ctx context.Context, c connections.Connection, s json.RawMessage, l, t, d, p string, limit int64, w io.Writer) (string, error) {
	info, err := r.ImageArchiveInfo(ctx, c, s, l, t, d, p, limit, w)
	return info.Digest, err
}

type repoInventory struct{}

func (repoInventory) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return []connections.Resource{{Type: "github_repo", Locator: "org/app"}}, nil
}

// An assessed image is linked to the repository its source label names, and
// the link follows the label without touching a link made by hand.
func TestPostgresWorkerLinksImageToItsSourceLabel(t *testing.T) {
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	hub := connections.Connection{Name: "hub", Provider: "dockerhub", Config: json.RawMessage(`{"namespace":"library","identifier":"bot"}`), Scope: connections.Scope{Include: []string{"docker.io/library/*"}}}
	gh := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	for _, c := range []connections.Connection{hub, gh} {
		if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := providers.Discover(ctx, "hub", imageInventory{}); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, "gh", repoInventory{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = json.NewEncoder(w).Encode(scanner.Output{Components: []assessments.Component{{Name: "busybox", Version: "1", Ecosystem: "Alpine:v3.19", PURL: "pkg:apk/alpine/busybox@1", Path: "lib/apk/db/installed"}}, Stages: []assessments.Stage{{Name: "inventory", Status: "ok"}}})
	}))
	defer server.Close()
	registry := &labelRegistry{digest: "sha256:" + strings.Repeat("d", 64)}
	w := Worker{Store: jobs, Connections: providers, Images: registry, Artifacts: &artifactSink{}, ScannerURL: server.URL + "/scan", ScannerToken: strings.Repeat("x", 40), Logger: slog.Default()}
	var imageID, repoID uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM "+schema+".assets WHERE type='container_image'").Scan(&imageID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT id FROM "+schema+".assets WHERE type='github_repo'").Scan(&repoID); err != nil {
		t.Fatal(err)
	}
	run := 0
	assess := func(label string) {
		t.Helper()
		run++
		registry.set(label)
		request := assessments.Request{Target: assessments.Target{Type: "image", Repository: "docker.io/library/app", Ref: "1.0"}}
		if _, _, err := jobs.Enqueue(ctx, request, uuid.New(), "tester", "image-link-"+string(rune('a'+run))); err != nil {
			t.Fatal(err)
		}
		job, err := jobs.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.run(ctx, &job); err != nil {
			t.Fatal(err)
		}
	}
	links := func() map[string]string {
		list, err := jobs.AssetLinks(ctx, imageID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, l := range list {
			if l.Direction != "out" || l.Kind != "built_from" {
				t.Fatalf("unexpected link %+v", l)
			}
			out[l.Asset.Locator] = l.Source
		}
		return out
	}

	assess("https://github.com/org/app")
	if got := links(); len(got) != 1 || got["org/app"] != "oci_label" {
		t.Fatalf("label link: %v", got)
	}
	// The repository lists the image it produced.
	back, err := jobs.AssetLinks(ctx, repoID)
	if err != nil || len(back) != 1 || back[0].Direction != "in" || back[0].Asset.Locator != "docker.io/library/app" {
		t.Fatalf("repository side: %+v %v", back, err)
	}
	// A label that names nothing known removes the label link.
	assess("https://github.com/org/unknown")
	if got := links(); len(got) != 0 {
		t.Fatalf("stale label link kept: %v", got)
	}
	// A link made by hand survives any label, including none.
	if _, _, err := jobs.AddLink(ctx, imageID, repoID, assessments.LinkSourceManual, uuid.New()); err != nil {
		t.Fatal(err)
	}
	assess("")
	assess("https://github.com/org/unknown")
	if got := links(); len(got) != 1 || got["org/app"] != "manual" {
		t.Fatalf("manual link: %v", got)
	}
	// The same repository by label does not turn a manual link into a label link.
	assess("git@github.com:org/app.git")
	if got := links(); got["org/app"] != "manual" {
		t.Fatalf("manual source lost: %v", got)
	}
}
