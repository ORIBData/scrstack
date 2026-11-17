package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/depsdev"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The optional package checks: typosquat names and recently published
// versions, each only when the policy asks, with a partial stage whenever a
// check could not cover every package.
func TestPostgresWorkerDependencyPolicy(t *testing.T) {
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
	store, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var lookups atomic.Int32
	failing := atomic.Bool{}
	published := map[string]string{
		"fresh-lib": time.Now().Add(-2 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"old-lib":   time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"crossenv":  time.Now().Add(-900 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"lodash":    time.Now().Add(-900 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // systems/npm/packages/{name}/versions/{v}
		if len(parts) != 6 || parts[0] != "systems" {
			w.WriteHeader(404)
			return
		}
		at, ok := published[parts[3]]
		if !ok {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"publishedAt": at})
	}))
	defer server.Close()
	w := Worker{Store: store, DepsDev: &depsdev.Client{BaseURL: server.URL, HTTP: server.Client()}}

	npm := func(name, version string) assessments.Component {
		return assessments.Component{Name: name, Version: version, Ecosystem: "npm", PURL: "pkg:npm/" + name + "@" + version, Path: "package-lock.json"}
	}
	components := []assessments.Component{npm("crossenv", "1.0.0"), npm("fresh-lib", "1.0.0"), npm("old-lib", "2.0.0"), npm("mystery", "1.0.0"), npm("lodash", "4.17.21")}
	run := func() (assessments.Stage, map[string]string) {
		t.Helper()
		output := scanner.Output{Components: append([]assessments.Component{}, components...)}
		stage := w.dependencyPolicy(ctx, &output)
		got := map[string]string{}
		for _, f := range output.Findings {
			if f.Type != "suspicious_dependency" || f.Severity != "medium" || !json.Valid(f.Evidence) || !json.Valid(f.Guidance) {
				t.Fatalf("malformed entry %+v", f)
			}
			got[f.Component.Name] = f.AdvisoryID
		}
		return stage, got
	}

	// Off by default: the stage is ok, nothing is flagged, nothing is looked up.
	stage, got := run()
	if stage.Name != "dependency_policy" || stage.Status != "ok" || len(got) != 0 || lookups.Load() != 0 {
		t.Fatalf("default policy: %+v %v lookups=%d", stage, got, lookups.Load())
	}

	policy, err := store.DependencyPolicy(ctx)
	if err != nil || policy.MinReleaseAgeDays != 0 || policy.Typosquat {
		t.Fatalf("default policy %+v %v", policy, err)
	}
	if _, err := store.SetDependencyPolicy(ctx, policy.Revision, 7, true, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	// Typosquat and release age together. "mystery" has no date at deps.dev and cannot be judged.
	stage, got = run()
	if stage.Status != "ok" || len(got) != 2 || got["crossenv"] != "SCRS-TYPOSQUAT" || got["fresh-lib"] != "SCRS-NEW-RELEASE" {
		t.Fatalf("flagged: %+v %v", stage, got)
	}
	first := lookups.Load()
	if first != 5 {
		t.Fatalf("expected one lookup per package version that deps.dev serves or refuses, got %d", first)
	}
	// Dates are cached, including "not known": a second scan asks nobody.
	if stage, got = run(); stage.Status != "ok" || len(got) != 2 || lookups.Load() != first {
		t.Fatalf("cache: %+v %v lookups=%d", stage, got, lookups.Load())
	}

	// Typosquat alone needs no network.
	stale, _ := store.DependencyPolicy(ctx)
	if _, err := store.SetDependencyPolicy(ctx, stale.Revision, 0, true, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if stage, got = run(); stage.Status != "ok" || len(got) != 1 || got["crossenv"] != "SCRS-TYPOSQUAT" {
		t.Fatalf("typosquat only: %+v %v", stage, got)
	}

	// A check that cannot cover every package is partial, so the next scan cannot close entries on its absence.
	stale, _ = store.DependencyPolicy(ctx)
	if _, err := store.SetDependencyPolicy(ctx, stale.Revision, 30, false, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	components = append(components, npm("brand-new", "9.9.9"))
	failing.Store(true)
	if stage, _ = run(); stage.Status != "partial" || !strings.Contains(stage.Detail, "not checked") {
		t.Fatalf("a failing deps.dev must make the stage partial: %+v", stage)
	}
	failing.Store(false)
	w.DepsDevMaxLookups = 0
	noClient := w
	noClient.DepsDev = nil
	output := scanner.Output{Components: components}
	if s := noClient.dependencyPolicy(ctx, &output); s.Status != "partial" || !strings.Contains(s.Detail, "deps.dev") {
		t.Fatalf("no deps.dev client: %+v", s)
	}
	// Policy bounds.
	current, _ := store.DependencyPolicy(ctx)
	if _, err := store.SetDependencyPolicy(ctx, current.Revision, 366, false, uuid.Nil); err != assessments.ErrInput {
		t.Fatalf("out of range: %v", err)
	}
	if _, err := store.SetDependencyPolicy(ctx, current.Revision+5, 1, false, uuid.Nil); err != assessments.ErrConflict {
		t.Fatalf("stale revision: %v", err)
	}
}
