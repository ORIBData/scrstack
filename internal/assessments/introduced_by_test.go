package assessments_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A dependency that is new since the previous scan of the ref names who
// brought it on the entries about it (MAL-004); the first scan, and a
// baseline whose inventory was empty, name nobody; a later scan keeps the
// first tag.
func TestPostgresIntroducedByTagsNewDependencies(t *testing.T) {
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

	lodash := assessments.Component{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.20", Path: "package-lock.json"}
	evil := assessments.Component{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/evil-pkg@1.0.0", Path: "package-lock.json"}
	entry := func(kind, advisory string, component assessments.Component) assessments.Finding {
		return assessments.Finding{Type: kind, AdvisoryID: advisory, Title: advisory, Severity: "high", Score: 60, Component: component, Evidence: json.RawMessage(`{"source":"test"}`), Guidance: json.RawMessage(`{}`)}
	}
	run := 0
	scan := func(actor string, components []assessments.Component, findings ...assessments.Finding) map[string]json.RawMessage {
		t.Helper()
		run++
		request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
		request.Trigger.Actor, request.Trigger.Origin = actor, "github_push"
		if _, _, err := s.Enqueue(ctx, request, uuid.New(), "tester", "intro-"+string(rune('a'+run))); err != nil {
			t.Fatal(err)
		}
		a, err := s.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}}
		if err := s.Complete(ctx, a, assessments.Result{Commit: strings.Repeat(string(rune('a'+run)), 40), Stages: stages, Components: components, Findings: findings}); err != nil {
			t.Fatal(err)
		}
		// Read the register, which holds the entry's live evidence.
		items, err := s.FindingsFiltered(ctx, assessments.RegisterFilter{}, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]json.RawMessage{}
		for _, f := range items {
			var evidence struct {
				IntroducedBy json.RawMessage `json:"introduced_by"`
			}
			_ = json.Unmarshal(f.Evidence, &evidence)
			out[f.AdvisoryID] = evidence.IntroducedBy
		}
		return out
	}

	// No baseline, then a baseline with no components: nothing is attributed.
	if got := scan("alice", nil); len(got) != 0 {
		t.Fatalf("unexpected entries %v", got)
	}
	if got := scan("alice", []assessments.Component{lodash}, entry("vulnerability", "CVE-1", lodash)); len(got["CVE-1"]) != 0 {
		t.Fatalf("a baseline with no components must name nobody: %s", got["CVE-1"])
	}
	// A new package carries the claimed actor and the revision; the old one stays untagged.
	got := scan("mallory", []assessments.Component{lodash, evil}, entry("vulnerability", "CVE-1", lodash), entry("malicious_dependency", "MAL-1", evil), entry("integrity", "SCRS-OTHER", assessments.Component{Path: "x"}))
	var tag struct {
		Actor, Origin, Commit, Ref string
		Claimed                    bool
	}
	if err := json.Unmarshal(got["MAL-1"], &tag); err != nil || tag.Actor != "mallory" || tag.Origin != "github_push" || tag.Ref != "main" || len(tag.Commit) != 40 || !tag.Claimed {
		t.Fatalf("introduced_by: %s %v", got["MAL-1"], err)
	}
	if len(got["CVE-1"]) != 0 || len(got["SCRS-OTHER"]) != 0 {
		t.Fatalf("only entries about new dependencies are tagged: %v", got)
	}
	// The next scan repeats the entry under another actor: the first tag stays.
	again := scan("carol", []assessments.Component{lodash, evil}, entry("malicious_dependency", "MAL-1", evil))
	var kept struct{ Actor string }
	if err := json.Unmarshal(again["MAL-1"], &kept); err != nil || kept.Actor != "mallory" {
		t.Fatalf("the tag must survive a repeated detection: %s %v", again["MAL-1"], err)
	}
}
