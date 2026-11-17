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

// Author history drives the quiet-days and off-hours signals, and a
// first-time author's push makes a large new file high instead of medium.
func TestPostgresAuthorHistoryAndSizeSignals(t *testing.T) {
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

	policy, err := s.IntegrityPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetIntegrityPolicy(ctx, policy.Revision, assessments.IntegrityPolicy{AuthorNewDays: 30, OffHours: true, LargeFileBytes: 1 << 20, CIGrowthBytes: 10000}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	at := func(hour int) time.Time { return time.Date(2026, 11, 17, hour, 0, 0, 0, time.UTC) }
	observe := func(commit string, hour int, authors ...string) []string {
		t.Helper()
		var commits []assessments.AuthoredCommit
		for _, a := range authors {
			commits = append(commits, assessments.AuthoredCommit{Author: a, Login: a, At: at(hour)})
		}
		events, err := s.ObservePush(ctx, assessments.PushObservation{Repository: "Org/Repo", Ref: "refs/heads/main", Commit: commit, Pusher: authors[0], Commits: commits})
		if err != nil {
			t.Fatal(err)
		}
		var kinds []string
		for _, e := range events {
			kinds = append(kinds, e.Kind+":"+e.Severity)
		}
		return kinds
	}

	// The first push of a repository is a baseline: nobody is "new" yet.
	if got := observe(strings.Repeat("1", 40), 10, "alice"); len(got) != 0 {
		t.Fatalf("baseline raised %v", got)
	}
	// Alice builds history at ten o'clock; a push at three in the night is unusual only after enough history.
	for i := 0; i < assessments.MinHistoryPushes-2; i++ {
		observe(strings.Repeat("2", 40), 10, "alice")
	}
	if got := observe(strings.Repeat("3", 40), 3, "alice"); len(got) != 0 {
		t.Fatalf("too little history for an hour to be unusual: %v", got)
	}
	observe(strings.Repeat("4", 40), 10, "alice")
	if got := observe(strings.Repeat("5", 40), 3, "alice"); len(got) != 1 || got[0] != "author_off_hours:low" {
		t.Fatalf("off hours: %v", got)
	}
	if got := observe(strings.Repeat("6", 40), 10, "alice"); len(got) != 0 {
		t.Fatalf("the usual hour: %v", got)
	}
	// A new author is flagged; one returning after the quiet period is flagged too, on the same author key.
	if got := observe(strings.Repeat("7", 40), 10, "dave"); len(got) != 1 || got[0] != "author_new:medium" {
		t.Fatalf("new author: %v", got)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".integrity_authors SET last_seen_at=now()-interval '45 days' WHERE author='dave'"); err != nil {
		t.Fatal(err)
	}
	if got := observe(strings.Repeat("8", 40), 10, "dave"); len(got) != 1 || got[0] != "author_new:medium" {
		t.Fatalf("returning author: %v", got)
	}
	if got := observe(strings.Repeat("9", 40), 10, "dave"); len(got) != 0 {
		t.Fatalf("seen yesterday: %v", got)
	}
	// Case does not make a second author, and a default-branch push by a new author is high.
	if got := observe(strings.Repeat("a", 40), 10, "Alice"); len(got) != 0 {
		t.Fatalf("author keys must ignore case: %v", got)
	}
	events, err := s.ObservePush(ctx, assessments.PushObservation{Repository: "org/repo", Ref: "refs/heads/main", Commit: strings.Repeat("b", 40), Pusher: "erin", DefaultBranch: true, Commits: []assessments.AuthoredCommit{{Author: "erin", Login: "erin", At: at(10)}}})
	if err != nil || len(events) != 1 || events[0].Severity != "high" {
		t.Fatalf("new author on the default branch: %v %v", events, err)
	}

	// Scans: the push by a first-time author leaves its head as first_push_commit,
	// so a large new file in that revision is high; an old author's is medium.
	run := 0
	scan := func(actor, commit string, files ...assessments.FileEvidence) map[string]string {
		t.Helper()
		run++
		request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
		request.Trigger.Actor = actor
		if _, _, err := s.Enqueue(ctx, request, uuid.New(), "tester", "size-"+string(rune('a'+run))); err != nil {
			t.Fatal(err)
		}
		a, err := s.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "integrity", Status: "ok"}}
		if err := s.Complete(ctx, a, assessments.Result{Commit: commit, Files: files, Stages: stages}); err != nil {
			t.Fatal(err)
		}
		found, err := s.Findings(ctx, a.ID, uuid.Nil, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range found {
			out[f.AdvisoryID] = f.Severity
		}
		return out
	}
	file := func(path string, size int64) assessments.FileEvidence {
		return assessments.FileEvidence{Path: path, SHA256: strings.Repeat("1", 64), Size: size, Malware: "clean"}
	}
	if got := scan("alice", strings.Repeat("c", 40), file("Makefile", 1000), file("main.go", 100)); len(got) != 0 {
		t.Fatalf("first scan has no baseline: %v", got)
	}
	got := scan("alice", strings.Repeat("d", 40), file("Makefile", 50000), file("main.go", 100), file("data.bin", 3<<20))
	if got["SCRS-LARGE-NEW-FILE"] != "medium" || got["SCRS-CI-FILE-GROWTH"] != "medium" {
		t.Fatalf("an established author: %v", got)
	}
	// erin's first push left head b…b, so a scan of that commit is a first-time author's push.
	got = scan("erin", strings.Repeat("b", 40), file("Makefile", 50000), file("main.go", 100), file("data.bin", 3<<20), file("more.bin", 4<<20))
	if got["SCRS-LARGE-NEW-FILE"] != "high" {
		t.Fatalf("a first-time author: %v", got)
	}
}
