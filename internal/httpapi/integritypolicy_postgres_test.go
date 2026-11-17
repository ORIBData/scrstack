package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// Behavioural author signals through the webhook (INT-003), switched on by
// the integrity policy: a first push only builds a baseline, a new author and
// a pusher who is not the author raise entries, routine merges do not, and
// everything is recorded even while a signal is off.
func TestPostgresIntegrityPolicyAndAuthorSignals(t *testing.T) {
	h := newHarness(t)
	gh := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := h.store.Put(h.ctx, gh, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Discover(h.ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}}); err != nil {
		t.Fatal(err)
	}

	// The policy: admin only, revisioned, bounded, and off by default.
	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	var policy struct {
		Revision      int64 `json:"revision"`
		AuthorNewDays int   `json:"author_new_days"`
		OffHours      bool  `json:"off_hours"`
		PusherDiffers bool  `json:"pusher_differs"`
	}
	w := h.expect(h.call("GET", "/policies/integrity", read, nil, ""), 200)
	if err := json.Unmarshal(w.Body.Bytes(), &policy); err != nil || policy.Revision != 1 || policy.AuthorNewDays != 0 || policy.OffHours || policy.PusherDiffers || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("default policy: %s", w.Body.String())
	}
	put := func(token, ifMatch, body string) int {
		r := httptest.NewRequest("PUT", BasePath+"/policies/integrity", strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		if ifMatch != "" {
			r.Header.Set("If-Match", ifMatch)
		}
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := put(write, `"1"`, `{"author_new_days":30}`); code != 403 {
		t.Fatalf("write scope changed the policy: %d", code)
	}
	if code := put(h.admin, "", `{"author_new_days":30}`); code != 428 {
		t.Fatalf("missing If-Match: %d", code)
	}
	if code := put(h.admin, `"1"`, `{"author_new_days":4000}`); code != 400 {
		t.Fatalf("out of range days: %d", code)
	}
	if code := put(h.admin, `"1"`, `{"large_file_bytes":-1}`); code != 400 {
		t.Fatalf("negative size: %d", code)
	}
	if code := put(h.admin, `"1"`, `{"nonsense":true}`); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}

	commit := func(id, message, login, email, committer string) string {
		return fmt.Sprintf(`{"id":%q,"message":%q,"timestamp":"2026-11-17T10:00:00Z","added":[],"removed":[],"modified":[],"author":{"name":%q,"email":%q,"username":%q},"committer":{"username":%q}}`, id, message, login, email, login, committer)
	}
	recorded := 0 // integrity events recorded so far
	push := func(pusher string, commits ...string) int {
		body := `{"ref":"refs/heads/main","before":"` + strings.Repeat("1", 40) + `","after":"` + strings.Repeat(string(rune('a'+len(commits)+int(pusher[0])%5)), 40) + `","repository":{"full_name":"org/api","default_branch":"main"},"pusher":{"name":"` + pusher + `"},"commits":[` + strings.Join(commits, ",") + `]}`
		mac := hmac.New(sha256.New, []byte(h.webhookSecret))
		_, _ = mac.Write([]byte(body))
		r := httptest.NewRequest("POST", BasePath+"/ingest/github", strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-GitHub-Event", "push")
		r.Header.Set("X-GitHub-Delivery", uuid.NewString())
		r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, r)
		if rec.Code != 202 && rec.Code != 200 {
			t.Fatalf("push: %d %s", rec.Code, rec.Body.String())
		}
		var total int
		if err := h.pool.QueryRow(h.ctx, "SELECT count(*) FROM "+h.schema+".integrity_events").Scan(&total); err != nil {
			t.Fatal(err)
		}
		raised := total - recorded
		recorded = total
		return raised
	}
	authors := func() int {
		var n int
		if err := h.pool.QueryRow(h.ctx, "SELECT count(*) FROM "+h.schema+".integrity_authors").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	kinds := func() string {
		rows, err := h.pool.Query(h.ctx, "SELECT kind FROM "+h.schema+".integrity_events ORDER BY kind")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var k string
			_ = rows.Scan(&k)
			out = append(out, k)
		}
		return strings.Join(out, ",")
	}

	// With the policy off, authors are still recorded and nothing is raised.
	if n := push("alice", commit(strings.Repeat("a", 40), "first", "alice", "alice@example.com", "alice")); n != 0 || authors() != 1 {
		t.Fatalf("baseline push: signals=%d authors=%d", n, authors())
	}
	if n := push("alice", commit(strings.Repeat("b", 40), "mine", "bob", "bob@example.com", "bob")); n != 0 || authors() != 2 {
		t.Fatalf("a signal off must raise nothing: signals=%d authors=%d", n, authors())
	}

	// Turn on new-author and pusher-differs checks.
	if code := put(h.admin, `"1"`, `{"author_new_days":30,"pusher_differs":true}`); code != 200 {
		t.Fatalf("enable: %d", code)
	}
	if code := put(h.admin, `"1"`, `{"author_new_days":30}`); code != 409 {
		t.Fatalf("stale revision: %d", code)
	}
	// A known author pushing for themselves: nothing. A new author: author_new, and since mallory
	// was pushed by alice, pusher_differs too.
	if n := push("alice", commit(strings.Repeat("c", 40), "again", "alice", "alice@example.com", "alice")); n != 0 {
		t.Fatalf("a known author raised %d signals", n)
	}
	if n := push("alice", commit(strings.Repeat("d", 40), "from mallory", "mallory", "m@example.com", "mallory")); n != 2 {
		t.Fatalf("new author pushed by someone else: %d signals, kinds %s", n, kinds())
	}
	// A web merge made by GitHub for a pull request is routine.
	if n := push("alice", commit(strings.Repeat("e", 40), "Merge pull request #1 from x/y", "bob", "bob@example.com", "web-flow")); n != 0 {
		t.Fatalf("a routine merge raised %d signals", n)
	}
	if got := kinds(); got != "author_new,pusher_differs_from_author" {
		t.Fatalf("recorded kinds: %s", got)
	}
	// The entries are in the register as integrity entries, naming the claimed pusher.
	register := h.expect(h.call("GET", "/register?type=integrity", read, nil, ""), 200).Body.String()
	if !strings.Contains(register, "SCRS-EVENT-AUTHOR-NEW") || !strings.Contains(register, "SCRS-EVENT-PUSHER-DIFFERS-FROM-AUTHOR") {
		t.Fatalf("register: %s", register)
	}
	var detailAuthors string
	if err := h.pool.QueryRow(h.ctx, "SELECT details->'details'->>'authors' FROM "+h.schema+".integrity_events WHERE kind='author_new'").Scan(&detailAuthors); err != nil || detailAuthors != `["mallory"]` {
		t.Fatalf("author_new authors: %q %v", detailAuthors, err)
	}
}
