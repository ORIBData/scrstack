package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/actionscheck"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// fakeActions answers GitHub Actions reads from a table the test edits.
type fakeActions struct {
	mu       sync.Mutex
	readings map[string]connections.ActionsInfo
	failing  map[string]bool
	calls    []string
}

func (f *fakeActions) GitHubActions(_ context.Context, _ connections.Connection, _ json.RawMessage, repository string) (connections.ActionsInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, repository)
	if f.failing[repository] {
		return connections.ActionsInfo{}, errors.New("provider returned HTTP 502")
	}
	return f.readings[repository], nil
}

func (f *fakeActions) set(repository string, info connections.ActionsInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readings[repository] = info
}

func workflow(path string, missing ...int) connections.ActionsWorkflow {
	return connections.ActionsWorkflow{ID: int64(len(path)), Name: path, Path: path, State: "active", Runs: 10, MinRun: 1, MaxRun: 12, Missing: missing, MissingCount: len(missing)}
}

// The Actions inventory (INT-014, INT-015): what a check stores, what it
// raises, that a repeated reading raises nothing new, and how a missing
// permission or an outage reads.
func TestPostgresActionsInventory(t *testing.T) {
	api := &fakeActions{readings: map[string]connections.ActionsInfo{}, failing: map[string]bool{}}
	h := newHarnessWith(t, func(s *Security) { s.ActionsAPI = api })
	gh := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := h.store.Put(h.ctx, gh, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Discover(h.ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}, {Type: "github_repo", Locator: "org/web"}}); err != nil {
		t.Fatal(err)
	}
	var apiID, webID uuid.UUID
	for repo, dst := range map[string]*uuid.UUID{"org/api": &apiID, "org/web": &webID} {
		if err := h.pool.QueryRow(h.ctx, "SELECT id FROM "+h.schema+".assets WHERE locator=$1", repo).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	path := func(id uuid.UUID, rest string) string { return "/assets/" + id.String() + rest }
	check := func(id uuid.UUID, status int) assessments.ActionsState {
		t.Helper()
		var st assessments.ActionsState
		w := h.expect(h.call("POST", path(id, "/actions:check"), write, nil, ""), status)
		if status == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
				t.Fatal(err)
			}
		}
		return st
	}
	events := func() []string {
		rows, err := h.pool.Query(h.ctx, "SELECT kind||':'||severity FROM "+h.schema+".integrity_events WHERE kind IN ('run_number_gap','actions_workflows_changed') ORDER BY created_at,kind")
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
		return out
	}
	flag := func() bool {
		var unused *bool
		if err := h.pool.QueryRow(h.ctx, "SELECT (flags->>'actions_unused')::boolean FROM "+h.schema+".assets WHERE id=$1", apiID).Scan(&unused); err != nil {
			t.Fatal(err)
		}
		return unused != nil && *unused
	}

	// Nothing is known until a check has run; read scope cannot run one.
	h.expect(h.call("GET", path(apiID, "/actions"), read, nil, ""), 404)
	h.expect(h.call("POST", path(apiID, "/actions:check"), read, nil, ""), 403)
	h.expect(h.call("POST", path(uuid.New(), "/actions:check"), write, nil, ""), 404)
	h.expect(h.call("GET", "/assets/nope/actions", read, nil, ""), 404)

	// A clean first reading: stored, no entries, Actions in use.
	api.set("org/api", connections.ActionsInfo{Available: true, Enabled: true, Workflows: []connections.ActionsWorkflow{workflow(".github/workflows/ci.yml")}})
	st := check(apiID, 200)
	if !st.Available || !st.Enabled || len(st.Workflows) != 1 || st.CheckedAt.IsZero() || len(events()) != 0 || flag() {
		t.Fatalf("first reading: %+v events=%v unused=%v", st, events(), flag())
	}
	var got assessments.ActionsState
	if err := json.Unmarshal(h.expect(h.call("GET", path(apiID, "/actions"), read, nil, ""), 200).Body.Bytes(), &got); err != nil || len(got.Workflows) != 1 {
		t.Fatalf("read back: %+v %v", got, err)
	}

	// A new workflow is reported once, however often it is read again.
	api.set("org/api", connections.ActionsInfo{Available: true, Enabled: true, Workflows: []connections.ActionsWorkflow{workflow(".github/workflows/ci.yml"), workflow(".github/workflows/release.yml")}})
	check(apiID, 200)
	check(apiID, 200)
	if got := events(); strings.Join(got, ",") != "actions_workflows_changed:low" {
		t.Fatalf("workflow list change: %v", got)
	}

	// Holes in run numbers: medium, and not raised again for the same holes.
	api.set("org/api", connections.ActionsInfo{Available: true, Enabled: true, Workflows: []connections.ActionsWorkflow{workflow(".github/workflows/ci.yml", 5, 6), workflow(".github/workflows/release.yml")}})
	check(apiID, 200)
	check(apiID, 200)
	if got := events(); strings.Join(got, ",") != "actions_workflows_changed:low,run_number_gap:medium" {
		t.Fatalf("first gap: %v", got)
	}
	register := h.expect(h.call("GET", "/register?type=integrity", read, nil, ""), 200).Body.String()
	if !strings.Contains(register, "SCRS-EVENT-RUN-NUMBER-GAP") || !strings.Contains(register, "SCRS-EVENT-ACTIONS-WORKFLOWS-CHANGED") {
		t.Fatalf("register: %s", register)
	}
	// Combined with another recent integrity entry for the asset, a new hole is high.
	if _, err := h.jobs.RecordIntegrity(h.ctx, "d-force", uuid.New(), []byte(`{"repository":{"full_name":"org/api"}}`), "direct", "push", []assessments.IntegrityEvent{{Kind: "force_push", Severity: "high", Title: "Force push", Repository: "org/api", Ref: "refs/heads/main", Actor: "mallory"}}); err != nil {
		t.Fatal(err)
	}
	api.set("org/api", connections.ActionsInfo{Available: true, Enabled: true, Workflows: []connections.ActionsWorkflow{workflow(".github/workflows/ci.yml", 5, 6, 7), workflow(".github/workflows/release.yml")}})
	check(apiID, 200)
	if got := events(); !strings.HasSuffix(strings.Join(got, ","), "run_number_gap:medium,run_number_gap:high") {
		t.Fatalf("combined gap: %v", got)
	}

	// A permission the credential lacks is a reading; the last inventory stays visible.
	api.set("org/api", connections.ActionsInfo{Available: false, Reason: "GitHub answered HTTP 403: the credential needs the read-only Actions permission on this repository"})
	st = check(apiID, 200)
	if st.Available || !strings.Contains(st.Reason, "Actions permission") || len(st.Workflows) != 2 {
		t.Fatalf("missing permission: %+v", st)
	}
	// An outage is a 502, noted on the state, and leaves the last good reading.
	api.failing["org/api"] = true
	h.expect(h.call("POST", path(apiID, "/actions:check"), write, nil, ""), 502)
	if err := json.Unmarshal(h.expect(h.call("GET", path(apiID, "/actions"), read, nil, ""), 200).Body.Bytes(), &got); err != nil || !strings.Contains(got.Error, "502") || len(got.Workflows) != 2 {
		t.Fatalf("outage state: %+v %v", got, err)
	}
	api.failing["org/api"] = false
	// Actions switched off, or no workflows: the asset is flagged actions_unused.
	api.set("org/api", connections.ActionsInfo{Available: true, Enabled: false, Workflows: []connections.ActionsWorkflow{}})
	if st = check(apiID, 200); st.Enabled || !flag() {
		t.Fatalf("disabled: %+v unused=%v", st, flag())
	}
	api.set("org/api", connections.ActionsInfo{Available: true, Enabled: true, Workflows: []connections.ActionsWorkflow{workflow(".github/workflows/ci.yml")}})
	if check(apiID, 200); flag() {
		t.Fatal("actions_unused must clear when workflows return")
	}

	// Only GitHub repositories qualify.
	uploaded, _ := h.upload("not-a-repo", "x")
	check(uploaded, 409)

	// The sweep checks only what is missing or stale, and survives a failing repository.
	api.set("org/web", connections.ActionsInfo{Available: true, Enabled: true, Workflows: []connections.ActionsWorkflow{workflow(".github/workflows/web.yml")}})
	api.calls = nil
	checker := actionscheck.Checker{Connections: h.store, Store: h.jobs, API: api}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if n := checker.Sweep(h.ctx, time.Hour, 10, 0, logger); n != 1 || len(api.calls) != 1 || api.calls[0] != "org/web" {
		t.Fatalf("sweep checked %d: %v", n, api.calls)
	}
	if n := checker.Sweep(h.ctx, time.Hour, 10, 0, logger); n != 0 {
		t.Fatalf("a second sweep inside the interval checked %d", n)
	}
	if _, err := h.pool.Exec(h.ctx, "UPDATE "+h.schema+".asset_actions SET checked_at=now()-interval '2 hours'"); err != nil {
		t.Fatal(err)
	}
	api.failing["org/api"] = true
	api.calls = nil
	if n := checker.Sweep(h.ctx, time.Hour, 10, 0, logger); n != 2 || len(api.calls) != 2 {
		t.Fatalf("sweep with a failing repository checked %d: %v", n, api.calls)
	}
	if n := checker.Sweep(h.ctx, time.Hour, 10, 0, logger); n != 0 {
		t.Fatalf("a failed check must not be retried on the next pass: %d", n)
	}
}
