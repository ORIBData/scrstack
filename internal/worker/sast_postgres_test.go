package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/ORIBData/scrstack/internal/sast"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// M9 through the worker and PostgreSQL with a fake scrs-sast service: SAST
// entries gate only when new, an inline suppression added for an open
// entry raises an integrity entry (AT-27), entries close when a complete
// run no longer reports them, a failed analyzer leaves the assessment
// incomplete, settings select analyzers and reachability, and Go
// vulnerability entries carry reachability (AT-29).
func TestPostgresSASTAndReachabilityPipeline(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
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

	// The scanner reports one Go and one PyPI vulnerability.
	output := scanner.Output{
		Components: []assessments.Component{{Name: "golang.org/x/text", Version: "v0.3.7", Ecosystem: "Go", PURL: "pkg:golang/golang.org/x/text@v0.3.7", Path: "go.mod"}, {Name: "requests", Version: "2.0.0", Ecosystem: "PyPI", PURL: "pkg:pypi/requests@2.0.0", Path: "requirements.txt"}},
		Findings: []assessments.Finding{
			{Type: "vulnerability", AdvisoryID: "GO-2022-1059", Title: "x/text DoS", Severity: "high", Score: 45, Component: assessments.Component{Name: "golang.org/x/text", Version: "v0.3.7", Ecosystem: "Go", PURL: "pkg:golang/golang.org/x/text@v0.3.7", Path: "go.mod"}, Evidence: json.RawMessage(`{"id":"GO-2022-1059"}`), Guidance: json.RawMessage(`{}`)},
			{Type: "vulnerability", AdvisoryID: "GHSA-requests", Title: "requests", Severity: "medium", Score: 25, Component: assessments.Component{Name: "requests", Version: "2.0.0", Ecosystem: "PyPI", PURL: "pkg:pypi/requests@2.0.0", Path: "requirements.txt"}, Evidence: json.RawMessage(`{"id":"GHSA-requests"}`), Guidance: json.RawMessage(`{}`)},
		},
	}
	for _, n := range []string{"inventory", "match_vuln", "match_malicious", "malware", "yara", "ioc", "integrity"} {
		output.Stages = append(output.Stages, assessments.Stage{Name: n, Status: "ok"})
	}
	scan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(output) }))
	defer scan.Close()

	// The fake scrs-sast service: what it returns is set per round.
	var mu sync.Mutex
	var requests []sast.Request
	sqli := sast.Finding{Tool: "gosec", ToolVersion: "2.30.0", RuleID: "G701", Title: "SQL injection", Severity: "high", CWE: []string{"CWE-89"}, Path: "svc/db.go", StartLine: 13, EndLine: 13, CodeHash: strings.Repeat("a", 64)}
	weak := sast.Finding{Tool: "bandit", ToolVersion: "1.9.4", RuleID: "B303", Title: "MD5", Severity: "medium", CWE: []string{"CWE-327"}, Path: "app/hash.py", StartLine: 4, EndLine: 4, CodeHash: strings.Repeat("b", 64)}
	respond := sast.Response{Runs: []sast.Run{{Analyzer: "gosec", Version: "2.30.0", Status: "ok", Findings: 2}}, Findings: []sast.Finding{sqli, weak}, Reachability: &sast.Reachability{Tool: "govulncheck", Version: "v1.9.0", Status: "ok", Modules: []string{"."}, Verdicts: []sast.Verdict{{Advisory: "GO-2022-1059", Module: "golang.org/x/text", Status: sast.Reachable, Method: "call_graph", Trace: []sast.Step{{Path: "main.go", Line: 10}}}}}}
	token := strings.Repeat("t", 40)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.URL.Path != "/analyze" {
			http.Error(w, "unexpected", 400)
			return
		}
		reader, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "multipart", 400)
			return
		}
		var req sast.Request
		archive := false
		for {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			switch part.FormName() {
			case "request":
				_ = json.NewDecoder(part).Decode(&req)
			case "archive":
				archive = true
			}
		}
		if !archive {
			http.Error(w, "archive", 400)
			return
		}
		mu.Lock()
		requests = append(requests, req)
		resp := respond
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer service.Close()
	sink := &artifactSink{}
	w := Worker{Store: jobs, Connections: providers, Source: syntheticSource{}, Artifacts: sink, ScannerURL: scan.URL + "/scan", ScannerToken: strings.Repeat("s", 40), Logger: slog.Default(), SAST: sast.NewClient(service.URL, token), SASTDefaults: assessments.SASTDefaults{Enabled: true, Reachability: true}}
	run := func(label string) assessments.Assessment {
		t.Helper()
		if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}, uuid.New(), "tester", label); err != nil {
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
	register := func(a assessments.Assessment) map[string]assessments.Finding {
		items, err := jobs.Findings(ctx, a.ID, uuid.Nil, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]assessments.Finding{}
		for _, f := range items {
			out[f.AdvisoryID] = f
		}
		return out
	}

	// Round 1: two new SAST entries; the new high warns.
	first := run("sast-1")
	entries := register(first)
	if first.Verdict != "warn" || entries["gosec:G701"].Type != "sast" || entries["gosec:G701"].Change != "new" || !strings.HasPrefix(entries["gosec:G701"].Component.Path, "svc/db.go#") {
		t.Fatalf("round 1 %s %+v", first.Verdict, entries)
	}
	var reach struct {
		Reachability struct {
			Status string `json:"status"`
			Trace  []any  `json:"trace"`
		} `json:"reachability"`
	}
	_ = json.Unmarshal(entries["GO-2022-1059"].Evidence, &reach)
	var pyReach struct {
		Reachability struct{ Status string } `json:"reachability"`
	}
	_ = json.Unmarshal(entries["GHSA-requests"].Evidence, &pyReach)
	if reach.Reachability.Status != "reachable" || len(reach.Reachability.Trace) != 1 || entries["GO-2022-1059"].Score != 55 || pyReach.Reachability.Status != "unsupported" {
		t.Fatalf("reachability %+v %+v score %d", reach, pyReach, entries["GO-2022-1059"].Score)
	}
	stages := map[string]assessments.Stage{}
	for _, s := range first.Stages {
		stages[s.Name] = s
	}
	if stages["sast"].Status != "ok" || stages["reachability"].Status != "ok" || !strings.Contains(stages["reachability"].Detail, "reachable 1") {
		t.Fatalf("stages %+v", stages)
	}

	// Round 2: the same code (same hash) is existing and no longer gates the
	// SAST verdict; a #nosec added to the open G701 entry raises integrity.
	mu.Lock()
	silenced := sqli
	silenced.SuppressedInCode, silenced.Suppression = true, "#nosec G701"
	respond.Findings = []sast.Finding{silenced, weak}
	mu.Unlock()
	second := run("sast-2")
	entries = register(second)
	if entries["gosec:G701"].Change != "existing" || entries["SCRS-SAST-SUPPRESSION-ADDED"].Type != "integrity" || second.Counts["suppressed_in_code"] != 1 {
		t.Fatalf("round 2 %s %v %+v", second.Verdict, second.Counts, entries)
	}
	// The new medium integrity entry warns.
	if second.Verdict != "warn" {
		t.Fatalf("round 2 verdict %s", second.Verdict)
	}

	// Round 3: B303 is fixed; a complete run closes it. The suppression
	// signal stays open until someone reviews it.
	mu.Lock()
	respond.Findings = []sast.Finding{silenced}
	mu.Unlock()
	third := run("sast-3")
	var weakStatus, signalStatus string
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE advisory_id='bandit:B303'`).Scan(&weakStatus)
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE advisory_id='SCRS-SAST-SUPPRESSION-ADDED'`).Scan(&signalStatus)
	if weakStatus != "fixed" || signalStatus != "open" {
		t.Fatalf("closure: B303 %s, signal %s (verdict %s)", weakStatus, signalStatus, third.Verdict)
	}

	// Round 4: an analyzer failure leaves the assessment incomplete and
	// closes nothing.
	mu.Lock()
	respond.Runs = []sast.Run{{Analyzer: "gosec", Version: "2.30.0", Status: "failed", Detail: "gosec failed"}}
	respond.Findings = nil
	mu.Unlock()
	fourth := run("sast-4")
	var sqliStatus string
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE advisory_id='gosec:G701'`).Scan(&sqliStatus)
	if fourth.Verdict != "incomplete" || sqliStatus != "open" {
		t.Fatalf("failed analyzer: verdict %s, G701 %s", fourth.Verdict, sqliStatus)
	}

	// Settings: the asset turns SAST off (reachability only) and excludes a
	// path; deployment-wide disabled rules and enabled rulesets are sent.
	if _, err := jobs.SetGlobalSASTSettings(ctx, assessments.GlobalSAST{DisabledRules: []string{"gosec:G104"}, Excludes: []string{"docs/**"}}, 0, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.SaveSASTRuleset(ctx, "no-eval", "team rule", "rules: []\n", true, uuid.New()); err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := jobs.SetAssetSASTSettings(ctx, first.AssetID, assessments.AssetSAST{Enabled: &off, Excludes: []string{"testdata/**"}}, 0, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.SetAssetSASTSettings(ctx, first.AssetID, assessments.AssetSAST{Enabled: &off}, 0, uuid.New()); err != assessments.ErrConflict {
		t.Fatalf("stale revision accepted: %v", err)
	}
	if _, err := jobs.SetAssetSASTSettings(ctx, first.AssetID, assessments.AssetSAST{Analyzers: []string{"semgrep"}}, 1, uuid.New()); err != assessments.ErrInput {
		t.Fatalf("unknown analyzer accepted: %v", err)
	}
	mu.Lock()
	respond.Runs = nil
	mu.Unlock()
	fifth := run("sast-5")
	mu.Lock()
	last := requests[len(requests)-1]
	mu.Unlock()
	if len(last.Analyzers) != 1 || last.Analyzers[0] != "none" || !last.Reachability || len(last.CustomRules) != 0 || strings.Join(last.Excludes, ",") != "docs/**,testdata/**" || last.DisabledRules[0] != "gosec:G104" {
		t.Fatalf("request %+v", last)
	}
	for _, s := range fifth.Stages {
		if s.Name == "sast" {
			t.Fatal("SAST stage recorded with SAST off")
		}
	}
	var audits int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action IN ('sast_settings.updated','sast_ruleset.saved','asset.sast_settings_updated')`).Scan(&audits)
	if audits != 3 {
		t.Fatalf("audit records %d", audits)
	}
}
