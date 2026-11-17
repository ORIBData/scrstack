package worker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/sast"
)

// AT-29 at the register boundary: Go entries take the govulncheck verdict,
// other ecosystems are unsupported, a failed analysis is unknown (never
// not_reachable), scores move by the weights and KEV entries stay high.
func TestApplyReachability(t *testing.T) {
	vuln := func(eco, name, id string, score int, guidance string) assessments.Finding {
		return assessments.Finding{Type: "vulnerability", AdvisoryID: id, Score: score, Component: assessments.Component{Name: name, Ecosystem: eco}, Evidence: json.RawMessage(`{"id":"` + id + `"}`), Guidance: json.RawMessage(guidance)}
	}
	findings := []assessments.Finding{
		vuln("Go", "golang.org/x/text", "GO-2022-1059", 45, `{}`),
		vuln("Go", "example.com/lib", "GHSA-xxxx", 45, `{"aliases":["GO-2026-0001"]}`),
		vuln("Go", "example.com/lib", "GO-2026-0002", 50, `{"kev":true}`),
		vuln("Go", "example.com/other", "GO-2026-0003", 25, `{}`),
		vuln("PyPI", "requests", "GHSA-yyyy", 25, `{}`),
		vuln("Go", "stdlib", "GO-2026-0004", 25, `{}`),
		{Type: "sast", Score: 45, Evidence: json.RawMessage(`{}`)},
	}
	r := &sast.Reachability{Tool: "govulncheck", Version: "v1.9.0", Status: "ok", Verdicts: []sast.Verdict{
		{Advisory: "GO-2022-1059", Module: "golang.org/x/text", Status: sast.Reachable, Method: "call_graph", Trace: []sast.Step{{Path: "main.go", Line: 10}}},
		{Advisory: "GO-2026-0001", Module: "example.com/lib", Status: sast.ImportedOnly, Method: "import_graph"},
		{Advisory: "GO-2026-0002", Module: "example.com/lib", Status: sast.NotReachable, Method: "call_graph"},
	}}
	counts := applyReachability(findings, r, nil, [2]int{DefaultReachableWeight, DefaultNotReachableWeight})
	read := func(f assessments.Finding) map[string]any {
		var e map[string]any
		_ = json.Unmarshal(f.Evidence, &e)
		out, _ := e["reachability"].(map[string]any)
		return out
	}
	want := []struct {
		status string
		score  int
	}{{sast.Reachable, 55}, {sast.ImportedOnly, 45}, {sast.NotReachable, 45}, {sast.Unknown, 25}, {sast.Unsupported, 25}, {sast.Unknown, 25}}
	for i, w := range want {
		got := read(findings[i])
		if got["status"] != w.status || findings[i].Score != w.score {
			t.Errorf("finding %d: %v score %d, want %s %d", i, got, findings[i].Score, w.status, w.score)
		}
	}
	if trace, _ := read(findings[0])["trace"].([]any); len(trace) != 1 {
		t.Fatalf("trace not kept: %v", read(findings[0]))
	}
	if read(findings[0])["id"] != nil || !strings.Contains(string(findings[0].Evidence), `"id":"GO-2022-1059"`) {
		t.Fatal("original evidence lost")
	}
	if read(findings[6]) != nil {
		t.Fatal("non-vulnerability entry given reachability")
	}
	if counts[sast.Reachable] != 1 || counts[sast.Unsupported] != 1 || counts[sast.Unknown] != 2 {
		t.Fatalf("counts %v", counts)
	}
	failed := []assessments.Finding{vuln("Go", "golang.org/x/text", "GO-2022-1059", 45, `{}`)}
	applyReachability(failed, &sast.Reachability{Status: "failed", Detail: "module download refused"}, nil, [2]int{10, -15})
	if read(failed[0])["status"] != sast.Unknown || failed[0].Score != 45 {
		t.Fatalf("failed analysis: %v", read(failed[0]))
	}
}

func TestSASTFindingAndStage(t *testing.T) {
	f := sastFinding(sast.Finding{Tool: "gosec", ToolVersion: "2.30.0", RuleID: "G701", Title: "SQL injection", Severity: "high", CWE: []string{"CWE-89"}, Path: "svc/db.go", StartLine: 13, EndLine: 13, CodeHash: strings.Repeat("a", 64), SuppressedInCode: true, Suppression: "#nosec G701"})
	var e map[string]any
	_ = json.Unmarshal(f.Evidence, &e)
	if f.Type != "sast" || f.AdvisoryID != "gosec:G701" || f.Component.Path != "svc/db.go#aaaaaaaaaaaaaaaa" || f.Score != 45 || e["suppressed_in_code"] != true || e["code"] != nil {
		t.Fatalf("finding %+v %v", f, e)
	}
	stage := sastStage(sast.Response{Runs: []sast.Run{{Analyzer: "gosec", Version: "2.30.0", Status: "ok", Findings: 3}, {Analyzer: "bandit", Status: "skipped", Detail: "no files in its languages"}, {Analyzer: "bearer", Status: "skipped", Detail: "time budget of 10m0s exceeded"}}, Unsupported: []string{"dart"}}, 3)
	if stage.Status != "partial" || !strings.Contains(stage.Detail, "bearer") || strings.Contains(stage.Detail, "bandit") || !strings.Contains(stage.Detail, "dart") {
		t.Fatalf("stage %+v", stage)
	}
	if s := sastStage(sast.Response{Runs: []sast.Run{{Analyzer: "gosec", Status: "failed"}}}, 0); s.Status != "failed" {
		t.Fatalf("failed stage %+v", s)
	}
}

// REA-005: npm and PyPI entries are imported_only when the repository's own
// source imports the package, and unknown otherwise, never not_reachable.
func TestApplyReachabilityImportLevel(t *testing.T) {
	vuln := func(eco, name string) assessments.Finding {
		return assessments.Finding{Type: "vulnerability", AdvisoryID: "GHSA-test", Score: 40, Component: assessments.Component{Name: name, Ecosystem: eco}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)}
	}
	imports := &sast.Imports{Tool: "scrs-imports", Version: "1", Status: "ok", Files: 2,
		NPM:  map[string][]sast.Step{"lodash": {{Path: "src/a.js", Line: 3}}},
		PyPI: map[string][]sast.Step{"bs4": {{Path: "app.py", Line: 1}}}}
	findings := []assessments.Finding{vuln("npm", "lodash"), vuln("npm", "express"), vuln("PyPI", "beautifulsoup4"), vuln("PyPI", "requests"), vuln("Maven", "org.x:y")}
	counts := applyReachability(findings, &sast.Reachability{Status: "skipped", Detail: "no Go modules"}, imports, [2]int{10, -15})
	read := func(f assessments.Finding) map[string]any {
		var e map[string]any
		_ = json.Unmarshal(f.Evidence, &e)
		out, _ := e["reachability"].(map[string]any)
		return out
	}
	for i, want := range []string{sast.ImportedOnly, sast.Unknown, sast.ImportedOnly, sast.Unknown, sast.Unsupported} {
		if got := read(findings[i])["status"]; got != want {
			t.Errorf("finding %d: %v, want %s", i, got, want)
		}
		if findings[i].Score != 40 {
			t.Errorf("finding %d: imported_only and unknown must not move the score: %d", i, findings[i].Score)
		}
	}
	if got := read(findings[0]); got["method"] != "import_graph" || got["tool"] != "scrs-imports" || got["confidence"] != "medium" {
		t.Fatalf("imported entry: %v", got)
	}
	if trace, _ := read(findings[0])["trace"].([]any); len(trace) != 1 {
		t.Fatalf("trace: %v", read(findings[0]))
	}
	if d, _ := read(findings[1])["detail"].(string); !strings.Contains(d, "another dependency") {
		t.Fatalf("an unknown entry explains itself: %v", read(findings[1]))
	}
	if counts[sast.ImportedOnly] != 2 || counts[sast.Unknown] != 2 || counts[sast.Unsupported] != 1 {
		t.Fatalf("counts %v", counts)
	}
	// Without a usable import scan the entries stay unsupported, as before.
	for _, none := range []*sast.Imports{nil, {Status: "skipped"}} {
		again := []assessments.Finding{vuln("npm", "lodash")}
		applyReachability(again, &sast.Reachability{Status: "skipped"}, none, [2]int{10, -15})
		if got := read(again[0])["status"]; got != sast.Unsupported {
			t.Fatalf("no import data: %v", got)
		}
	}
}
