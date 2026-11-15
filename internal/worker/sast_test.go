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
	counts := applyReachability(findings, r, [2]int{DefaultReachableWeight, DefaultNotReachableWeight})
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
	applyReachability(failed, &sast.Reachability{Status: "failed", Detail: "module download refused"}, [2]int{10, -15})
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
