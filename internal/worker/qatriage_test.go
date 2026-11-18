package worker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/summarize"
)

func evidenceOf(t *testing.T, v map[string]any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestQAFacts(t *testing.T) {
	failure := assessments.Finding{Type: "qa_failure", Evidence: evidenceOf(t, map[string]any{"suite": "repo", "feature": "users.feature", "scenario": "get user", "line": 7, "tags": []string{"@smoke"}, "error": "status code was: 500, expected: 200", "request_body": "SECRET-BODY"})}
	text := strings.Join(qaFacts(failure), "\n")
	for _, want := range []string{"repo/users.feature line 7", "scenario: get user", "@smoke", "status code was: 500"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, "SECRET-BODY") {
		t.Fatal("a field outside the allowlist reached the facts")
	}
	lint := assessments.Finding{Type: "qa_lint", Evidence: evidenceOf(t, map[string]any{"tool": "ruff", "rule": "F401", "path": "a.py", "count": 3, "fixable": true, "locations": []map[string]any{{"line": 1, "message": "os unused"}}})}
	text = strings.Join(qaFacts(lint), "\n")
	if !strings.Contains(text, "ruff, rule: F401, file: a.py, occurrences: 3, auto-fixable: true") || !strings.Contains(text, "line 1: os unused") {
		t.Fatal(text)
	}
	perf := assessments.Finding{Type: "qa_performance", Evidence: evidenceOf(t, map[string]any{"assertion": map[string]any{"description": "p95 < 500ms", "passed": false, "actual": 812.0}, "stats": map[string]any{"requests": 1000, "ko": 12, "p95_ms": 812.0, "throughput_rps": 41.5}})}
	text = strings.Join(qaFacts(perf), "\n")
	if !strings.Contains(text, "p95 < 500ms (measured 812.0)") || !strings.Contains(text, "failed: 12") {
		t.Fatal(text)
	}
	if got := qaFacts(assessments.Finding{Type: "qa_untested", Evidence: json.RawMessage(`not json`)}); got != nil {
		t.Fatal("unreadable evidence produced facts", got)
	}
}

func TestQATypesAreSeparatedByRunKind(t *testing.T) {
	if !qaTypesOf(qa.KindLint)["qa_lint"] || qaTypesOf(qa.KindLint)["qa_failure"] {
		t.Fatal("lint run types")
	}
	if !qaTypesOf(qa.KindFunctional)["qa_failure"] || qaTypesOf(qa.KindFunctional)["qa_lint"] || qaTypesOf(qa.KindFunctional)["qa_performance"] {
		t.Fatal("functional run types")
	}
	if !qaTypesOf(qa.KindPerformance)["qa_performance"] || qaTypesOf(qa.KindPerformance)["qa_failure"] {
		t.Fatal("performance run types")
	}
	// None of them is on the findings allowlist: QA triage is a separate path.
	for kind := range summarize.QATypes {
		if summarize.Allowed(kind) {
			t.Fatalf("%s is on the hosted-safe allowlist", kind)
		}
	}
}
