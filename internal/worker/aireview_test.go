package worker

import (
	"encoding/json"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
)

func TestNotesFromFindingsGroupsStaticAnalysisByFile(t *testing.T) {
	sast := func(severity, tool, rule, path string, line int, suppressed bool) assessments.Finding {
		evidence, _ := json.Marshal(map[string]any{"tool": tool, "rule_id": rule, "path": path, "start_line": line, "suppressed_in_code": suppressed})
		return assessments.Finding{Type: "sast", Severity: severity, Title: rule + " title", Evidence: evidence}
	}
	notes := notesFromFindings([]assessments.Finding{
		sast("low", "gosec", "G104", "svc/a.go", 40, false),
		sast("high", "gosec", "G201", "svc/a.go", 90, false),
		sast("high", "bearer", "x", "svc/a.go", 12, false),
		sast("medium", "gosec", "G101", "svc/b.go", 5, false),
		sast("high", "gosec", "G999", "svc/a.go", 1, true), // suppressed in code: left out
		{Type: "vulnerability", Severity: "critical", Evidence: json.RawMessage(`{"path":"svc/a.go","start_line":1}`)},
		{Type: "sast", Severity: "high", Evidence: json.RawMessage(`not json`)},
		{Type: "sast", Severity: "high", Evidence: json.RawMessage(`{"tool":"x","rule_id":"y"}`)}, // no path
	})
	if len(notes) != 2 || len(notes["svc/b.go"]) != 1 {
		t.Fatalf("grouping: %+v", notes)
	}
	a := notes["svc/a.go"]
	if len(a) != 3 || a[0].Severity != "high" || a[0].Line != 12 || a[1].Line != 90 || a[2].Severity != "low" {
		t.Fatalf("most severe first, then by line: %+v", a)
	}
	if notesFromFindings(nil) == nil || len(notesFromFindings(nil)) != 0 {
		t.Fatal("no findings, no notes")
	}
}

func TestNotesFromFindingsIncludesLintEntries(t *testing.T) {
	evidence, _ := json.Marshal(map[string]any{"tool": "ruff", "rule": "F401", "path": "app/main.py", "locations": []map[string]any{{"line": 1, "message": "os imported but unused"}, {"line": 4, "message": "sys imported but unused"}}})
	notes := notesFromFindings([]assessments.Finding{
		{Type: "qa_lint", Severity: "low", Evidence: evidence},
		{Type: "qa_lint", Severity: "low", Evidence: json.RawMessage(`not json`)},
		{Type: "qa_lint", Severity: "low", Evidence: json.RawMessage(`{"tool":"ruff","rule":"X"}`)}, // no path
	})
	got := notes["app/main.py"]
	if len(notes) != 1 || len(got) != 2 || got[0].Tool != "ruff" || got[0].Rule != "F401" || got[0].Line != 1 || got[1].Line != 4 || got[0].Title != "os imported but unused" {
		t.Fatalf("%+v", notes)
	}
}
