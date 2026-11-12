package assessments

import (
	"slices"
	"testing"
)

func TestVerdictGate(t *testing.T) {
	malware := Finding{Fingerprint: "m", Type: "malware", Severity: "critical"}
	high := Finding{Fingerprint: "h", Type: "vulnerability", Severity: "high"}
	critical := Finding{Fingerprint: "c", Type: "vulnerability", Severity: "critical"}
	workflow := Finding{Fingerprint: "w", Type: "integrity", Severity: "high"}
	for _, tc := range []struct {
		name     string
		result   Result
		waived   map[string]bool
		expected string
	}{
		{"clean complete scan passes", Result{Complete: true}, nil, "pass"},
		{"partial clean scan is incomplete", Result{}, nil, "incomplete"},
		{"malware in partial scan still fails", Result{Findings: []Finding{malware}}, nil, "fail"},
		{"high in partial scan stays incomplete", Result{Findings: []Finding{high}}, nil, "incomplete"},
		{"high in complete scan warns", Result{Complete: true, Findings: []Finding{high}}, nil, "warn"},
		{"integrity entry fails by default", Result{Complete: true, Findings: []Finding{workflow}}, nil, "fail"},
		{"waived critical no longer gates", Result{Complete: true, Findings: []Finding{critical}}, map[string]bool{"c": true}, "pass"},
		{"waived malware never drops below warn", Result{Complete: true, Findings: []Finding{malware}}, map[string]bool{"m": true}, "warn"},
	} {
		if got, _ := verdict(tc.result, tc.waived); got != tc.expected {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.expected)
		}
	}
	_, counts := verdict(Result{Findings: []Finding{critical, high}}, map[string]bool{"c": true})
	if counts["total"] != 2 || counts["waived"] != 1 || counts["critical"] != 1 {
		t.Fatalf("unexpected counts %v", counts)
	}
}

func TestClosableTypesRequireProducingStages(t *testing.T) {
	stages := []Stage{{"resolve", "ok", ""}, {"fetch", "ok", ""}, {"inventory", "ok", ""}, {"sbom", "ok", ""}, {"match_vuln", "ok", ""}, {"match_malicious", "ok", ""}, {"malware", "partial", ""}, {"ioc", "skipped", ""}, {"integrity", "partial", ""}}
	got := closableTypes(stages)
	slices.Sort(got)
	if !slices.Equal(got, []string{"malicious_dependency", "vulnerability"}) {
		t.Fatalf("unexpected closable types %v", got)
	}
	stages[4].Status = "failed"
	if got := closableTypes(stages); slices.Contains(got, "vulnerability") {
		t.Fatal("failed matcher allowed vulnerability closure")
	}
	if got := closableTypes(stages[2:]); len(got) != 0 {
		t.Fatal("closure allowed without resolve and fetch")
	}
}
