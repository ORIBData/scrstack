package assessments

import (
	"strings"
	"testing"
)

func TestParseTrivyReport(t *testing.T) {
	report := `{"SchemaVersion":2,"Trivy":{"Version":"0.58.1"},"Results":[{"Target":"package-lock.json","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"lodash","InstalledVersion":"4.17.0","FixedVersion":"4.17.21","Severity":"CRITICAL","Title":"Prototype pollution","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.0"}}]},{"Target":"Dockerfile","Type":"dockerfile","Misconfigurations":[{"ID":"DS002","Title":"Root user","Severity":"HIGH","Status":"FAIL","Resolution":"Add USER"},{"ID":"DS001","Title":"ok","Severity":"LOW","Status":"PASS"}]},{"Target":".env","Secrets":[{"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key","StartLine":3,"Match":"AKIAIOSFODNN7EXAMPLE"}]}]}`
	src, components, findings, err := ParseReport("trivy", []byte(report))
	if err != nil || src.Tool != "trivy" || src.ToolVersion != "0.58.1" || len(components) != 1 || len(findings) != 3 {
		t.Fatal(src, components, findings, err)
	}
	kinds := map[string]Finding{}
	for _, f := range findings {
		kinds[f.Type] = f
		if strings.Contains(string(f.Evidence), "AKIA") || strings.Contains(string(f.Guidance), "AKIA") {
			t.Fatal("secret value copied into the register")
		}
	}
	if v := kinds["vulnerability"]; v.Severity != "critical" || v.Score != 60 || v.Component.PURL != "pkg:npm/lodash@4.17.0" {
		t.Fatal("vulnerability mapping", v)
	}
	if kinds["misconfiguration"].AdvisoryID != "DS002" || kinds["secret"].Component.Path != ".env:3" {
		t.Fatal("misconfiguration or secret mapping", kinds)
	}
	if _, _, _, err := ParseReport("trivy", []byte(`{"SchemaVersion":1}`)); err == nil {
		t.Fatal("old Trivy schema accepted")
	}
}

func TestParseSARIFReport(t *testing.T) {
	report := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","semanticVersion":"1.90.0","rules":[{"id":"sql-injection","shortDescription":{"text":"SQL injection"},"properties":{"security-severity":"9.1"}}]}},"results":[{"ruleId":"sql-injection","level":"error","message":{"text":"tainted query"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.go"},"region":{"startLine":42}}}]},{"ruleId":"style","level":"note","message":{"text":"nit"}}]}]}`
	src, _, findings, err := ParseReport("sarif", []byte(report))
	if err != nil || src.Tool != "semgrep" || len(findings) != 2 {
		t.Fatal(src, findings, err)
	}
	if f := findings[0]; f.Type != "code" || f.Severity != "critical" || f.Component.Path != "src/db.go:42" || f.Title != "SQL injection" {
		t.Fatal("security-severity mapping", f)
	}
	if findings[1].Severity != "low" {
		t.Fatal("level fallback", findings[1])
	}
	for _, bad := range []string{`{"version":"2.0.0","runs":[{}]}`, `not json`} {
		if _, _, _, err := ParseReport("sarif", []byte(bad)); err == nil {
			t.Fatal("invalid SARIF accepted", bad)
		}
	}
	if _, _, _, err := ParseReport("csv", nil); err == nil {
		t.Fatal("unknown format accepted")
	}
}
