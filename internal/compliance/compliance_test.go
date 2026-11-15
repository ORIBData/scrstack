package compliance

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestShippedPacks(t *testing.T) {
	want := map[string]int{"owasp-top10-2021": 10, "owasp-top10-2025": 10, "cwe-top25-2024": 25, "cwe-top25-2025": 25}
	for id, n := range want {
		p, ok := BuiltinPack(id)
		if !ok || len(p.Categories) != n || p.Source == "" || !p.Builtin {
			t.Fatalf("%s: %+v", id, p)
		}
	}
	owasp, _ := BuiltinPack("owasp-top10-2025")
	if owasp.Categories[2].ID != "A03:2025" || owasp.Categories[2].Name != "Software Supply Chain Failures" || owasp.TypeCategories["vulnerability"] != "A03:2025" {
		t.Fatalf("2025 pack %+v", owasp.Categories[2])
	}
	old, _ := BuiltinPack("owasp-top10-2021")
	injection := old.Categories[2]
	if injection.ID != "A03:2021" || !containsInt(injection.CWEs, 79) || !containsInt(injection.CWEs, 89) {
		t.Fatalf("A03:2021 %+v", injection)
	}
	top, _ := BuiltinPack("cwe-top25-2025")
	if top.Categories[0].CWEs[0] != 79 || !strings.HasPrefix(top.Categories[0].Name, "CWE-79 ") {
		t.Fatalf("Top 25 rank 1 %+v", top.Categories[0])
	}
	pci, _ := BuiltinPack("pci-dss-4.0.1")
	if pci.Kind != KindPCIDSS || len(pci.Requirements) != 3 {
		t.Fatalf("PCI %+v", pci)
	}
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestParsePack(t *testing.T) {
	good := `{"id":"acme-pack","name":"Acme","version":"1","kind":"cwe_mapping","categories":[{"id":"c1","name":"One","cwes":[79]}],"type_categories":{"secret":"c1"}}`
	if _, err := ParsePack([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, "acme-pack", "owasp-top10-2025", 1),
		strings.Replace(good, `"cwe_mapping"`, `"pci_dss"`, 1),
		strings.Replace(good, `"secret":"c1"`, `"secret":"c9"`, 1),
		strings.Replace(good, `[79]`, `[0]`, 1),
		strings.Replace(good, `"id":"acme-pack"`, `"id":"A B"`, 1),
		strings.Replace(good, `}],`, `}],"extra":1,`, 1),
	} {
		if _, err := ParsePack([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	compiler := jsonschema.NewCompiler()
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
	_ = compiler.AddResource("pack.json", doc)
	schema, err := compiler.Compile("pack.json")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(good))
	if err := schema.Validate(instance); err != nil {
		t.Fatal(err)
	}
}

func TestBuildOWASPAndPCI(t *testing.T) {
	until := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	since := until.Add(-28 * 24 * time.Hour)
	fresh, stale := until.Add(-24*time.Hour), until.Add(-60*24*time.Hour)
	a1, a2, a3 := uuid.New(), uuid.New(), uuid.New()
	closed := until.Add(-3 * 24 * time.Hour)
	in := Input{ID: uuid.New(), Scope: Scope{Kind: "portfolio"}, Since: since, Until: until, DataAsOf: until, Version: "1.0", Format: "json",
		Assets: []Asset{{ID: a1, Locator: "org/api", LastSBOM: &fresh, SBOMs: 3}, {ID: a2, Locator: "org/old", LastSBOM: &stale}, {ID: a3, Locator: "org/none"}},
		Findings: []Finding{
			{AssetID: a1, Type: "code", Severity: "high", Status: "open", FirstSeen: since.Add(48 * time.Hour), CWEs: []int{79}},
			{AssetID: a1, Type: "vulnerability", Severity: "critical", Status: "open", FirstSeen: until.Add(-45 * 24 * time.Hour), CWEs: []int{89}, KEV: true},
			{AssetID: a1, Type: "vulnerability", Severity: "high", Status: "fixed", FirstSeen: since.Add(24 * time.Hour), ClosedAt: &closed},
			{AssetID: a2, Type: "code", Severity: "low", Status: "open", FirstSeen: since, CWEs: []int{99999}},
			{AssetID: a2, Type: "code", Severity: "low", Status: "open", FirstSeen: since},
			{AssetID: a2, Type: "license", Severity: "medium", Status: "open", FirstSeen: since},
			{AssetID: a2, Type: "code", Severity: "low", Status: "false_positive", FirstSeen: since, CWEs: []int{79}},
		},
	}
	owasp, _ := BuiltinPack("owasp-top10-2021")
	r := Build(owasp, in)
	cat := map[string]CategoryResult{}
	for _, c := range r.Categories {
		cat[c.ID] = c
	}
	// The SQL injection CVE counts under A03 by CWE and A06 by type.
	if a03 := cat["A03:2021"]; a03.Open != 2 || a03.MappedByCWE != 2 || a03.BySeverity["critical"] != 1 || a03.Opened != 1 {
		t.Fatalf("A03 %+v", a03)
	}
	if a06 := cat["A06:2021"]; a06.Open != 1 || a06.MappedByType != 2 || a06.Closed != 1 {
		t.Fatalf("A06 %+v", a06)
	}
	if r.Unmapped.NoCWE != 1 || r.Unmapped.OutsidePack != 1 || r.Unmapped.TopOutside[0].CWE != 99999 {
		t.Fatalf("unmapped %+v", r.Unmapped)
	}
	if r.Totals.Considered != 5 || r.Totals.Dismissed != 1 || r.Totals.Excluded["license"] != 1 {
		t.Fatalf("totals %+v", r.Totals)
	}
	if len(r.Gaps) != 2 || r.Gaps[0].Locator != "org/old" || r.Gaps[1].Reason != "no SBOM recorded" {
		t.Fatalf("gaps %+v", r.Gaps)
	}
	if len(cat["A03:2021"].Trend) < 4 || r.Statement != Statement {
		t.Fatal("trend weeks or statement")
	}
	pci, _ := BuiltinPack("pci-dss-4.0.1")
	p := Build(pci, in)
	metrics := map[string]map[string]any{}
	for _, req := range p.Requirements {
		metrics[req.ID] = req.Metrics
	}
	if metrics["6.3.1"]["open_known_exploited"] != 1 || metrics["6.3.2"]["gaps"] != 2 || metrics["6.3.2"]["assets_with_sbom_in_window"] != 1 {
		t.Fatalf("6.3.1/6.3.2 %+v", metrics)
	}
	bySeverity := metrics["6.3.3"]["by_severity"].(map[string]map[string]int)
	if bySeverity["critical"]["open_overdue"] != 1 || bySeverity["high"]["fixed_within_window"] != 1 {
		t.Fatalf("6.3.3 %+v", bySeverity)
	}
	for _, format := range Formats {
		data, err := Render(r, format)
		if err != nil || len(data) == 0 || bytes.Contains(bytes.ToLower(data), []byte(`"verdict"`)) {
			t.Fatalf("%s: %v", format, err)
		}
		if format == "csv" {
			if _, err := csv.NewReader(bytes.NewReader(data)).ReadAll(); err != nil {
				t.Fatal(err)
			}
		}
	}
	md, _ := Render(p, "md")
	if !bytes.Contains(md, []byte("## Requirement 6.3.3")) || !bytes.Contains(md, []byte("org/none")) {
		t.Fatalf("markdown %s", md)
	}
}
