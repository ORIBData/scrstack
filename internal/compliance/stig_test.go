package compliance

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestImportSTIG(t *testing.T) {
	raw, err := os.ReadFile("testdata/asd-sample-xccdf.xml")
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportSTIG(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := imported.Pack
	if p.ID != "stig-application-security-development-stig-v6" || p.Kind != KindSTIG || p.Version != "6" || p.Benchmark.Release != "Release: 3 Benchmark Date: 01 Jan 2026" || len(p.Categories) != 4 {
		t.Fatalf("pack %+v %+v", p, p.Benchmark)
	}
	sql := p.Categories[0]
	if sql.ID != "APSC-DV-002540" || sql.Severity != "CAT I" || sql.VulnID != "V-222607" || sql.RuleID != "SV-222607r961158_rule" || !containsInt(sql.CWEs, 89) || len(sql.CCIs) != 1 {
		t.Fatalf("SQL injection rule %+v", sql)
	}
	if p.Categories[3].Severity != "CAT III" || len(p.Categories[3].CWEs) != 0 {
		t.Fatalf("unmapped rule %+v", p.Categories[3])
	}
	// secret maps to the embedded-authentication rule; the patching rule is
	// missing from this benchmark, so vulnerability is not mapped.
	if p.TypeCategories["secret"] != "APSC-DV-003110" || p.TypeCategories["vulnerability"] != "" {
		t.Fatalf("types %+v", p.TypeCategories)
	}
	if imported.Mapped != 3 || !slices.Contains(imported.Unmatched, "APSC-DV-002630") || slices.Contains(imported.Unmatched, "APSC-DV-002540") {
		t.Fatalf("mapping %+v %+v", imported.Mapped, imported.Unmatched)
	}

	// An exported pack can be edited and uploaded again, and it matches
	// the published schema.
	body, _ := json.Marshal(p)
	if _, err := ParsePack(body); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
	_ = compiler.AddResource("pack.json", doc)
	schema, err := compiler.Compile("pack.json")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err := schema.Validate(instance); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(string(body), `"CAT I"`, `"high"`, 1),
		strings.Replace(string(body), `"benchmark":{`, `"benchmark":{"x":1,`, 1),
		strings.Replace(string(body), `"stig"`, `"cwe_mapping"`, 1),
	} {
		if _, err := ParsePack([]byte(bad)); err == nil {
			t.Errorf("accepted %.200s", bad)
		}
	}

	// DISA's zip distribution.
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	readme, _ := zw.Create("U_ASD_STIG_V6R3_Readme.txt")
	_, _ = readme.Write([]byte("readme"))
	entry, _ := zw.Create("U_ASD_STIG_V6R3_Manual_STIG/U_ASD_STIG_V6R3_Manual-xccdf.xml")
	_, _ = entry.Write(raw)
	_ = zw.Close()
	fromZip, err := ImportSTIG(zipped.Bytes())
	if err != nil || fromZip.Pack.ID != p.ID || len(fromZip.Pack.Categories) != 4 {
		t.Fatalf("zip %+v %v", fromZip.Pack.ID, err)
	}

	for name, upload := range map[string][]byte{
		"entity":   []byte(`<?xml version="1.0"?><!DOCTYPE b [<!ENTITY x SYSTEM "file:///etc/passwd">]><Benchmark id="b"><title>&x;</title></Benchmark>`),
		"no rules": []byte(`<Benchmark id="b"><title>T</title></Benchmark>`),
		"not xml":  []byte(`{"id":"b"}`),
		"empty zip": func() []byte {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			_ = w.Close()
			return b.Bytes()
		}(),
	} {
		if _, err := ImportSTIG(upload); !errors.Is(err, ErrSTIG) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSTIGReport(t *testing.T) {
	raw, _ := os.ReadFile("testdata/asd-sample-xccdf.xml")
	imported, _ := ImportSTIG(raw)
	until := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	asset := uuid.New()
	in := Input{ID: uuid.New(), Scope: Scope{Kind: "portfolio"}, Since: until.Add(-30 * 24 * time.Hour), Until: until, DataAsOf: until, Version: "1.0",
		Assets: []Asset{{ID: asset, Locator: "org/api"}},
		Findings: []Finding{
			{AssetID: asset, Type: "sast", Severity: "high", Status: "open", FirstSeen: until.Add(-time.Hour), CWEs: []int{89}},
			{AssetID: asset, Type: "sast", Severity: "high", Status: "fixed", FirstSeen: until.Add(-48 * time.Hour), ClosedAt: &until, CWEs: []int{79}},
		},
	}
	r := Build(imported.Pack, in)
	st := r.STIG
	if st == nil || st.Rules != 4 || st.RulesByEvidence["open_findings"] != 1 || st.RulesByEvidence["no_open_findings"] != 2 || st.RulesByEvidence["not_evidenced"] != 1 || st.OpenByCAT["CAT I"] != 1 {
		t.Fatalf("summary %+v", st)
	}
	for _, format := range Formats {
		data, err := Render(r, format)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(data))
		if format == "pdf" {
			text = strings.ToLower(pdfText(t, data))
		}
		// No checklist statuses and no compliance verdict (AT-30).
		for _, word := range []string{"not a finding", "notafinding", "compliant", "certified"} {
			if strings.Contains(text, word) {
				t.Fatalf("%s contains %q", format, word)
			}
		}
		if !strings.Contains(text, "apsc-dv-002540") {
			t.Fatalf("%s lacks the rule: %.300s", format, text)
		}
	}
}

func TestPDF(t *testing.T) {
	until := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	in := Input{ID: uuid.New(), Scope: Scope{Kind: "portfolio"}, Since: until.Add(-24 * time.Hour), Until: until, DataAsOf: until, Version: "1.0"}
	for i := 0; i < 150; i++ {
		in.Assets = append(in.Assets, Asset{ID: uuid.New(), Locator: "org/repo-" + strconv.Itoa(i) + "-with-a-long-name (and) back\\slash é ✓"})
	}
	owasp, _ := BuiltinPack("owasp-top10-2025")
	r := Build(owasp, in)
	first, err := Render(r, "pdf")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Render(r, "pdf")
	if !bytes.Equal(first, again) {
		t.Fatal("PDF output is not deterministic")
	}
	if !bytes.HasPrefix(first, []byte("%PDF-1.4\n")) || !bytes.HasSuffix(first, []byte("%%EOF\n")) {
		t.Fatal("PDF header or trailer")
	}
	// Every cross-reference offset points at its object.
	xref := regexp.MustCompile(`(?s)startxref\n(\d+)\n`).FindSubmatch(first)
	start, _ := strconv.Atoi(string(xref[1]))
	table := strings.Split(string(first[start:]), "\n")
	count, _ := strconv.Atoi(strings.Fields(table[1])[1])
	for i := 1; i < count; i++ {
		offset, _ := strconv.Atoi(strings.Fields(table[2+i])[0])
		if !bytes.HasPrefix(first[offset:], []byte(strconv.Itoa(i)+" 0 obj\n")) {
			t.Fatalf("object %d offset %d", i, offset)
		}
	}
	text := pdfText(t, first)
	pages := strings.Count(text, "Page ")
	if pages < 3 || !strings.Contains(text, "Page 1 of "+strconv.Itoa(pages)) {
		t.Fatalf("pages %d", pages)
	}
	if !strings.Contains(text, `\(and\)`) || !strings.Contains(text, `back\\slash`) || !strings.Contains(text, `\351`) {
		t.Fatal("text escaping")
	}
	if !strings.Contains(text, "repo-149") || !strings.Contains(text, Statement[:40]) {
		t.Fatal("content missing")
	}
}

// pdfText inflates every content stream.
func pdfText(t *testing.T, data []byte) string {
	t.Helper()
	var out strings.Builder
	streams := regexp.MustCompile(`(?s)/Length (\d+) /Filter /FlateDecode >>\nstream\n`)
	for _, m := range streams.FindAllSubmatchIndex(data, -1) {
		n, _ := strconv.Atoi(string(data[m[2]:m[3]]))
		z, err := zlib.NewReader(bytes.NewReader(data[m[1] : m[1]+n]))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(raw)
	}
	return out.String()
}
