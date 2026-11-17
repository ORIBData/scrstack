package compliance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// AI-written summaries are an optional, labelled section: they appear in
// JSON, Markdown and PDF when asked for, change nothing else, and leave a
// report that did not ask for them byte-for-byte as it was.
func TestReportAISummaries(t *testing.T) {
	until := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	asset := uuid.New()
	base := Input{ID: uuid.New(), Scope: Scope{Kind: "portfolio"}, Since: until.Add(-28 * 24 * time.Hour), Until: until, DataAsOf: until, Version: "1.0", Format: "json",
		Assets:   []Asset{{ID: asset, Locator: "org/api", SBOMs: 1}},
		Findings: []Finding{{AssetID: asset, Type: "vulnerability", Severity: "high", Status: "open", FirstSeen: until.Add(-48 * time.Hour)}},
	}
	pack, _ := BuiltinPack("owasp-top10-2021")
	plain := Build(pack, base)
	if plain.AISummaryNotice != "" || plain.AISummaries != nil {
		t.Fatalf("a report that did not ask has AI sections: %+v", plain.AISummaries)
	}
	for _, format := range []string{"json", "md", "pdf"} {
		data, _ := Render(plain, format)
		if bytes.Contains(data, []byte("AI-written")) || bytes.Contains(data, []byte("ai_summar")) {
			t.Fatalf("%s mentions AI summaries without being asked", format)
		}
	}

	asked := base
	asked.Params.IncludeAISummaries = true
	asked.AISummaries = []AISummary{{AssetID: asset, Locator: "org/api", Ref: "main", Model: "qwen2.5", CreatedAt: until.Add(-time.Hour), Headline: "One high finding", Text: "One high vulnerability is open.\nUpgrade lodash to 4.17.21.\n\nIt is not known to be exploited."}}
	with := Build(pack, asked)
	if with.AISummaryNotice != AINotice || len(with.AISummaries) != 1 {
		t.Fatalf("summaries missing: %+v", with)
	}
	if with.Totals.Considered != plain.Totals.Considered || with.Totals.Open != plain.Totals.Open || len(with.Gaps) != len(plain.Gaps) || len(with.Categories) != len(plain.Categories) {
		t.Fatal("AI summaries must change no count, mapping or gap")
	}
	js, _ := Render(with, "json")
	var doc struct {
		Notice    string `json:"ai_summary_notice"`
		Summaries []struct {
			Locator, Model, Text string
		} `json:"ai_summaries"`
	}
	if err := json.Unmarshal(js, &doc); err != nil || doc.Notice != AINotice || len(doc.Summaries) != 1 || doc.Summaries[0].Locator != "org/api" {
		t.Fatalf("json: %v %s", err, js)
	}
	md, _ := Render(with, "md")
	for _, want := range []string{"## AI-written summaries (unverified)", "unverified", "### org/api", "qwen2.5", "Upgrade lodash to 4.17.21."} {
		if !strings.Contains(string(md), want) {
			t.Fatalf("markdown lacks %q:\n%s", want, md)
		}
	}
	pdf, err := Render(with, "pdf")
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) || bytes.Equal(pdf, mustRender(t, plain, "pdf")) {
		t.Fatalf("pdf: %v", err)
	}
	if again, _ := Render(with, "pdf"); !bytes.Equal(again, pdf) {
		t.Fatal("the same report must produce the same PDF bytes")
	}
	// Asked, but nothing to show: the notice and an explicit empty list.
	empty := base
	empty.Params.IncludeAISummaries = true
	r := Build(pack, empty)
	if md, _ := Render(r, "md"); !strings.Contains(string(md), "No asset in scope has an AI summary yet.") {
		t.Fatal("an empty section must say so")
	}
	// CSV keeps its table shape.
	csvData, _ := Render(with, "csv")
	if bytes.Contains(csvData, []byte("AI-written")) {
		t.Fatal("CSV is a table of counts and carries no AI text")
	}
}

func mustRender(t *testing.T, r Report, format string) []byte {
	t.Helper()
	data, err := Render(r, format)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
