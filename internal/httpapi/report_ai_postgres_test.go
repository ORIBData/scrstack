package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/knowledge"
)

// A report asked to include AI summaries carries the newest summary of each
// asset in scope, and only that; the older summary it replaced is not shown.
func TestPostgresReportIncludesAISummaries(t *testing.T) {
	h := newHarness(t)
	asset, _ := h.upload("ai-report", "a")
	h.upload("no-summary", "b") // an asset without a summary adds nothing
	kn := h.jobs.Knowledge()
	old, err := kn.AddDocument(h.ctx, knowledge.Document{Kind: knowledge.KindAssessmentSummary, AssetID: &asset, Title: "Old headline", Body: "Old text.", Origin: knowledge.OriginLLM, Provenance: map[string]any{"model": "old-model"}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kn.AddDocument(h.ctx, knowledge.Document{Kind: knowledge.KindAssessmentSummary, AssetID: &asset, Ref: "main", Title: "One high finding", Body: "One high vulnerability is open.\n" + strings.Repeat("x", 5000), Origin: knowledge.OriginLLM, Supersedes: &old, Provenance: map[string]any{"model": "qwen2.5", "provider": "local"}}, "", nil); err != nil {
		t.Fatal(err)
	}
	// An advisory document of the same asset is not a summary.
	if _, err := kn.AddDocument(h.ctx, knowledge.Document{Kind: knowledge.KindAdvisory, AssetID: &asset, Title: "Advisory", Body: "Advisory text.", Origin: knowledge.OriginLLM}, "", nil); err != nil {
		t.Fatal(err)
	}
	write := h.issue("engineer", "write")
	request := func(params string) assessments.ReportJob {
		t.Helper()
		var job assessments.ReportJob
		w := h.call("POST", "/reports", write, []byte(`{"framework":"owasp-top10-2021","scope":{"kind":"portfolio"},"format":"md","params":`+params+`}`), "application/json")
		if w.Code != 202 && w.Code != 201 {
			t.Fatalf("report request: %d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		return job
	}
	_, none, err := h.jobs.ReportInput(h.ctx, request(`{}`))
	if err != nil || len(none.AISummaries) != 0 || none.Params.IncludeAISummaries {
		t.Fatalf("not asked: %+v %v", none.AISummaries, err)
	}
	_, with, err := h.jobs.ReportInput(h.ctx, request(`{"include_ai_summaries":true}`))
	if err != nil || !with.Params.IncludeAISummaries || len(with.AISummaries) != 1 {
		t.Fatalf("asked: %+v %v", with.AISummaries, err)
	}
	got := with.AISummaries[0]
	if got.AssetID != asset || got.Locator != "upload/ai-report" || got.Model != "qwen2.5" || got.Provider != "local" || got.Ref != "main" || got.Headline != "One high finding" || !strings.HasPrefix(got.Text, "One high vulnerability is open.") || len(got.Text) > 4010 || strings.Contains(got.Text, "Old text") {
		t.Fatalf("summary: %+v", got)
	}
	h.expect(h.call("POST", "/reports", write, []byte(`{"framework":"owasp-top10-2021","scope":{"kind":"portfolio"},"params":{"include_ai_summaries":"yes"}}`), "application/json"), 400)
}
