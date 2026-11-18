package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/embed"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/ORIBData/scrstack/internal/llm/guard"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/summarize"
	"github.com/google/uuid"
)

// qaTypesOf names the finding types a QA run of a kind produces, so a
// triage describes only that run's own entries.
func qaTypesOf(kind string) map[string]bool {
	switch kind {
	case qa.KindLint:
		return map[string]bool{"qa_lint": true, "qa_lint_config": true}
	case qa.KindPerformance:
		return map[string]bool{"qa_performance": true}
	}
	return map[string]bool{"qa_failure": true, "qa_untested": true, "qa_config": true}
}

// qaFacts reduces a QA entry's evidence to the short facts a model may see.
// Request and response bodies are not in the evidence, and error text is
// clipped; the model client's guard screens the rest.
func qaFacts(f assessments.Finding) []string {
	var e struct {
		Suite, Feature, Scenario string
		Line                     int
		Tags                     []string
		Error                    string
		Problem                  string
		Operation                string `json:"operation"`
		Tool, Rule, Path         string
		Count                    int
		Fixable                  bool
		Locations                []struct {
			Line    int    `json:"line"`
			Message string `json:"message"`
		} `json:"locations"`
		Assertion struct {
			Description string  `json:"description"`
			Actual      float64 `json:"actual"`
		} `json:"assertion"`
		Stats struct {
			Requests   int     `json:"requests"`
			KO         int     `json:"ko"`
			P95Millis  float64 `json:"p95_ms"`
			Throughput float64 `json:"throughput_rps"`
		} `json:"stats"`
	}
	// Field names in the stored evidence are lower-case JSON keys.
	var raw map[string]json.RawMessage
	if json.Unmarshal(f.Evidence, &raw) != nil {
		return nil
	}
	get := func(key string, into any) { _ = json.Unmarshal(raw[key], into) }
	get("suite", &e.Suite)
	get("feature", &e.Feature)
	get("scenario", &e.Scenario)
	get("line", &e.Line)
	get("tags", &e.Tags)
	get("error", &e.Error)
	get("problem", &e.Problem)
	get("operation", &e.Operation)
	get("tool", &e.Tool)
	get("rule", &e.Rule)
	get("path", &e.Path)
	get("count", &e.Count)
	get("fixable", &e.Fixable)
	get("locations", &e.Locations)
	get("assertion", &e.Assertion)
	get("stats", &e.Stats)
	var facts []string
	add := func(format string, args ...any) { facts = append(facts, fmt.Sprintf(format, args...)) }
	switch f.Type {
	case "qa_failure":
		add("feature: %s/%s line %d", e.Suite, e.Feature, e.Line)
		add("scenario: %s", e.Scenario)
		if len(e.Tags) > 0 {
			add("tags: %s", strings.Join(e.Tags, " "))
		}
		if e.Error != "" {
			add("failure: %s", summarize.Clip(e.Error, 700))
		}
	case "qa_performance":
		add("threshold: %s (measured %.1f)", e.Assertion.Description, e.Assertion.Actual)
		add("requests: %d, failed: %d, p95: %.0f ms, throughput: %.1f/s", e.Stats.Requests, e.Stats.KO, e.Stats.P95Millis, e.Stats.Throughput)
	case "qa_untested":
		add("operation without test traffic: %s", e.Operation)
	case "qa_lint":
		add("tool: %s, rule: %s, file: %s, occurrences: %d, auto-fixable: %v", e.Tool, e.Rule, e.Path, e.Count, e.Fixable)
		for i, l := range e.Locations {
			if i >= 5 {
				break
			}
			add("line %d: %s", l.Line, summarize.Clip(l.Message, 200))
		}
	default:
		if e.Problem != "" {
			add("problem: %s", summarize.Clip(e.Problem, 300))
		}
	}
	return facts
}

// qaTriageFindings reads the run's own register entries from its assessment.
func (w Worker) qaTriageFindings(ctx context.Context, run assessments.QARun) ([]summarize.QAFinding, map[string]int, error) {
	types := qaTypesOf(run.Kind)
	counts := map[string]int{}
	var out []summarize.QAFinding
	after := uuid.Nil
	for page := 0; page < 50; page++ {
		items, err := w.Store.Findings(ctx, *run.AssessmentID, uuid.Nil, after)
		if err != nil {
			return nil, nil, err
		}
		more := len(items) > 100
		if more {
			items = items[:100]
		}
		for _, f := range items {
			after = f.ID
			if !types[f.Type] || f.Status == "fixed" || !strings.Contains(string(f.Evidence), run.ID.String()) {
				continue
			}
			counts[f.Severity]++
			out = append(out, summarize.QAFinding{ID: f.ID.String(), Type: f.Type, Severity: f.Severity, Title: f.Title, Facts: qaFacts(f)})
		}
		if !more {
			break
		}
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] > rank[out[j].Severity]
		}
		return out[i].ID < out[j].ID
	})
	return out, counts, nil
}

// aiQATriage writes a summary and advisories for one finished QA run. It
// uses the same guarded, budgeted model calls as the assessment summary, and
// stores its documents in the asset's chronicle: the run summary as a QA
// summary, each advisory against its register entry.
func (w Worker) aiQATriage(ctx context.Context, j assessments.AISummary, provider assessments.LLMProvider, settings llm.Provider, client *llm.Client) (assessments.AISummaryResult, bool, error) {
	var res assessments.AISummaryResult
	run, err := w.Store.QARunByID(ctx, *j.Options.QARunID)
	if err != nil || run.AssessmentID == nil {
		return res, false, errors.New("the QA run no longer exists")
	}
	findings, counts, err := w.qaTriageFindings(ctx, run)
	if err != nil {
		return res, true, err
	}
	res.Considered = len(findings)
	if len(findings) == 0 {
		return res, false, errors.New("the QA run has no open entries to triage")
	}
	a, err := w.Store.Get(ctx, *run.AssessmentID)
	if err != nil {
		return res, true, err
	}
	kn := w.Store.Knowledge()
	budget := w.budgetFor(provider, settings)
	var budgetErr error
	call := func(purpose, system, prompt string, schema json.RawMessage, name string) (llm.Response, bool, error) {
		in := knowledge.EstimateTokens(system + prompt)
		if err := kn.Reserve(ctx, a.ID, budget, in, int64(provider.MaxTokens)); err != nil {
			if errors.Is(err, knowledge.ErrBudget) {
				budgetErr = err
				return llm.Response{}, false, err
			}
			return llm.Response{}, true, err
		}
		resp, err := client.Complete(ctx, llm.Request{System: system, Prompt: prompt, Schema: schema, SchemaName: name})
		usage := knowledge.Usage{Purpose: purpose, AssetID: &a.AssetID, AssessmentID: &a.ID, Provider: provider.Name, Model: provider.Model, InputTokens: int64(resp.InputTokens), OutputTokens: int64(resp.OutputTokens), Truncated: resp.Truncated, Redactions: guard.Merge(resp.Redactions.Input, resp.Redactions.Output), Status: "ok"}
		if usage.InputTokens == 0 {
			usage.InputTokens = in
		}
		if err != nil {
			usage.Status = "error"
			_ = kn.RecordUsage(ctx, usage)
			transient, failure := modelFailure(err)
			return resp, transient, failure
		}
		if resp.Truncated {
			usage.Status = "truncated"
		}
		_ = kn.RecordUsage(ctx, usage)
		res.InputTokens += usage.InputTokens
		res.OutputTokens += usage.OutputTokens
		res.Redactions = guard.Merge(res.Redactions, usage.Redactions)
		return resp, false, nil
	}

	known := map[string]bool{}
	titles := map[string]string{}
	byID := map[string]summarize.QAFinding{}
	for _, f := range findings {
		known[f.ID], titles[f.ID], byID[f.ID] = true, f.Title, f
	}
	ctxInfo := summarize.QAContext{Asset: a.Request.Target.Repository, Ref: run.Ref, Commit: run.Commit, Kind: run.Kind, Status: run.Status, Counts: counts, Passed: run.Summary.Passed, Failed: run.Summary.Failed}
	if run.Summary.Lint != nil {
		ctxInfo.Issues = run.Summary.Lint.Issues
	}
	if prev, err := kn.Latest(ctx, a.AssetID, knowledge.KindQASummary, nil); err == nil {
		ctxInfo.Previous = prev.Body
	}

	// 1. The run summary; a cut-off answer is retried once with fewer entries.
	group := findings[:min(len(findings), 25)]
	var summary summarize.Assessment
	for attempt := 0; ; attempt++ {
		resp, transient, err := call("qa_summary", summarize.QASummarySystem, summarize.QASummaryPrompt(ctxInfo, group), summarize.AssessmentSchema, "qa_summary")
		if err != nil {
			return res, transient, err
		}
		if resp.Truncated {
			if attempt == 0 && len(group) > 8 {
				group = group[:len(group)/2]
				continue
			}
			return res, false, errors.New("the QA summary was cut off at max_tokens; raise the provider's max_tokens")
		}
		var problems []string
		summary, problems = summarize.ParseAssessment(resp.Text, known)
		if summary.Headline == "" {
			return res, attempt == 0, fmt.Errorf("the model's QA summary was unusable: %s", strings.Join(problems, "; "))
		}
		break
	}
	e := w.embedder()
	meta := map[string]any{"model": provider.Model, "provider": provider.Name, "provider_locality": settings.Locality(w.LLMPrivateHosts), "prompt_version": summarize.QAPromptVersion, "summary_job_id": j.ID, "qa_run_id": run.ID, "qa_kind": run.Kind, "assessment_commit": a.Commit, "findings_considered": res.Considered}
	var superseded *uuid.UUID
	if prev, err := kn.Latest(ctx, a.AssetID, knowledge.KindQASummary, nil); err == nil {
		superseded = &prev.ID
	}
	body := summarize.RenderQASummary(summary, titles, ctxInfo)
	model, chunks := w.chunksFor(ctx, e, body)
	docID, err := kn.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindQASummary, AssetID: &a.AssetID, AssessmentID: &a.ID, Ref: run.Ref, Title: summary.Headline, Body: body, Origin: knowledge.OriginLLM, Provenance: meta, Supersedes: superseded}, model, chunks)
	if err != nil {
		return res, true, err
	}
	res.SummaryDocumentID = &docID

	// 2. Advisories for the most important entries, a few to a call.
	max := min(len(findings), j.Options.MaxAdvisories)
	for start := 0; start < max; start += advisoryBatch {
		batch := findings[start:min(start+advisoryBatch, max)]
		written, stopped, err := w.qaAdvisoryBatch(ctx, call, batch, byID, a, run, kn, e, meta)
		if err != nil {
			return res, false, err
		}
		res.Advisories += written
		if stopped {
			res.Incomplete = budgetMessage(budgetErr)
			break
		}
	}
	if res.Advisories < max && res.Incomplete == "" {
		res.Incomplete = fmt.Sprintf("%d of %d advisories were written; the rest were incomplete or cut off at max_tokens", res.Advisories, max)
	}
	return res, false, nil
}

// qaAdvisoryBatch writes advisories for up to a few QA entries. A cut-off
// answer for several is retried one entry at a time.
func (w Worker) qaAdvisoryBatch(ctx context.Context, call func(string, string, string, json.RawMessage, string) (llm.Response, bool, error), batch []summarize.QAFinding, byID map[string]summarize.QAFinding, a assessments.Assessment, run assessments.QARun, kn *knowledge.Store, e *embed.Client, meta map[string]any) (written int, budgetStopped bool, err error) {
	known := map[string]bool{}
	for _, f := range batch {
		known[f.ID] = true
	}
	resp, _, err := call("qa_advisory", summarize.QAAdvisorySystem, summarize.QAAdvisoryPrompt(batch), summarize.AdvisorySchema, "advisories")
	if errors.Is(err, knowledge.ErrBudget) {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	if resp.Truncated {
		if len(batch) == 1 {
			return 0, false, nil
		}
		for _, f := range batch {
			n, stopped, err := w.qaAdvisoryBatch(ctx, call, []summarize.QAFinding{f}, byID, a, run, kn, e, meta)
			if err != nil || stopped {
				return written + n, stopped, err
			}
			written += n
		}
		return written, false, nil
	}
	advisories, _ := summarize.ParseAdvisories(resp.Text, known)
	for _, adv := range advisories {
		f := byID[adv.FindingID]
		findingID, perr := uuid.Parse(adv.FindingID)
		if perr != nil {
			continue
		}
		var superseded *uuid.UUID
		if prev, err := kn.Latest(ctx, a.AssetID, knowledge.KindAdvisory, &findingID); err == nil {
			superseded = &prev.ID
		}
		body := summarize.RenderQAAdvisory(adv, f)
		model, chunks := w.chunksFor(ctx, e, body)
		provenance := map[string]any{}
		for k, v := range meta {
			provenance[k] = v
		}
		provenance["urgency"] = adv.Urgency
		if _, err := kn.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindAdvisory, AssetID: &a.AssetID, AssessmentID: &a.ID, FindingID: &findingID, Ref: run.Ref, Title: truncateTitle(f.Title), Body: body, Origin: knowledge.OriginLLM, Provenance: provenance, Supersedes: superseded}, model, chunks); err != nil {
			return written, false, err
		}
		written++
	}
	return written, false, nil
}

// autoTriage queues an AI triage of a finished run when the asset's QA
// profile names a provider that may receive this kind of text and the run has
// entries worth describing. It never fails the run: a problem is logged.
func (w Worker) autoTriage(ctx context.Context, r assessments.QARun, outcome assessments.QAOutcome) {
	if outcome.Status != qa.StatePassed && outcome.Status != qa.StateFailed {
		return
	}
	if r.AssessmentID == nil {
		// Triage texts are filed under an assessment; a run without one has
		// its entries in the register and its report, but no summary.
		return
	}
	types := qaTypesOf(r.Kind)
	worth := false
	for _, f := range outcome.Findings {
		if types[f.Type] {
			worth = true
			break
		}
	}
	if !worth {
		return
	}
	profile, err := w.Store.QAProfileFor(ctx, r.AssetID)
	if err != nil || !profile.AITriage || profile.LLMProviderID == nil {
		return
	}
	if exists, err := w.Store.QATriageExists(ctx, r.ID); err != nil || exists {
		return
	}
	policy := w.sourcePolicy()
	_, err = w.Store.EnqueueQATriage(ctx, r.ID, *profile.LLMProviderID, "scrs", func(p assessments.LLMProvider) bool {
		_, ok := policy.Check(llm.Provider{Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model, MaxTokens: p.MaxTokens, Temperature: p.Temperature}, p.SourceAckAt != nil)
		return ok
	})
	if err != nil && !errors.Is(err, assessments.ErrQASource) {
		w.Logger.Warn("automatic QA triage not queued", "qa_run_id", r.ID, "error", err)
	}
}
