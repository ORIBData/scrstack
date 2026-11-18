package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/embed"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/ORIBData/scrstack/internal/llm/guard"
	"github.com/ORIBData/scrstack/internal/netguard"
	"github.com/ORIBData/scrstack/internal/summarize"
	"github.com/google/uuid"
)

// RunAISummaries runs queued advisory and summary jobs, one at a time.
func (w Worker) RunAISummaries(ctx context.Context) {
	for {
		worked, err := w.AISummaryOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("AI summary failed", "error", err)
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// AISummaryOnce runs one queued job and reports whether there was one.
func (w Worker) AISummaryOnce(ctx context.Context) (bool, error) {
	j, err := w.Store.ClaimAISummary(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	jobCtx, cancel := context.WithTimeout(ctx, assessments.AISummaryLease)
	defer cancel()
	res, retry, failure := w.aiSummary(jobCtx, j)
	finish := context.WithoutCancel(ctx)
	if failure != nil {
		w.Logger.Warn("AI summary ended with an error", "summary_id", j.ID, "error", failure)
		return true, w.Store.FinishAISummary(finish, j, failure.Error(), retry)
	}
	done, err := w.Store.CompleteAISummary(finish, j, res)
	if err != nil {
		return true, err
	}
	w.Logger.Info("AI summary finished", "summary_id", j.ID, "advisories", done.Advisories, "incomplete", done.Incomplete)
	return true, nil
}

// advisoryBatch is how many findings one model call describes: enough to
// share context, few enough that the answer stays well inside max_tokens.
const advisoryBatch = 4

// summaryFindings reads an assessment's findings, keeps those of the allowed
// types, and counts the rest.
func (w Worker) summaryFindings(ctx context.Context, a assessments.Assessment) (allowed []summarize.Finding, counts map[string]int, excluded int, err error) {
	counts = map[string]int{}
	after := uuid.Nil
	for page := 0; page < 20; page++ {
		items, err := w.Store.Findings(ctx, a.ID, uuid.Nil, after)
		if err != nil {
			return nil, nil, 0, err
		}
		more := len(items) > 100
		if more {
			items = items[:100]
		}
		for _, f := range items {
			after = f.ID
			if f.Status == "fixed" {
				continue
			}
			if !summarize.Allowed(f.Type) {
				excluded++
				continue
			}
			counts[f.Severity]++
			var g struct {
				Aliases []string `json:"aliases"`
				Fixed   []string `json:"fixed_versions"`
				KEV     bool     `json:"kev"`
				EPSS    float64  `json:"epss"`
			}
			_ = json.Unmarshal(f.Guidance, &g)
			allowed = append(allowed, summarize.Finding{
				ID: f.ID.String(), Type: f.Type, Severity: f.Severity, Title: f.Title, AdvisoryID: f.AdvisoryID, Aliases: g.Aliases,
				Package: f.Component.Name, Version: f.Component.Version, Ecosystem: f.Component.Ecosystem, Status: f.Status,
				Fixed: g.Fixed, KEV: g.KEV, EPSS: g.EPSS, New: f.Change == "new",
			})
		}
		if !more {
			break
		}
	}
	return allowed, counts, excluded, nil
}

// embedder returns the self-hosted embedding client, or nil when none is
// configured (SCRS_EMBED_URL is empty).
func (w Worker) embedder() *embed.Client {
	cfg, on, err := embed.ConfigFromEnv()
	if !on {
		return nil
	}
	if err != nil {
		w.Logger.Warn("embedding is configured incorrectly; documents are stored without vectors", "error", err)
		return nil
	}
	client, err := embed.New(cfg, netguard.Hosts(os.Getenv("SCRS_EMBED_PRIVATE_HOSTS")))
	if err != nil {
		w.Logger.Warn("embedding client unavailable; documents are stored without vectors", "error", err)
		return nil
	}
	return client
}

// chunksFor splits a document's text and embeds the parts. A failure returns
// no chunks: the document is still stored, and the failure is logged.
func (w Worker) chunksFor(ctx context.Context, e *embed.Client, text string) (string, []knowledge.Chunk) {
	if e == nil {
		return "", nil
	}
	parts := knowledge.Split(text, 1000, 120)
	if len(parts) == 0 {
		return "", nil
	}
	vectors, err := e.Embed(ctx, parts)
	if err != nil {
		w.Logger.Warn("embedding failed; the document is stored without vectors", "error", err)
		return "", nil
	}
	chunks := make([]knowledge.Chunk, len(parts))
	for i := range parts {
		chunks[i] = knowledge.Chunk{Text: parts[i], Vector: vectors[i]}
	}
	return e.Model(), chunks
}

func (w Worker) aiSummary(ctx context.Context, j assessments.AISummary) (assessments.AISummaryResult, bool, error) {
	var res assessments.AISummaryResult
	if j.ProviderID == nil {
		return res, false, assessments.ErrAISummaryProvider
	}
	provider, sealed, err := w.Store.LLMProviderCredential(ctx, *j.ProviderID)
	if err != nil || !provider.Enabled {
		return res, false, assessments.ErrAISummaryProvider
	}
	settings := llm.Provider{Kind: provider.Kind, BaseURL: provider.BaseURL, Model: provider.Model, MaxTokens: provider.MaxTokens, Temperature: provider.Temperature}
	var secret llm.Secret
	if err := w.unseal(sealed, assessments.LLMAAD(provider.ID), &secret); err != nil {
		return res, false, err
	}
	client, err := llm.NewClient(settings, secret, w.LLMPrivateHosts)
	if err != nil {
		return res, false, errors.New("LLM provider settings invalid: " + err.Error())
	}
	if j.Options.QARunID != nil {
		// QA entries carry paths and failure text: checked again here, as
		// for a code review, in case the provider changed since queueing.
		if _, ok := w.sourcePolicy().Check(settings, provider.SourceAckAt != nil); !ok {
			return res, false, assessments.ErrQASource
		}
		return w.aiQATriage(ctx, j, provider, settings, client)
	}
	a, err := w.Store.Get(ctx, j.AssessmentID)
	if err != nil {
		return res, true, err
	}
	findings, counts, excluded, err := w.summaryFindings(ctx, a)
	if err != nil {
		return res, true, err
	}
	res.Considered, res.Excluded = len(findings), excluded
	ranked := summarize.Rank(findings)
	if len(ranked) == 0 {
		return res, false, errors.New("the assessment has no open findings of a type that may be described to a model")
	}

	// Upstream advisory text for the findings that will be described.
	topForSummary := ranked[:min(len(ranked), 30)]
	forAdvisories := ranked[:min(len(ranked), j.Options.MaxAdvisories)]
	var ids []string
	for _, f := range ranked[:min(len(ranked), 30)] {
		ids = append(ids, f.AdvisoryID)
	}
	texts, err := w.Store.AdvisoryTexts(ctx, ids)
	if err != nil {
		return res, true, err
	}
	for i := range ranked {
		ranked[i].Detail = texts[ranked[i].AdvisoryID]
	}

	kn := w.Store.Knowledge()
	budget := w.budgetFor(provider, settings)
	known := map[string]bool{}
	titles := map[string]string{}
	byID := map[string]summarize.Finding{}
	for _, f := range ranked {
		known[f.ID], titles[f.ID], byID[f.ID] = true, f.Title, f
	}
	var asset string
	if a.Request.Target.Repository != "" {
		asset = a.Request.Target.Repository
	}
	ctxInfo := summarize.Context{Asset: asset, Ref: a.Request.Target.Ref, Commit: a.Commit, Verdict: a.Verdict, Counts: counts, Excluded: excluded}
	if prev, err := kn.Latest(ctx, a.AssetID, knowledge.KindAssessmentSummary, nil); err == nil {
		ctxInfo.Previous = prev.Body
	}

	var budgetErr error
	// call makes one guarded, budgeted model call and records it.
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
	budgetStop := func() { res.Incomplete = budgetMessage(budgetErr) }

	// 1. The assessment summary. A truncated answer is retried once with fewer findings.
	var summary summarize.Assessment
	group := topForSummary
	for attempt := 0; ; attempt++ {
		resp, transient, err := call("assessment_summary", summarize.AssessmentSystem, summarize.AssessmentPrompt(ctxInfo, group), summarize.AssessmentSchema, "assessment_summary")
		if err != nil {
			return res, transient, err
		}
		if resp.Truncated {
			if attempt == 0 && len(group) > 8 {
				group = group[:len(group)/2]
				continue
			}
			return res, false, errors.New("the summary was cut off at max_tokens; raise the provider's max_tokens")
		}
		var problems []string
		summary, problems = summarize.ParseAssessment(resp.Text, known)
		if summary.Headline == "" {
			return res, attempt == 0, fmt.Errorf("the model's summary was unusable: %s", strings.Join(problems, "; "))
		}
		break
	}

	e := w.embedder()
	meta := map[string]any{"model": provider.Model, "provider": provider.Name, "provider_locality": settings.Locality(w.LLMPrivateHosts), "prompt_version": summarize.PromptVersion, "summary_job_id": j.ID, "assessment_commit": a.Commit, "findings_considered": res.Considered, "findings_excluded": excluded}
	var superseded *uuid.UUID
	if prev, err := kn.Latest(ctx, a.AssetID, knowledge.KindAssessmentSummary, nil); err == nil {
		superseded = &prev.ID
	}
	body := summarize.RenderAssessment(summary, titles, ctxInfo)
	model, chunks := w.chunksFor(ctx, e, body)
	docID, err := kn.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindAssessmentSummary, AssetID: &a.AssetID, AssessmentID: &a.ID, Ref: a.Request.Target.Ref, Title: summary.Headline, Body: body, Origin: knowledge.OriginLLM, Provenance: meta, Supersedes: superseded}, model, chunks)
	if err != nil {
		return res, true, err
	}
	res.SummaryDocumentID = &docID

	// 2. Advisories for the most important findings, a few to a call.
	for start := 0; start < len(forAdvisories); start += advisoryBatch {
		batch := forAdvisories[start:min(start+advisoryBatch, len(forAdvisories))]
		written, stopped, err := w.advisoryBatch(ctx, call, batch, byID, a, kn, e, meta, &res)
		if err != nil {
			return res, false, err
		}
		res.Advisories += written
		if stopped {
			budgetStop()
			break
		}
	}
	if res.Advisories < len(forAdvisories) && res.Incomplete == "" {
		res.Incomplete = fmt.Sprintf("%d of %d advisories were written; the rest were incomplete or cut off at max_tokens", res.Advisories, len(forAdvisories))
	}
	return res, false, nil
}

// advisoryBatch writes the advisories of up to a few findings. A cut-off
// answer for several findings is retried one finding at a time.
func (w Worker) advisoryBatch(ctx context.Context, call func(string, string, string, json.RawMessage, string) (llm.Response, bool, error), batch []summarize.Finding, byID map[string]summarize.Finding, a assessments.Assessment, kn *knowledge.Store, e *embed.Client, meta map[string]any, res *assessments.AISummaryResult) (written int, budgetStopped bool, err error) {
	known := map[string]bool{}
	for _, f := range batch {
		known[f.ID] = true
	}
	resp, _, err := call("advisory", summarize.AdvisorySystem, summarize.AdvisoryPrompt(batch), summarize.AdvisorySchema, "advisories")
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
			n, stopped, err := w.advisoryBatch(ctx, call, []summarize.Finding{f}, byID, a, kn, e, meta, res)
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
		body := summarize.RenderAdvisory(adv, f)
		var superseded *uuid.UUID
		if prev, err := kn.Latest(ctx, a.AssetID, knowledge.KindAdvisory, &findingID); err == nil {
			superseded = &prev.ID
		}
		model, chunks := w.chunksFor(ctx, e, body)
		provenance := map[string]any{}
		for k, v := range meta {
			provenance[k] = v
		}
		provenance["advisory_id"], provenance["urgency"] = f.AdvisoryID, adv.Urgency
		if _, err := kn.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindAdvisory, AssetID: &a.AssetID, AssessmentID: &a.ID, FindingID: &findingID, Ref: a.Request.Target.Ref, Title: truncateTitle(f.Title), Body: body, Origin: knowledge.OriginLLM, Provenance: provenance, Supersedes: superseded}, model, chunks); err != nil {
			return written, false, err
		}
		written++
	}
	return written, false, nil
}

func truncateTitle(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	if s == "" {
		s = "Advisory"
	}
	return s
}
