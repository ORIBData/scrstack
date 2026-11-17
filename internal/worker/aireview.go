package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/ORIBData/scrstack/internal/llm/guard"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/review"
	"github.com/google/uuid"
)

// RunAIReviews runs queued code reviews, one at a time.
func (w Worker) RunAIReviews(ctx context.Context) {
	for {
		worked, err := w.AIReviewOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("AI code review failed", "error", err)
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

// AIReviewOnce runs one queued review and reports whether there was one.
func (w Worker) AIReviewOnce(ctx context.Context) (bool, error) {
	r, err := w.Store.ClaimAIReview(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	jobCtx, cancel := context.WithTimeout(ctx, assessments.AIReviewLease)
	defer cancel()
	res, retry, failure := w.aiReview(jobCtx, r)
	finish := context.WithoutCancel(ctx)
	if failure != nil {
		w.Logger.Warn("AI code review ended with an error", "review_id", r.ID, "error", failure)
		return true, w.Store.FinishAIReview(finish, r, failure.Error(), retry)
	}
	done, err := w.Store.CompleteAIReview(finish, r, res)
	if err != nil {
		return true, err
	}
	w.Logger.Info("AI code review finished", "review_id", r.ID, "files", done.FilesReviewed, "findings", done.Findings, "incomplete", done.Incomplete)
	return true, nil
}

// aiReview reads the source and asks the model about one file at a time.
func (w Worker) aiReview(ctx context.Context, r assessments.AIReview) (assessments.AIReviewResult, bool, error) {
	var res assessments.AIReviewResult
	if r.ProviderID == nil || r.AssessmentID == nil {
		return res, false, assessments.ErrAIReviewProvider
	}
	provider, sealed, err := w.Store.LLMProviderCredential(ctx, *r.ProviderID)
	if err != nil || !provider.Enabled {
		return res, false, assessments.ErrAIReviewProvider
	}
	settings := llm.Provider{Kind: provider.Kind, BaseURL: provider.BaseURL, Model: provider.Model, MaxTokens: provider.MaxTokens, Temperature: provider.Temperature}
	// Checked again here, not only when the review was queued: the provider
	// may have been edited, or its acknowledgement withdrawn, since.
	if _, ok := w.sourcePolicy().Check(settings, provider.SourceAckAt != nil); !ok {
		return res, false, assessments.ErrAIReviewSource
	}
	var secret llm.Secret
	if err := w.unseal(sealed, assessments.LLMAAD(provider.ID), &secret); err != nil {
		return res, false, err
	}
	client, err := llm.NewClient(settings, secret, w.LLMPrivateHosts)
	if err != nil {
		return res, false, errors.New("LLM provider settings invalid: " + err.Error())
	}
	a, err := w.Store.Get(ctx, *r.AssessmentID)
	if err != nil {
		return res, true, err
	}
	archive, err := w.fetchCommit(ctx, a, r.Commit)
	if err != nil {
		return res, !errors.Is(err, assessments.ErrScope), errors.New("source download failed: " + err.Error())
	}
	snap, err := qa.ReadSnapshot(archive, review.Candidate, 5000, 64<<20)
	if err != nil {
		return res, false, errors.New("source archive unreadable: " + err.Error())
	}
	paths := snap.Paths[:0:0]
	for _, p := range snap.Paths {
		if _, ok := snap.Files[p]; ok && (len(r.Options.Paths) == 0 || contains(r.Options.Paths, p)) {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return res, false, errors.New("no reviewable source files (Go, Python, JavaScript, TypeScript, Java, Kotlin, Ruby, PHP, C#, Rust, C, C++, Swift, Scala or shell, outside tests, vendored and generated code)")
	}
	paths = review.Rank(paths, func(p string) int { return len(snap.Files[p]) })
	if len(paths) > r.Options.MaxFiles {
		res.Skipped = len(paths) - r.Options.MaxFiles
		paths = paths[:r.Options.MaxFiles]
	}

	knowledgeStore := w.Store.Knowledge()
	budget := w.budgetFor(provider, settings)
	problems, cutOff := 0, 0
	for _, p := range paths {
		code := string(snap.Files[p])
		prompt := review.UserPrompt(p, code)
		in := knowledge.EstimateTokens(review.SystemPrompt + prompt)
		if err := knowledgeStore.Reserve(ctx, *r.AssessmentID, budget, in, int64(provider.MaxTokens)); err != nil {
			if errors.Is(err, knowledge.ErrBudget) {
				res.Incomplete = budgetMessage(err) + " or review fewer files"
				res.Skipped += len(paths) - len(res.Reviewed)
				break
			}
			return res, true, err
		}
		resp, err := client.Complete(ctx, llm.Request{System: review.SystemPrompt, Prompt: prompt, Schema: review.Schema, SchemaName: "code_review"})
		usage := knowledge.Usage{Purpose: "code_review", AssetID: &r.AssetID, AssessmentID: r.AssessmentID, Provider: provider.Name, Model: provider.Model, InputTokens: int64(resp.InputTokens), OutputTokens: int64(resp.OutputTokens), Truncated: resp.Truncated, Redactions: guard.Merge(resp.Redactions.Input, resp.Redactions.Output), Status: "ok"}
		if err != nil {
			usage.Status = "error"
			_ = knowledgeStore.RecordUsage(ctx, usage)
			transient, failure := modelFailure(err)
			return res, transient, failure
		}
		if usage.InputTokens == 0 {
			usage.InputTokens = in
		}
		res.InputTokens += usage.InputTokens
		res.OutputTokens += usage.OutputTokens
		res.Redactions = guard.Merge(res.Redactions, usage.Redactions)
		if resp.Truncated {
			// A cut-off answer is not a finished review of the file.
			usage.Status = "truncated"
			_ = knowledgeStore.RecordUsage(ctx, usage)
			cutOff++
			res.Skipped++
			continue
		}
		_ = knowledgeStore.RecordUsage(ctx, usage)
		issues, bad := review.Parse(resp.Text, review.CountLines(code))
		problems += len(bad)
		res.Reviewed = append(res.Reviewed, p)
		for _, issue := range issues {
			res.Issues = append(res.Issues, assessments.AIIssue{Path: p, Language: review.Language(p), Issue: issue})
		}
	}
	if cutOff > 0 && res.Incomplete == "" {
		res.Incomplete = fmt.Sprintf("%d file(s) were not reviewed because the model's answer was cut off at max_tokens; raise the provider's max_tokens", cutOff)
	}
	if len(res.Reviewed) == 0 && res.Incomplete != "" {
		return res, false, errors.New(res.Incomplete)
	}
	res.ReviewModel, res.PromptVersion = provider.Model, review.PromptVersion
	if id := w.chronicleReview(ctx, r, a, res, problems); id != nil {
		res.DocumentID = id
	}
	return res, false, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// chronicleReview writes the review into the asset's chronicle: a readable
// summary linked to the asset and assessment, with provenance. It lists
// titles, files and lines, never code. A failure here does not fail the review.
func (w Worker) chronicleReview(ctx context.Context, r assessments.AIReview, a assessments.Assessment, res assessments.AIReviewResult, problems int) *uuid.UUID {
	var b strings.Builder
	commit := r.Commit
	if len(commit) > 8 {
		commit = commit[:8]
	}
	fmt.Fprintf(&b, "AI code review of %s at %s by %s (prompt %s). Reviewed %d file(s), skipped %d, %d finding(s). Written by a language model and not verified.\n", r.Ref, commit, res.ReviewModel, res.PromptVersion, len(res.Reviewed), res.Skipped, len(res.Issues))
	if res.Incomplete != "" {
		fmt.Fprintf(&b, "Incomplete: %s\n", res.Incomplete)
	}
	issues := append([]assessments.AIIssue(nil), res.Issues...)
	sort.SliceStable(issues, func(i, j int) bool {
		return issues[i].Path < issues[j].Path || issues[i].Path == issues[j].Path && issues[i].LineStart < issues[j].LineStart
	})
	for _, i := range issues {
		fmt.Fprintf(&b, "- [%s] %s: %s (%s:%d)\n", i.Severity, i.Category, i.Title, i.Path, i.LineStart)
	}
	id, err := w.Store.Knowledge().AddDocument(ctx, knowledge.Document{
		Kind: knowledge.KindCodeReview, AssetID: &r.AssetID, AssessmentID: r.AssessmentID, Ref: r.Ref,
		Title: "AI code review: " + r.Ref + "@" + commit, Body: b.String(), Origin: knowledge.OriginLLM,
		Provenance: map[string]any{"model": res.ReviewModel, "provider": r.ProviderName, "prompt_version": res.PromptVersion, "review_id": r.ID, "files_reviewed": len(res.Reviewed), "files_skipped": res.Skipped, "invalid_findings_dropped": problems, "incomplete": res.Incomplete, "redactions": res.Redactions, "assessment_commit": a.Commit},
	}, "", nil)
	if err != nil {
		w.Logger.Warn("AI code review summary not stored in the chronicle", "review_id", r.ID, "error", err)
		return nil
	}
	return &id
}

// sourcePolicy says which providers may be sent source code.
func (w Worker) sourcePolicy() llm.SourcePolicy {
	return llm.SourcePolicy{Private: w.LLMPrivateHosts, AllowHosted: w.LLMAllowSource}
}

// budgetFor is the token budget for work with a provider: the per-assessment
// budget, plus the monthly cap when the provider is hosted (billed per token).
func (w Worker) budgetFor(provider assessments.LLMProvider, settings llm.Provider) knowledge.Budget {
	b := knowledge.BudgetFromEnv()
	if !settings.Local(w.LLMPrivateHosts) {
		b = b.WithMonthly(provider.Name)
	}
	return b
}

// budgetMessage explains which token limit stopped the work.
func budgetMessage(err error) string {
	if errors.Is(err, knowledge.ErrMonthlyCap) {
		return "the provider's monthly token cap was reached; raise SCRS_LLM_MONTHLY_INPUT_TOKENS and SCRS_LLM_MONTHLY_OUTPUT_TOKENS (0 removes a cap) or wait for the next month"
	}
	return "the token budget for this assessment was reached; raise SCRS_LLM_ASSESSMENT_INPUT_TOKENS and SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS"
}
