package worker

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/ORIBData/scrstack/internal/llm/guard"
	"github.com/ORIBData/scrstack/internal/qa"
)

// RunGenerations drafts tests with the profile's LLM provider, one
// generation at a time.
func (w Worker) RunGenerations(ctx context.Context) {
	for {
		worked, err := w.GenerateOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("QA generation failed", "error", err)
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

// opsPerRequest groups operations into one model request: enough for
// related scenarios, small enough for complete answers.
const opsPerRequest = 8

// GenerateOnce runs one queued generation and reports whether there was one.
func (w Worker) GenerateOnce(ctx context.Context) (bool, error) {
	g, err := w.Store.ClaimQAGeneration(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	jobCtx, cancel := context.WithTimeout(ctx, assessments.QAGenerationLease*3)
	defer cancel()
	retry, failure := w.generate(jobCtx, g)
	if failure != nil {
		w.Logger.Warn("QA generation ended with an error", "generation_id", g.ID, "error", failure)
		return true, w.Store.FinishQAGeneration(context.WithoutCancel(ctx), g, failure.Error(), retry)
	}
	return true, w.Store.FinishQAGeneration(context.WithoutCancel(ctx), g, "", false)
}

// generate returns whether retrying may help and the error that ended the
// generation.
func (w Worker) generate(ctx context.Context, g assessments.QAGeneration) (bool, error) {
	profile, err := w.Store.QAProfileFor(ctx, g.AssetID)
	if err != nil || !profile.Enabled || profile.LLMProviderID == nil || (g.Kind == "unit" && !profile.AllowSourceUpload) {
		return false, assessments.ErrQAProvider
	}
	provider, sealed, err := w.Store.LLMProviderCredential(ctx, *profile.LLMProviderID)
	if err != nil || !provider.Enabled {
		return false, assessments.ErrQAProvider
	}
	var secret llm.Secret
	if err := w.unseal(sealed, assessments.LLMAAD(provider.ID), &secret); err != nil {
		return false, err
	}
	settings := llm.Provider{Kind: provider.Kind, BaseURL: provider.BaseURL, Model: provider.Model, MaxTokens: provider.MaxTokens, Temperature: provider.Temperature}
	if g.Kind == "unit" {
		if _, ok := w.sourcePolicy().Check(settings, provider.SourceAckAt != nil); !ok {
			return false, assessments.ErrQASource
		}
	}
	// A hosted provider is billed per token: stop when its monthly cap is
	// used up. The cap is checked once per generation, and what the
	// generation uses is added to the ledger so the next one sees it.
	if err := w.Store.Knowledge().ReserveMonth(ctx, w.budgetFor(provider, settings), 0, int64(provider.MaxTokens)); err != nil {
		if errors.Is(err, knowledge.ErrBudget) {
			return false, errors.New(budgetMessage(err))
		}
		return true, err
	}
	client, err := llm.NewClient(settings, secret, w.LLMPrivateHosts)
	if err != nil {
		return false, errors.New("LLM provider settings invalid: " + err.Error())
	}
	if g.AssessmentID == nil {
		return false, assessments.ErrQANoAssessment
	}
	a, err := w.Store.Get(ctx, *g.AssessmentID)
	if err != nil {
		return true, err
	}
	archive, err := w.fetchCommit(ctx, a, g.Commit)
	if err != nil {
		return !errors.Is(err, assessments.ErrScope), errors.New("source download failed: " + err.Error())
	}
	if g.Kind == "unit" {
		return w.generateUnit(ctx, g, client, archive)
	}
	return w.generateAPI(ctx, g, profile, client, archive)
}

// modelFailure reports whether a model error is worth retrying later.
func modelFailure(err error) (bool, error) {
	text := err.Error()
	transient := strings.Contains(text, "rate limit") || strings.Contains(text, "provider error") || strings.Contains(text, "unreachable")
	return transient, errors.New("model request failed: " + text)
}

func (w Worker) generateAPI(ctx context.Context, g assessments.QAGeneration, profile assessments.QAProfile, client *llm.Client, archive []byte) (bool, error) {
	specPath := profile.OpenAPIPath
	snap, err := qa.ReadSnapshot(archive, func(rel string, size int64) bool {
		return rel == specPath || qa.SpecNames[strings.ToLower(path.Base(rel))]
	}, 50, 8*qa.MaxSpecBytes)
	if err != nil {
		return false, errors.New("source archive unreadable: " + err.Error())
	}
	if specPath == "" {
		specPath = qa.FindSpec(snap.Paths)
	}
	data, ok := snap.Files[specPath]
	if specPath == "" || !ok {
		return false, errors.New("no OpenAPI document at this commit; set openapi_path in the QA profile")
	}
	api, err := qa.ParseAPI(data)
	if err != nil {
		return false, errors.New("OpenAPI document " + specPath + " unusable: " + err.Error())
	}
	ops := w.pickOperations(ctx, g, api)
	if len(ops) == 0 {
		return false, errors.New("every selected operation already has a generated suite or is deprecated")
	}
	for start := 0; start < len(ops); start += opsPerRequest {
		batch := ops[start:min(start+opsPerRequest, len(ops))]
		resp, err := client.Complete(ctx, llm.Request{System: qa.APISystemPrompt, Prompt: qa.APIPrompt(api, batch, 48<<10)})
		if err != nil {
			return modelFailure(err)
		}
		keys := make([]string, len(batch))
		for i, o := range batch {
			keys[i] = o.Key()
		}
		source := strings.Join(keys, ", ")
		files := qa.ParseFiles(resp.Text)
		suites := make([]assessments.QASuite, 0, len(files)+1)
		for i, f := range files {
			problems := qa.CheckFeature(f.Path, f.Data)
			if resp.Truncated && i == len(files)-1 {
				problems = append(problems, "model output stopped at max_tokens; this file may be incomplete")
			}
			suites = append(suites, assessments.QASuite{Path: f.Path, Source: source, Content: string(f.Data), Problems: problems})
		}
		if len(files) == 0 {
			suites = append(suites, assessments.QASuite{Path: "unparsed-output.txt", Source: source, Content: clipText(resp.Text, qa.MaxGeneratedBytes), Problems: []string{qa.ErrNoFiles.Error()}})
		}
		w.recordQAUsage(ctx, g, "qa_api", resp)
		if err := w.Store.AddQASuites(ctx, g, suites, resp.InputTokens, resp.OutputTokens); err != nil {
			return true, err
		}
	}
	return false, nil
}

// pickOperations orders the operations to generate for: those named in
// the options, else the ones the latest functional run did not exercise,
// then the rest, skipping deprecated ones and those whose suites exist.
func (w Worker) pickOperations(ctx context.Context, g assessments.QAGeneration, api qa.API) []qa.Operation {
	covered := map[string]bool{}
	if runs, err := w.Store.QARuns(ctx, assessments.QARunFilter{Asset: g.AssetID, Kind: qa.KindFunctional, Status: qa.StatePassed, Limit: 1}); err == nil && len(runs) > 0 {
		covered = coveredOperations(ctx, w.Store, runs[0])
	}
	if runs, err := w.Store.QARuns(ctx, assessments.QARunFilter{Asset: g.AssetID, Kind: qa.KindFunctional, Status: qa.StateFailed, Limit: 1}); err == nil && len(runs) > 0 && len(covered) == 0 {
		covered = coveredOperations(ctx, w.Store, runs[0])
	}
	existing := map[string]bool{}
	for _, status := range []string{"draft", "approved"} {
		suites, _ := w.Store.QASuites(ctx, assessments.QASuiteFilter{Asset: g.AssetID, Kind: "api", Status: status})
		for _, s := range suites {
			for _, key := range strings.Split(s.Source, ", ") {
				existing[key] = true
			}
		}
	}
	var picked []qa.Operation
	for _, o := range api.Operations {
		if o.Deprecated {
			continue
		}
		if len(g.Options.Operations) > 0 {
			if slices.Contains(g.Options.Operations, o.Key()) {
				picked = append(picked, o)
			}
			continue
		}
		if !existing[o.Key()] {
			picked = append(picked, o)
		}
	}
	sort.SliceStable(picked, func(i, j int) bool { return !covered[picked[i].Key()] && covered[picked[j].Key()] })
	if len(picked) > g.Options.MaxOperations {
		picked = picked[:g.Options.MaxOperations]
	}
	// Keep a path's operations together, so one feature can cover them.
	sort.SliceStable(picked, func(i, j int) bool { return picked[i].Path < picked[j].Path })
	return picked
}

func coveredOperations(ctx context.Context, store *assessments.Store, run assessments.QARun) map[string]bool {
	out := map[string]bool{}
	body, err := store.QARunCoverage(ctx, run.ID)
	if err != nil {
		return out
	}
	var c qa.Coverage
	if json.Unmarshal(body, &c) == nil {
		for _, o := range c.Operations {
			if o.Hits > 0 {
				out[o.Key()] = true
			}
		}
	}
	return out
}

// isTest reports a path that looks like an existing unit test, kept as a
// style sample for the model.
func isTest(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") || strings.HasSuffix(base, "Test.java") || strings.HasSuffix(base, "Test.kt")
}

func (w Worker) generateUnit(ctx context.Context, g assessments.QAGeneration, client *llm.Client, archive []byte) (bool, error) {
	snap, err := qa.ReadSnapshot(archive, func(rel string, size int64) bool {
		return qa.UnitCandidate(rel, size) || rel == "package.json" || (isTest(rel) && size <= 16<<10)
	}, 3000, 64<<20)
	if err != nil {
		return false, errors.New("source archive unreadable: " + err.Error())
	}
	framework := qa.JSFramework(snap.Files["package.json"])
	targets := qa.UnitTargets(snap, framework, 1000)
	if len(g.Options.Paths) > 0 {
		var chosen []qa.UnitTarget
		for _, t := range targets {
			if slices.Contains(g.Options.Paths, t.Source) {
				chosen = append(chosen, t)
			}
		}
		targets = chosen
	}
	existing := map[string]bool{}
	for _, status := range []string{"draft", "approved"} {
		suites, _ := w.Store.QASuites(ctx, assessments.QASuiteFilter{Asset: g.AssetID, Kind: "unit", Status: status})
		for _, s := range suites {
			existing[s.Source] = true
		}
	}
	var work []qa.UnitTarget
	for _, t := range targets {
		if !existing[t.Source] && len(work) < g.Options.MaxFiles {
			work = append(work, t)
		}
	}
	if len(work) == 0 {
		return false, errors.New("no source files without tests (or all already have drafts) in Go, TypeScript, JavaScript, Python, Java or Kotlin")
	}
	for _, t := range work {
		samplePath, sample := "", ""
		for _, p := range snap.Paths {
			if data, ok := snap.Files[p]; ok && isTest(p) && path.Ext(p) == path.Ext(t.TestPath) {
				samplePath, sample = p, string(data)
				break
			}
		}
		resp, err := client.Complete(ctx, llm.Request{System: qa.UnitSystemPrompt, Prompt: qa.UnitPrompt(t, snap.Files[t.Source], sample, samplePath)})
		if err != nil {
			return modelFailure(err)
		}
		files := qa.ParseFiles(resp.Text)
		suite := assessments.QASuite{Path: t.TestPath, Source: t.Source}
		switch {
		case len(files) == 0:
			suite.Content, suite.Problems = clipText(resp.Text, qa.MaxGeneratedBytes), []string{qa.ErrNoFiles.Error()}
		default:
			suite.Content, suite.Problems = string(files[0].Data), qa.CheckUnitTest(t, files[0])
		}
		if resp.Truncated {
			suite.Problems = append(suite.Problems, "model output stopped at max_tokens; this file may be incomplete")
		}
		w.recordQAUsage(ctx, g, "qa_unit", resp)
		if err := w.Store.AddQASuites(ctx, g, []assessments.QASuite{suite}, resp.InputTokens, resp.OutputTokens); err != nil {
			return true, err
		}
	}
	return false, nil
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// recordQAUsage adds a generation's model call to the usage ledger, which the
// monthly provider cap reads.
func (w Worker) recordQAUsage(ctx context.Context, g assessments.QAGeneration, purpose string, resp llm.Response) {
	_ = w.Store.Knowledge().RecordUsage(context.WithoutCancel(ctx), knowledge.Usage{Purpose: purpose, AssetID: &g.AssetID, Provider: g.ProviderName, Model: g.Model, InputTokens: int64(resp.InputTokens), OutputTokens: int64(resp.OutputTokens), Truncated: resp.Truncated, Redactions: guard.Merge(resp.Redactions.Input, resp.Redactions.Output), Status: "ok"})
}
