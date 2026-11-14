package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/qa"
)

// QAReports stores runner report archives.
type QAReports interface {
	PutQAReport(context.Context, []byte) (string, string, error)
}

// RunQA moves QA runs through the runner: submit queued runs, poll active
// ones, ingest finished reports and remove cancelled jobs. Each claim is
// one short step, so many runs progress on one worker.
func (w Worker) RunQA(ctx context.Context) {
	for {
		worked, err := w.QAOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("QA step failed", "error", err)
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// QAOnce performs one step on one run and reports whether there was one.
func (w Worker) QAOnce(ctx context.Context) (bool, error) {
	if w.QARunner == nil {
		return false, nil
	}
	max := w.QAMaxActive
	if max <= 0 {
		max = 4
	}
	r, err := w.Store.ClaimQARun(ctx, max)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stepCtx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	switch {
	case r.Cleanup:
		if err := w.QARunner.Delete(stepCtx, r.ID.String()); err != nil {
			return true, w.Store.AdvanceQARun(ctx, r, assessments.QAStep{Status: r.Status, Delay: time.Minute, Error: r.Error})
		}
		return true, w.Store.QACleaned(ctx, r)
	case r.Status == "queued":
		return true, w.submitQA(stepCtx, r)
	}
	return true, w.pollQA(stepCtx, r)
}

// qaAttempts bounds submissions of one run (runner unreachable, busy or
// restarted).
const qaAttempts = 5

// failQA ends a run that could not execute; it closes no findings.
func (w Worker) failQA(ctx context.Context, r assessments.QARun, message string, findings []assessments.Finding) error {
	return w.Store.FinishQARun(context.WithoutCancel(ctx), r, assessments.QAOutcome{Status: qa.StateError, Error: message, Findings: findings})
}

// retryQA requeues a run after a transient failure, or ends it.
func (w Worker) retryQA(ctx context.Context, r assessments.QARun, err error) error {
	if r.Attempts >= qaAttempts {
		return w.failQA(ctx, r, "runner submission failed after "+fmt.Sprint(qaAttempts)+" attempts: "+err.Error(), nil)
	}
	delay := time.Duration(15<<r.Attempts) * time.Second
	if errors.Is(err, qa.ErrRunnerBusy) {
		delay = 30 * time.Second
	}
	return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, assessments.QAStep{Status: "queued", Delay: delay, Error: err.Error()})
}

// fetchCommit downloads the source archive of an assessed commit.
func (w Worker) fetchCommit(ctx context.Context, a assessments.Assessment, commit string) ([]byte, error) {
	name, err := w.Connections.NameByID(ctx, a.ConnectionID)
	if err != nil {
		return nil, assessments.ErrScope
	}
	c, secret, err := w.Connections.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	if !c.Enabled {
		return nil, assessments.ErrScope
	}
	asset, err := w.Connections.Asset(ctx, a.AssetID)
	if err != nil {
		return nil, assessments.ErrScope
	}
	source := w.Source
	if source == nil {
		source = connections.NewNativeAdapters()
	}
	archive, resolved, _, err := source.Snapshot(ctx, c, secret, asset.Locator, "", commit)
	if err != nil {
		return nil, err
	}
	if resolved != commit {
		return nil, errors.New("source host returned another commit")
	}
	return archive, nil
}

// unseal opens a sealed JSON value bound to aad.
func (w Worker) unseal(sealed, aad []byte, into any) error {
	if len(sealed) == 0 {
		return nil
	}
	plain, err := w.Connections.Unseal(sealed, aad)
	if err != nil {
		return errors.New("sealed secret could not be opened; check SCRS_MASTER_KEY")
	}
	return json.Unmarshal(plain, into)
}

// configFinding is a qa_config finding for a setup problem.
func configFinding(r assessments.QARun, key, title string) assessments.Finding {
	evidence, _ := json.Marshal(map[string]string{"problem": title, "qa_run_id": r.ID.String(), "commit": r.Commit})
	return assessments.Finding{Type: "qa_config", AdvisoryID: "SCRS-QA-CONFIG", Title: title, Severity: "low", Score: 10, Component: assessments.Component{Name: key, Path: "qa-profile#" + key}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Fix the QA profile or add the missing files to the repository; see QA_TESTING.md.","automatic_changes":false}`)}
}

// generatedConfig is the karate-config.js of the generated suite: baseUrl,
// the profile's variables (as vars.NAME) and the profile's auth header.
func generatedConfig(p assessments.QAProfile) []byte {
	var b strings.Builder
	b.WriteString("function fn() {\n  var env = java.lang.System.getenv;\n  var config = { baseUrl: env('SCRS_BASE_URL'), vars: {} };\n")
	for _, name := range p.VariableNames {
		fmt.Fprintf(&b, "  config.vars['%s'] = env('QA_%s');\n", name, name)
	}
	if p.Auth.Header != "" {
		fmt.Fprintf(&b, "  var credential = env('QA_%s');\n  if (credential) karate.configure('headers', { '%s': '%s' + credential });\n", p.Auth.Variable, p.Auth.Header, p.Auth.Prefix)
	}
	b.WriteString("  return config;\n}\n")
	return []byte(b.String())
}

// Bundle limits: repository test files and their total size.
const (
	maxTestFiles = 2000
	maxTestBytes = 24 << 20
)

// submitQA prepares a run's bundle from the assessed commit and submits it.
func (w Worker) submitQA(ctx context.Context, r assessments.QARun) error {
	a, profile, sealed, err := w.Store.QAContext(ctx, r)
	if errors.Is(err, assessments.ErrQAProfile) || (err == nil && !profile.Enabled) {
		return w.failQA(ctx, r, "the asset's QA profile was removed or disabled", nil)
	}
	if err != nil {
		return w.retryQA(ctx, r, err)
	}
	variables := map[string]string{}
	if err := w.unseal(sealed, assessments.QAAAD(r.AssetID), &variables); err != nil {
		return w.failQA(ctx, r, err.Error(), nil)
	}
	archive, err := w.fetchCommit(ctx, a, r.Commit)
	if errors.Is(err, assessments.ErrScope) {
		return w.failQA(ctx, r, "the asset's connection is disabled or out of scope", nil)
	}
	if err != nil {
		return w.retryQA(ctx, r, err)
	}
	testPath := strings.Trim(profile.TestPath, "/")
	snap, err := qa.ReadSnapshot(archive, func(rel string, size int64) bool {
		return (qa.Under(rel, testPath) && size <= 4<<20) || rel == profile.OpenAPIPath || qa.SpecNames[strings.ToLower(path.Base(rel))]
	}, maxTestFiles+50, maxTestBytes+qa.MaxSpecBytes*4)
	if err != nil {
		return w.failQA(ctx, r, "source archive unreadable: "+err.Error(), nil)
	}
	var files []qa.File
	repoFeatures := 0
	for _, rel := range snap.Paths {
		data, kept := snap.Files[rel]
		if !kept || !qa.Under(rel, testPath) {
			continue
		}
		inner := rel
		if testPath != "" && testPath != "." {
			inner = strings.TrimPrefix(rel, testPath+"/")
		}
		if len(files) >= maxTestFiles {
			break
		}
		files = append(files, qa.File{Path: "repo/" + inner, Data: data})
		if strings.HasSuffix(inner, ".feature") {
			repoFeatures++
		}
	}
	var problems []string
	var findings []assessments.Finding
	step := assessments.QAStep{Status: "submitted", Delay: 10 * time.Second, BaseURL: profile.BaseURL}
	if r.Kind == qa.KindFunctional {
		statuses := []string{"approved"}
		if r.IncludeDrafts {
			statuses = append(statuses, "draft")
		}
		generated := map[string][]byte{}
		for _, status := range statuses {
			suites, err := w.Store.QASuites(ctx, assessments.QASuiteFilter{Asset: r.AssetID, Kind: "api", Status: status, Content: true})
			if err != nil {
				return w.retryQA(ctx, r, err)
			}
			for _, s := range suites {
				if _, taken := generated[s.Path]; !taken {
					generated[s.Path] = []byte(s.Content)
				}
			}
		}
		for p, data := range generated {
			files = append(files, qa.File{Path: "generated/" + p, Data: data})
		}
		if len(generated) > 0 {
			files = append(files, qa.File{Path: "generated/karate-config.js", Data: generatedConfig(profile)})
		}
		if repoFeatures == 0 {
			problems = append(problems, "no Karate .feature files under "+firstNonEmpty(testPath, "the repository root"))
		}
		if repoFeatures == 0 && len(generated) == 0 {
			findings = append(findings, configFinding(r, "no-tests", "QA profile has no Karate tests to run at "+firstNonEmpty(testPath, "the repository root")+" and no approved generated suites"))
			return w.failQA(ctx, r, problems[0], findings)
		}
		spec := profile.OpenAPIPath
		if spec == "" {
			spec = qa.FindSpec(snap.Paths)
		}
		if data, ok := snap.Files[spec]; ok && spec != "" {
			api, err := qa.ParseAPI(data)
			if err != nil {
				problems = append(problems, "OpenAPI document "+spec+" unusable: "+err.Error())
			} else {
				step.Operations, step.BasePaths, step.Spec = api.Operations, api.BasePaths, spec
			}
		} else if profile.OpenAPIPath != "" {
			problems = append(problems, "OpenAPI document "+profile.OpenAPIPath+" not found at this commit")
		}
	} else if repoFeatures == 0 {
		return w.failQA(ctx, r, "performance features are not in the repository at this commit", []assessments.Finding{configFinding(r, "no-perf-features", "QA performance features are missing at "+firstNonEmpty(testPath, "the repository root"))})
	}
	step.Problems = problems
	bundle, err := qa.Pack(files)
	if err != nil || len(bundle) > qa.MaxBundleBytes {
		return w.failQA(ctx, r, "test bundle exceeds 32 MiB or has unsafe paths", nil)
	}
	spec := qa.JobSpec{ID: r.ID.String(), Kind: r.Kind, BaseURL: profile.BaseURL, Env: profile.Environment, Threads: profile.Threads, TimeoutSeconds: profile.TimeoutSeconds, Variables: variables}
	if r.Kind == qa.KindPerformance {
		if profile.Perf == nil {
			return w.failQA(ctx, r, "the QA profile has no perf settings", nil)
		}
		perf := profile.Perf.Perf
		spec.Perf = &perf
		spec.Suites = []qa.Suite{{Dir: "repo"}}
		// Load runs last up to the duration plus ramp; allow for start-up.
		spec.TimeoutSeconds = min(7200, max(spec.TimeoutSeconds, perf.DurationSeconds+perf.RampSeconds+300))
	} else {
		if repoFeatures > 0 {
			spec.Suites = append(spec.Suites, qa.Suite{Dir: "repo", Tags: profile.Tags})
		}
		for _, f := range files {
			if strings.HasPrefix(f.Path, "generated/") {
				spec.Suites = append(spec.Suites, qa.Suite{Dir: "generated"})
				break
			}
		}
	}
	if err := spec.Validate(); err != nil {
		return w.failQA(ctx, r, "QA job invalid: "+err.Error(), nil)
	}
	if _, err := w.QARunner.Submit(ctx, spec, bundle); err != nil {
		return w.retryQA(ctx, r, err)
	}
	if r.Kind == qa.KindPerformance {
		step.Delay = 30 * time.Second
	}
	return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, step)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" && v != "." {
			return v
		}
	}
	return ""
}

// pollQA checks a submitted run and ingests its report once finished.
func (w Worker) pollQA(ctx context.Context, r assessments.QARun) error {
	status, err := w.QARunner.Status(ctx, r.ID.String())
	if errors.Is(err, qa.ErrUnknownJob) {
		// The runner restarted or pruned the job: submit again.
		return w.retryQA(ctx, r, errors.New("runner no longer knows the job; resubmitting"))
	}
	profileTimeout := 2 * time.Hour
	if p, perr := w.Store.QAProfileFor(ctx, r.AssetID); perr == nil {
		profileTimeout = time.Duration(p.TimeoutSeconds) * time.Second
		if p.Perf != nil && r.Kind == qa.KindPerformance {
			profileTimeout = max(profileTimeout, time.Duration(p.Perf.DurationSeconds+p.Perf.RampSeconds+300)*time.Second)
		}
	}
	since := r.CreatedAt
	if r.SubmittedAt != nil {
		since = *r.SubmittedAt
	}
	overdue := time.Since(since) > profileTimeout+30*time.Minute
	if err != nil {
		if overdue {
			return w.failQA(ctx, r, "runner unreachable until the run's deadline: "+err.Error(), nil)
		}
		return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, assessments.QAStep{Status: r.Status, Delay: 30 * time.Second, Error: err.Error()})
	}
	if !qa.Finished(status.State) {
		if overdue {
			_ = w.QARunner.Delete(ctx, r.ID.String())
			return w.failQA(ctx, r, "the runner did not finish before the run's deadline", nil)
		}
		next := assessments.QAStep{Status: r.Status, Delay: 10 * time.Second, Started: status.StartedAt}
		if status.State == qa.StateRunning {
			next.Status = "running"
		}
		if r.Kind == qa.KindPerformance {
			next.Delay = 30 * time.Second
		}
		return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, next)
	}
	if status.ReportSHA256 == "" {
		message := status.Error
		if message == "" {
			message = "runner finished without a report (state " + status.State + ")"
		}
		_ = w.QARunner.Delete(ctx, r.ID.String())
		return w.failQA(ctx, r, message, nil)
	}
	archive, err := w.QARunner.Report(ctx, r.ID.String(), status.ReportSHA256)
	if err != nil {
		return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, assessments.QAStep{Status: r.Status, Delay: 30 * time.Second, Error: err.Error()})
	}
	key, digest, err := w.QAReports.PutQAReport(ctx, archive)
	if err != nil {
		return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, assessments.QAStep{Status: r.Status, Delay: 30 * time.Second, Error: "report storage failed"})
	}
	report, err := qa.ParseReport(archive)
	if err != nil {
		_ = w.QARunner.Delete(ctx, r.ID.String())
		return w.Store.FinishQARun(context.WithoutCancel(ctx), r, assessments.QAOutcome{Status: qa.StateError, Error: "report unreadable: " + err.Error(), ReportKey: key, ReportSHA256: digest})
	}
	outcome := qaOutcome(r, status, report)
	outcome.ReportKey, outcome.ReportSHA256 = key, digest
	if err := w.Store.FinishQARun(context.WithoutCancel(ctx), r, outcome); err != nil {
		return err
	}
	if err := w.QARunner.Delete(ctx, r.ID.String()); err != nil {
		w.Logger.Warn("runner job not removed; it expires with the runner's retention", "qa_run_id", r.ID, "error", err)
	}
	return nil
}

var severityScore = map[string]int{"critical": 60, "high": 45, "medium": 25, "low": 10}

// scenarioSeverity reads a @severity=<level> tag; failures default to medium.
func scenarioSeverity(tags []string) string {
	for _, t := range tags {
		if level, ok := strings.CutPrefix(strings.ToLower(t), "severity="); ok {
			if _, known := severityScore[level]; known {
				return level
			}
		}
	}
	return "medium"
}

// qaOutcome turns a finished runner job and its report into a run outcome:
// API coverage and the qa_failure, qa_untested, qa_performance and
// qa_config findings, with the finding types this run re-evaluated.
func qaOutcome(r assessments.QARun, status qa.JobStatus, report qa.Report) assessments.QAOutcome {
	o := assessments.QAOutcome{Status: status.State, Error: status.Error, Report: &report}
	if o.Status == qa.StateCancelled {
		o.Status = qa.StateError
		o.Error = firstNonEmpty(o.Error, "the runner cancelled the job")
	}
	ran := o.Status == qa.StatePassed || o.Status == qa.StateFailed
	meta := func(extra map[string]any) json.RawMessage {
		base := map[string]any{"qa_run_id": r.ID.String(), "commit": r.Commit, "base_url": r.BaseURL}
		for k, v := range extra {
			base[k] = v
		}
		data, _ := json.Marshal(base)
		return data
	}
	if r.Coverage != nil {
		for i, problem := range r.Coverage.Problems {
			o.Findings = append(o.Findings, configFinding(r, fmt.Sprintf("setup-%d", i), problem))
		}
	}
	if r.Kind == qa.KindPerformance {
		if ran && report.Perf != nil {
			o.Closes = []string{"qa_performance"}
			for _, a := range report.Perf.Assertions {
				if a.Passed {
					continue
				}
				o.Findings = append(o.Findings, assessments.Finding{Type: "qa_performance", AdvisoryID: "SCRS-QA-PERFORMANCE", Title: clipTitle("Load threshold breached: " + a.Description), Severity: "medium", Score: severityScore["medium"], Component: assessments.Component{Name: a.Description, Path: "performance#" + a.Description}, Evidence: meta(map[string]any{"assertion": a, "stats": report.Perf}), Guidance: json.RawMessage(`{"summary":"Profile the slow or failing endpoints under load, or adjust perf thresholds if the target changed.","automatic_changes":false}`)})
			}
		}
		return o
	}
	if !ran {
		return o
	}
	o.Closes = []string{"qa_failure", "qa_config"}
	for _, s := range report.Scenarios {
		if s.Status != "failed" {
			continue
		}
		severity := scenarioSeverity(s.Tags)
		o.Findings = append(o.Findings, assessments.Finding{Type: "qa_failure", AdvisoryID: "SCRS-QA-FAILURE", Title: clipTitle("QA scenario failed: " + s.Name), Severity: severity, Score: severityScore[severity], Component: assessments.Component{Name: s.Name, Path: s.Suite + "/" + s.Feature + "#" + s.Name}, Evidence: meta(map[string]any{"suite": s.Suite, "feature": s.Feature, "scenario": s.Name, "line": s.Line, "tags": s.Tags, "error": s.Error}), Guidance: json.RawMessage(`{"summary":"Reproduce the scenario against the target; fix the API or update the test if the contract changed.","automatic_changes":false}`)})
	}
	if len(r.Operations) > 0 {
		coverage := qa.Cover(r.Operations, r.BasePaths, r.BaseURL, report.Calls)
		o.Coverage = &coverage
		o.Closes = append(o.Closes, "qa_untested")
		spec := ""
		if r.Coverage != nil {
			spec = r.Coverage.Spec
		}
		for _, op := range coverage.Operations {
			if op.Hits > 0 || op.Deprecated {
				continue
			}
			o.Findings = append(o.Findings, assessments.Finding{Type: "qa_untested", AdvisoryID: "SCRS-QA-UNTESTED", Title: clipTitle("API operation has no test traffic: " + op.Key()), Severity: "low", Score: severityScore["low"], Component: assessments.Component{Name: op.Key(), Path: spec + "#" + op.Key()}, Evidence: meta(map[string]any{"operation": op.Key(), "operation_id": op.OperationID, "spec": spec}), Guidance: json.RawMessage(`{"summary":"Add a Karate scenario for this operation, or generate a draft with POST /assets/{id}/qa/generations.","automatic_changes":false}`)})
		}
	}
	sort.SliceStable(o.Findings, func(i, j int) bool { return o.Findings[i].Type < o.Findings[j].Type })
	return o
}

func clipTitle(s string) string {
	if len(s) > 240 {
		return s[:240]
	}
	return s
}
