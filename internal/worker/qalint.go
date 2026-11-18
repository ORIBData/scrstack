package worker

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"context"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/qa"
)

// Lint bundle limits: files and bytes of source sent to the runner.
const (
	maxLintFiles = 20000
	maxLintBytes = 96 << 20
	maxLintFile  = 2 << 20
)

// lintExtensions are the source files each linter reads; lintConfigs are the
// files that configure it or its project.
var (
	lintExtensions = map[string][]string{
		"ruff":          {".py", ".pyi"},
		"mypy":          {".py", ".pyi"},
		"bandit":        {".py"},
		"pylint":        {".py"},
		"phpstan":       {".php", ".phtml", ".inc", ".neon"},
		"phpcs":         {".php", ".phtml", ".inc"},
		"clang-tidy":    {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++", ".ipp"},
		"golangci-lint": {".go"},
		"eslint":        {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue"},
		"ktlint":        {".kt", ".kts"},
		"swiftlint":     {".swift"},
		"dart-analyze":  {".dart"},
	}
	lintConfigs = map[string][]string{
		"ruff":          {"pyproject.toml", "ruff.toml", ".ruff.toml", "setup.cfg"},
		"mypy":          {"pyproject.toml", "mypy.ini", ".mypy.ini", "setup.cfg", "tox.ini"},
		"bandit":        {"pyproject.toml"},
		"pylint":        {"pyproject.toml", ".pylintrc", "pylintrc", "setup.cfg", "tox.ini"},
		"phpstan":       {"composer.json", "composer.lock", "phpstan.neon", "phpstan.neon.dist", "phpstan.dist.neon"},
		"phpcs":         {"composer.json", "phpcs.xml", ".phpcs.xml", "phpcs.xml.dist", ".phpcs.xml.dist", "ruleset.xml"},
		"clang-tidy":    {".clang-tidy"},
		"golangci-lint": {"go.mod", "go.sum", "go.work", ".golangci.yml", ".golangci.yaml", ".golangci.toml", ".golangci.json"},
		"eslint":        {"package.json", "package-lock.json", "tsconfig.json", "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts", "eslint.config.mts", "eslint.config.cts"},
		"ktlint":        {".editorconfig"},
		"swiftlint":     {".swiftlint.yml", ".swiftlint.yaml"},
		"dart-analyze":  {"pubspec.yaml", "pubspec.lock", "analysis_options.yaml"},
	}
)

// lintWanted chooses the files a set of linters needs. node_modules and
// other installed dependency trees are never sent.
func lintWanted(tools []string) func(rel string, size int64) bool {
	ext, names := map[string]bool{}, map[string]bool{}
	for _, t := range tools {
		for _, e := range lintExtensions[t] {
			ext[e] = true
		}
		for _, n := range lintConfigs[t] {
			names[n] = true
		}
	}
	return func(rel string, size int64) bool {
		if size > maxLintFile {
			return false
		}
		for _, part := range strings.Split(rel, "/") {
			if part == "node_modules" || part == ".git" || part == ".dart_tool" || part == "Pods" {
				return false
			}
		}
		base := path.Base(rel)
		return names[base] || ext[strings.ToLower(path.Ext(base))]
	}
}

// lintBundle reads a commit's archive and returns the source files for the
// requested linters, with the number of wanted files that did not fit.
func lintBundle(archive []byte, tools []string) ([]qa.File, int, error) {
	wanted := lintWanted(tools)
	count := 0
	snap, err := qa.ReadSnapshot(archive, func(rel string, size int64) bool {
		ok := wanted(rel, size)
		if ok {
			count++
		}
		return ok
	}, maxLintFiles, maxLintBytes)
	if err != nil {
		return nil, 0, err
	}
	paths := make([]string, 0, len(snap.Files))
	for p := range snap.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	files := make([]qa.File, 0, len(paths))
	for _, p := range paths {
		files = append(files, qa.File{Path: "src/" + p, Data: snap.Files[p]})
	}
	return files, count - len(files), nil
}

// submitLint prepares a lint run's bundle from the assessed commit and
// submits it. Nothing about the deployed target is needed.
func (w Worker) submitLint(ctx context.Context, r assessments.QARun, profile assessments.QAProfile, archive []byte) error {
	if profile.Lint == nil {
		return w.failQA(ctx, r, "the QA profile has no lint settings", nil)
	}
	files, over, err := lintBundle(archive, profile.Lint.Tools)
	if err != nil {
		return w.failQA(ctx, r, "source archive unreadable: "+err.Error(), nil)
	}
	if len(files) == 0 {
		return w.failQA(ctx, r, "the commit has no source files for "+strings.Join(profile.Lint.Tools, ", "), []assessments.Finding{lintConfigFinding(r, "no-source", "No source files for the profile's linters ("+strings.Join(profile.Lint.Tools, ", ")+") at this commit")})
	}
	bundle, err := qa.Pack(files)
	if err != nil || len(bundle) > qa.MaxBundleBytes {
		return w.failQA(ctx, r, "lint bundle exceeds 32 MiB compressed or has unsafe paths; reduce the linters or the source size", []assessments.Finding{lintConfigFinding(r, "too-large", "Source is too large to lint in one bundle (32 MiB compressed)")})
	}
	spec := qa.JobSpec{ID: r.ID.String(), Kind: qa.KindLint, Threads: 1, TimeoutSeconds: profile.TimeoutSeconds, Lint: profile.Lint}
	if err := spec.Validate(); err != nil {
		return w.failQA(ctx, r, "lint job invalid: "+err.Error(), nil)
	}
	if _, err := w.QARunner.Submit(ctx, spec, bundle); err != nil {
		return w.retryQA(ctx, r, err)
	}
	step := assessments.QAStep{Status: "submitted", Delay: 10 * time.Second}
	if over > 0 {
		step.Problems = []string{fmt.Sprintf("%d source file(s) were left out of the lint bundle (over %d files, %d MiB or 2 MiB per file)", over, maxLintFiles, maxLintBytes>>20)}
	}
	return w.Store.AdvanceQARun(context.WithoutCancel(ctx), r, step)
}

// lintConfigFinding is a qa_lint_config entry for a lint setup problem or a
// linter that could not run. It has its own type so a functional run, which
// closes qa_config entries, does not close it.
func lintConfigFinding(r assessments.QARun, key, title string) assessments.Finding {
	evidence, _ := json.Marshal(map[string]string{"problem": title, "qa_run_id": r.ID.String(), "commit": r.Commit})
	return assessments.Finding{Type: "qa_lint_config", AdvisoryID: "SCRS-QA-LINT-CONFIG", Title: clipTitle(title), Severity: "low", Score: severityScore["low"], Component: assessments.Component{Name: key, Path: "lint#" + key}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Fix the QA profile's lint settings, add the missing linter to the runner image, or change the source layout; see QA_TESTING.md.","automatic_changes":false}`)}
}

// lintGroup is the issues of one tool's rule in one file. One register entry
// per group keeps an entry stable when lines move.
type lintGroup struct {
	tool, rule, file string
	severity         string
	issues           []qa.LintIssue
	fixable          bool
}

var lintRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

// lintOutcome turns a lint report into register entries: one qa_lint entry
// for each tool, rule and file, and a qa_lint_config entry for each tool that
// did not run.
func lintOutcome(r assessments.QARun, report qa.Report, ran bool) ([]assessments.Finding, []string) {
	if !ran || report.Lint == nil {
		return nil, nil
	}
	var findings []assessments.Finding
	allRan := len(report.Lint.Tools) > 0
	for _, tr := range report.Lint.Tools {
		allRan = allRan && tr.Status == "ran" && tr.Note == ""
		if tr.Note != "" {
			findings = append(findings, lintConfigFinding(r, tr.Tool+"-incomplete", "Linter "+tr.Tool+" result may be incomplete: "+tr.Note))
		}
		switch tr.Status {
		case "unavailable":
			findings = append(findings, lintConfigFinding(r, tr.Tool, "Linter "+tr.Tool+" is not installed on the QA runner"))
		case "error":
			findings = append(findings, lintConfigFinding(r, tr.Tool, "Linter "+tr.Tool+" could not produce a result: "+tr.Error))
		}
	}
	if report.Lint.Truncated {
		findings = append(findings, lintConfigFinding(r, "issue-limit", fmt.Sprintf("Lint reported more than %d issues; the rest were not recorded", qa.MaxLintIssues)))
	}
	groups := map[string]*lintGroup{}
	var order []string
	for _, i := range report.Lint.Issues {
		key := i.Tool + "\x00" + i.Rule + "\x00" + i.Path
		g := groups[key]
		if g == nil {
			g = &lintGroup{tool: i.Tool, rule: i.Rule, file: i.Path, severity: i.Severity}
			groups[key] = g
			order = append(order, key)
		}
		if lintRank[i.Severity] > lintRank[g.severity] {
			g.severity = i.Severity
		}
		g.fixable = g.fixable || i.Fixable
		g.issues = append(g.issues, i)
	}
	for _, key := range order {
		g := groups[key]
		first := g.issues[0]
		title := fmt.Sprintf("Lint %s %s in %s: %s", g.tool, g.rule, g.file, first.Message)
		if len(g.issues) > 1 {
			title += fmt.Sprintf(" (+%d more)", len(g.issues)-1)
		}
		type location struct {
			Line    int    `json:"line"`
			Column  int    `json:"column,omitempty"`
			Message string `json:"message"`
		}
		var locations []location
		for _, i := range g.issues[:min(len(g.issues), 20)] {
			locations = append(locations, location{i.Line, i.Column, i.Message})
		}
		evidence, _ := json.Marshal(map[string]any{"qa_run_id": r.ID.String(), "commit": r.Commit, "tool": g.tool, "rule": g.rule, "path": g.file, "count": len(g.issues), "fixable": g.fixable, "locations": locations})
		summary := "Fix the reported lines, or configure the rule in the repository's linter configuration."
		if g.fixable {
			summary = "The linter can fix this automatically (for example `ruff check --fix` or `eslint --fix`); review the change before committing."
		}
		guidance, _ := json.Marshal(map[string]any{"summary": summary, "automatic_changes": false})
		findings = append(findings, assessments.Finding{Type: "qa_lint", AdvisoryID: "SCRS-QA-LINT", Title: clipTitle(title), Severity: g.severity, Score: severityScore[g.severity], Component: assessments.Component{Name: g.tool + "/" + g.rule, Path: g.file + "#" + g.tool + "/" + g.rule}, Evidence: evidence, Guidance: guidance})
	}
	// An entry is closed by absence only when every requested linter ran
	// and the issue list is complete; otherwise silence is not a fix.
	closes := []string{"qa_lint_config"}
	if allRan && !report.Lint.Truncated {
		closes = append(closes, "qa_lint")
	}
	return findings, closes
}
