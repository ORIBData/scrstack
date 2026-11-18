package qa

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// KindLint runs linters over the repository's source at the assessed commit.
// It needs no deployed target: the runner never starts the code.
const KindLint = "lint"

// LintTools are the linters a job may name, with what each covers. The
// runner runs only the ones installed on its image.
var LintTools = map[string]string{
	"ruff":          "Python style and errors",
	"mypy":          "Python types",
	"bandit":        "Python security",
	"pylint":        "Python code quality",
	"phpstan":       "PHP static analysis",
	"phpcs":         "PHP code style",
	"clang-tidy":    "C and C++",
	"golangci-lint": "Go",
	"eslint":        "JavaScript and TypeScript",
	"ktlint":        "Kotlin",
	"swiftlint":     "Swift",
	"dart-analyze":  "Dart and Flutter",
}

// LintExecutable is the command a tool runs as when it is not the tool's
// own name: `dart analyze` is the dart executable.
func LintExecutable(tool string) string {
	if tool == "dart-analyze" {
		return "dart"
	}
	return tool
}

// Lint selects the linters of a lint job.
type Lint struct {
	Tools []string `json:"tools"`
}

// Validate checks the tool names: one to all known tools, no repeats.
func (l Lint) Validate() error {
	if len(l.Tools) == 0 || len(l.Tools) > len(LintTools) {
		return errors.New("lint.tools lists one to " + fmt.Sprint(len(LintTools)) + " linters")
	}
	seen := map[string]bool{}
	for _, t := range l.Tools {
		if _, ok := LintTools[t]; !ok || seen[t] {
			return fmt.Errorf("lint tool %q must be one of %s, listed once", t, strings.Join(LintToolNames(), ", "))
		}
		seen[t] = true
	}
	return nil
}

// LintToolNames lists the known tools in order.
func LintToolNames() []string {
	names := make([]string, 0, len(LintTools))
	for n := range LintTools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// LintIssue is one linter finding. Message is the tool's own text; no
// source lines are kept.
type LintIssue struct {
	Tool     string `json:"tool"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Column   int    `json:"column,omitempty"`
	Message  string `json:"message"`
	Fixable  bool   `json:"fixable,omitempty"`
}

// LintToolResult says what happened to one requested linter. Status is
// "ran", "unavailable" (not installed on the runner) or "error" (it could
// not produce a result).
type LintToolResult struct {
	Tool   string `json:"tool"`
	Status string `json:"status"`
	Issues int    `json:"issues"`
	Error  string `json:"error,omitempty"`
	// Note says the result may be incomplete, for example when the project's
	// dependencies could not be installed so the linter could not resolve them.
	Note string `json:"note,omitempty"`
}

// LintReport is what SCRS reads from a lint job.
type LintReport struct {
	Tools     []LintToolResult `json:"tools"`
	Issues    []LintIssue      `json:"issues"`
	Truncated bool             `json:"truncated,omitempty"`
}

// LintSummary counts a lint run's issues.
type LintSummary struct {
	Issues     int            `json:"issues"`
	Files      int            `json:"files"`
	ByTool     map[string]int `json:"by_tool"`
	BySeverity map[string]int `json:"by_severity"`
}

// MaxLintIssues bounds the issues kept per run.
const MaxLintIssues = 5000

// Summarize counts a report's issues.
func (r LintReport) Summarize() LintSummary {
	s := LintSummary{ByTool: map[string]int{}, BySeverity: map[string]int{}}
	files := map[string]bool{}
	for _, i := range r.Issues {
		s.Issues++
		s.ByTool[i.Tool]++
		s.BySeverity[i.Severity]++
		files[i.Path] = true
	}
	s.Files = len(files)
	return s
}

// srcMarker is where a job's source tree starts inside the absolute paths
// some linters print: <workdir>/<job>/bundle/src/<path>.
const srcMarker = "/bundle/src/"

// relPath makes a linter's file name relative to the repository.
func relPath(p string) string {
	if i := strings.Index(p, srcMarker); i >= 0 {
		p = p[i+len(srcMarker):]
	}
	return clipText(strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./"), 512)
}

// ruffSeverity: rules that usually mean a runtime error are medium; style
// and convention rules are low.
func ruffSeverity(code string) string {
	if code == "invalid-syntax" {
		return "high"
	}
	for _, prefix := range []string{"E9", "F63", "F7", "F82", "PLE"} {
		if strings.HasPrefix(code, prefix) {
			return "medium"
		}
	}
	return "low"
}

// ParseRuff reads `ruff check --output-format json`.
func ParseRuff(data []byte) ([]LintIssue, error) {
	var in []struct {
		Code     string `json:"code"`
		Message  string `json:"message"`
		Filename string `json:"filename"`
		Location struct {
			Row    int `json:"row"`
			Column int `json:"column"`
		} `json:"location"`
		Fix json.RawMessage `json:"fix"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("ruff output is not the expected JSON")
	}
	out := make([]LintIssue, 0, len(in))
	for _, i := range in {
		rule := i.Code
		if rule == "" {
			rule = "syntax-error"
		}
		sev := ruffSeverity(rule)
		if i.Code == "" {
			sev = "high"
		}
		out = append(out, LintIssue{Tool: "ruff", Rule: rule, Severity: sev, Path: relPath(i.Filename), Line: i.Location.Row, Column: i.Location.Column, Message: clipText(i.Message, 500), Fixable: len(i.Fix) > 0 && string(i.Fix) != "null"})
	}
	return out, nil
}

// mypySeverity: a syntax error stops mypy and is high; a type error is medium.
func mypySeverity(code string) string {
	if code == "syntax" {
		return "high"
	}
	return "medium"
}

// ParseMypy reads `mypy --output json`, one JSON object per line. Notes
// (follow-up lines of an error) are not issues.
func ParseMypy(data []byte) ([]LintIssue, error) {
	out := []LintIssue{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var i struct {
			File     string `json:"file"`
			Line     int    `json:"line"`
			Column   int    `json:"column"`
			Message  string `json:"message"`
			Code     string `json:"code"`
			Severity string `json:"severity"`
		}
		if err := json.Unmarshal([]byte(line), &i); err != nil || i.File == "" {
			return nil, errors.New("mypy output is not the expected JSON lines")
		}
		if i.Severity != "error" {
			continue
		}
		rule := i.Code
		if rule == "" {
			rule = "error"
		}
		// mypy columns are zero-based.
		out = append(out, LintIssue{Tool: "mypy", Rule: rule, Severity: mypySeverity(i.Code), Path: relPath(i.File), Line: i.Line, Column: i.Column + 1, Message: clipText(i.Message, 500)})
	}
	return out, nil
}

// ParseBandit reads `bandit -f json`. Bandit's own severity is kept. A file
// it could not parse is an issue too, because the security scan skipped it.
func ParseBandit(data []byte) ([]LintIssue, error) {
	var in struct {
		Results []struct {
			Filename string `json:"filename"`
			Line     int    `json:"line_number"`
			Column   int    `json:"col_offset"`
			Severity string `json:"issue_severity"`
			Text     string `json:"issue_text"`
			TestID   string `json:"test_id"`
			CWE      struct {
				ID int `json:"id"`
			} `json:"issue_cwe"`
		} `json:"results"`
		Errors []struct {
			Filename string `json:"filename"`
			Reason   string `json:"reason"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("bandit output is not the expected JSON")
	}
	out := make([]LintIssue, 0, len(in.Results)+len(in.Errors))
	for _, r := range in.Results {
		sev := strings.ToLower(r.Severity)
		if sev != "high" && sev != "medium" {
			sev = "low"
		}
		msg := r.Text
		if r.CWE.ID > 0 {
			msg += " (CWE-" + fmt.Sprint(r.CWE.ID) + ")"
		}
		out = append(out, LintIssue{Tool: "bandit", Rule: r.TestID, Severity: sev, Path: relPath(r.Filename), Line: r.Line, Column: r.Column + 1, Message: clipText(msg, 500)})
	}
	for _, e := range in.Errors {
		out = append(out, LintIssue{Tool: "bandit", Rule: "not-scanned", Severity: "medium", Path: relPath(e.Filename), Message: clipText("bandit skipped this file: "+e.Reason, 500)})
	}
	return out, nil
}

// pylintSeverity: fatal errors and syntax errors are high, errors medium;
// warnings, refactor hints and conventions are low.
func pylintSeverity(kind, symbol string) string {
	switch {
	case kind == "fatal" || symbol == "syntax-error":
		return "high"
	case kind == "error":
		return "medium"
	}
	return "low"
}

// ParsePylint reads `pylint --output-format=json2`.
func ParsePylint(data []byte) ([]LintIssue, error) {
	var in struct {
		Messages []struct {
			Type    string `json:"type"`
			Symbol  string `json:"symbol"`
			Message string `json:"message"`
			Path    string `json:"path"`
			Line    int    `json:"line"`
			Column  int    `json:"column"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("pylint output is not the expected JSON")
	}
	out := make([]LintIssue, 0, len(in.Messages))
	for _, m := range in.Messages {
		out = append(out, LintIssue{Tool: "pylint", Rule: m.Symbol, Severity: pylintSeverity(m.Type, m.Symbol), Path: relPath(m.Path), Line: m.Line, Column: m.Column + 1, Message: clipText(m.Message, 500)})
	}
	return out, nil
}

// ParsePHPStan reads `phpstan analyse --error-format=json`. Errors that
// belong to no file (a bad configuration, a missing path) mean PHPStan did
// not analyse as asked, so they are an error of the tool, not issues.
func ParsePHPStan(data []byte) ([]LintIssue, error) {
	var in struct {
		Files  json.RawMessage `json:"files"`
		Errors []string        `json:"errors"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("phpstan output is not the expected JSON")
	}
	if len(in.Errors) > 0 {
		return nil, errors.New("phpstan reported: " + clipText(in.Errors[0], 300))
	}
	// PHP encodes "no files" as [] and a populated map as an object.
	var files map[string]struct {
		Messages []struct {
			Message    string `json:"message"`
			Line       int    `json:"line"`
			Identifier string `json:"identifier"`
		} `json:"messages"`
	}
	if len(in.Files) > 0 && in.Files[0] == '{' {
		if err := json.Unmarshal(in.Files, &files); err != nil {
			return nil, errors.New("phpstan output is not the expected JSON")
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []LintIssue{}
	for _, name := range names {
		for _, m := range files[name].Messages {
			rule, sev := m.Identifier, "medium"
			if rule == "" {
				rule = "phpstan"
			}
			if rule == "phpstan.parse" {
				sev = "high"
			}
			out = append(out, LintIssue{Tool: "phpstan", Rule: rule, Severity: sev, Path: relPath(name), Line: m.Line, Message: clipText(m.Message, 500)})
		}
	}
	return out, nil
}

// ParsePHPCS reads `phpcs --report=json`. It checks a coding standard, so
// every finding is low, except a file phpcs could not read.
func ParsePHPCS(data []byte) ([]LintIssue, error) {
	var in struct {
		Files json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("phpcs output is not the expected JSON")
	}
	var files map[string]struct {
		Messages []struct {
			Message string `json:"message"`
			Source  string `json:"source"`
			Fixable bool   `json:"fixable"`
			Line    int    `json:"line"`
			Column  int    `json:"column"`
		} `json:"messages"`
	}
	if len(in.Files) > 0 && in.Files[0] == '{' {
		if err := json.Unmarshal(in.Files, &files); err != nil {
			return nil, errors.New("phpcs output is not the expected JSON")
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []LintIssue{}
	for _, name := range names {
		for _, m := range files[name].Messages {
			sev := "low"
			if strings.HasPrefix(m.Source, "Internal.") && strings.HasSuffix(m.Source, "Exception") {
				sev = "medium"
			}
			out = append(out, LintIssue{Tool: "phpcs", Rule: m.Source, Severity: sev, Path: relPath(name), Line: m.Line, Column: m.Column, Message: clipText(m.Message, 500), Fixable: m.Fixable})
		}
	}
	return out, nil
}

// clangLine is one clang-tidy diagnostic: path:line:col: warning: text [check].
// Notes, which explain the path to a warning, are not matched.
var clangLine = regexp.MustCompile(`^(.+?):(\d+):(\d+): (warning|error): (.*) \[([A-Za-z0-9_.,-]+)\]$`)

// ParseClangTidy reads clang-tidy's text output. An include that cannot be
// found is not an issue with the code (the dependency is not installed); see
// ClangTidyMissingIncludes.
func ParseClangTidy(data []byte) ([]LintIssue, error) {
	out := []LintIssue{}
	for _, line := range strings.Split(string(data), "\n") {
		m := clangLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil || missingInclude(m[5]) {
			continue
		}
		ln, col := atoi(m[2]), atoi(m[3])
		out = append(out, LintIssue{Tool: "clang-tidy", Rule: m[6], Severity: clangSeverity(m[4], m[6]), Path: relPath(m[1]), Line: ln, Column: col, Message: clipText(m[5], 500)})
	}
	return out, nil
}

func missingInclude(msg string) bool { return strings.HasSuffix(msg, "file not found") }

// ClangTidyMissingIncludes counts the diagnostics that say an included header
// could not be found. The analysis of those files stops at the include.
func ClangTidyMissingIncludes(data []byte) int {
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if m := clangLine.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil && missingInclude(m[5]) {
			n++
		}
	}
	return n
}

// clangSeverity: the static analyzer and bugprone checks point at probable
// bugs and a compile error stops the analysis of the file (medium); the rest
// is low.
func clangSeverity(kind, check string) string {
	switch {
	case strings.HasPrefix(check, "clang-analyzer-"), strings.HasPrefix(check, "bugprone-"), strings.HasPrefix(check, "cert-"), kind == "error":
		return "medium"
	}
	return "low"
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// golangciMedium names the linters whose findings point at probable bugs.
var golangciMedium = map[string]bool{"govet": true, "staticcheck": true, "errcheck": true, "gosec": true, "ineffassign": true, "typecheck": true, "bodyclose": true, "nilerr": true}

// ParseGolangci reads golangci-lint's JSON report (`Issues` array).
func ParseGolangci(data []byte) ([]LintIssue, error) {
	var in struct {
		Issues []struct {
			FromLinter string `json:"FromLinter"`
			Text       string `json:"Text"`
			Severity   string `json:"Severity"`
			Pos        struct {
				Filename string `json:"Filename"`
				Line     int    `json:"Line"`
				Column   int    `json:"Column"`
			} `json:"Pos"`
			Replacement json.RawMessage `json:"Replacement"`
		} `json:"Issues"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("golangci-lint output is not the expected JSON")
	}
	out := make([]LintIssue, 0, len(in.Issues))
	for _, i := range in.Issues {
		sev := "low"
		switch strings.ToLower(i.Severity) {
		case "error", "high":
			sev = "medium"
		}
		if golangciMedium[i.FromLinter] {
			sev = "medium"
		}
		out = append(out, LintIssue{Tool: "golangci-lint", Rule: i.FromLinter, Severity: sev, Path: relPath(i.Pos.Filename), Line: i.Pos.Line, Column: i.Pos.Column, Message: clipText(i.Text, 500), Fixable: len(i.Replacement) > 0 && string(i.Replacement) != "null"})
	}
	return out, nil
}

// ParseESLint reads `eslint -f json`.
func ParseESLint(data []byte) ([]LintIssue, error) {
	var in []struct {
		FilePath string `json:"filePath"`
		Messages []struct {
			RuleID   *string         `json:"ruleId"`
			Severity int             `json:"severity"`
			Message  string          `json:"message"`
			Line     int             `json:"line"`
			Column   int             `json:"column"`
			Fatal    bool            `json:"fatal"`
			Fix      json.RawMessage `json:"fix"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("eslint output is not the expected JSON")
	}
	var out []LintIssue
	for _, f := range in {
		for _, m := range f.Messages {
			rule := "parse-error"
			if m.RuleID != nil && *m.RuleID != "" {
				rule = *m.RuleID
			}
			sev := "low"
			switch {
			case m.Fatal:
				sev = "high"
			case m.Severity >= 2:
				sev = "medium"
			}
			out = append(out, LintIssue{Tool: "eslint", Rule: rule, Severity: sev, Path: relPath(f.FilePath), Line: m.Line, Column: m.Column, Message: clipText(m.Message, 500), Fixable: len(m.Fix) > 0 && string(m.Fix) != "null"})
		}
	}
	return out, nil
}

// ParseKtlint reads `ktlint --reporter=json`. Every rule is a style rule, so
// the severity is low.
func ParseKtlint(data []byte) ([]LintIssue, error) {
	var in []struct {
		File   string `json:"file"`
		Errors []struct {
			Line    int    `json:"line"`
			Column  int    `json:"column"`
			Message string `json:"message"`
			Rule    string `json:"rule"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("ktlint output is not the expected JSON")
	}
	var out []LintIssue
	for _, f := range in {
		for _, e := range f.Errors {
			rule := e.Rule
			if rule == "" {
				rule = "parse-error"
			}
			out = append(out, LintIssue{Tool: "ktlint", Rule: rule, Severity: "low", Path: relPath(f.File), Line: e.Line, Column: e.Column, Message: clipText(e.Message, 500)})
		}
	}
	return out, nil
}

// ParseSwiftLint reads `swiftlint lint --reporter json`.
func ParseSwiftLint(data []byte) ([]LintIssue, error) {
	var in []struct {
		File     string `json:"file"`
		Line     int    `json:"line"`
		Column   int    `json:"character"`
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Reason   string `json:"reason"`
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("swiftlint output is not the expected JSON")
	}
	out := make([]LintIssue, 0, len(in))
	for _, i := range in {
		sev := "low"
		if strings.EqualFold(i.Severity, "error") {
			sev = "medium"
		}
		out = append(out, LintIssue{Tool: "swiftlint", Rule: i.RuleID, Severity: sev, Path: relPath(i.File), Line: i.Line, Column: i.Column, Message: clipText(i.Reason, 500)})
	}
	return out, nil
}

// ParseDartAnalyze reads `dart analyze --format=json`. A compile-time error
// is high, a warning medium, a hint or lint low.
func ParseDartAnalyze(data []byte) ([]LintIssue, error) {
	var in struct {
		Diagnostics []struct {
			Code     string `json:"code"`
			Severity string `json:"severity"`
			Location struct {
				File  string `json:"file"`
				Range struct {
					Start struct {
						Line   int `json:"line"`
						Column int `json:"column"`
					} `json:"start"`
				} `json:"range"`
			} `json:"location"`
			Message string `json:"problemMessage"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, errors.New("dart analyze output is not the expected JSON")
	}
	out := make([]LintIssue, 0, len(in.Diagnostics))
	for _, d := range in.Diagnostics {
		sev := "low"
		switch strings.ToUpper(d.Severity) {
		case "ERROR":
			sev = "high"
		case "WARNING":
			sev = "medium"
		}
		out = append(out, LintIssue{Tool: "dart-analyze", Rule: d.Code, Severity: sev, Path: relPath(d.Location.File), Line: d.Location.Range.Start.Line, Column: d.Location.Range.Start.Column, Message: clipText(d.Message, 500)})
	}
	return out, nil
}

// LintParsers read each tool's raw output file.
var LintParsers = map[string]func([]byte) ([]LintIssue, error){
	"ruff":          ParseRuff,
	"mypy":          ParseMypy,
	"bandit":        ParseBandit,
	"pylint":        ParsePylint,
	"phpstan":       ParsePHPStan,
	"phpcs":         ParsePHPCS,
	"clang-tidy":    ParseClangTidy,
	"golangci-lint": ParseGolangci,
	"eslint":        ParseESLint,
	"ktlint":        ParseKtlint,
	"swiftlint":     ParseSwiftLint,
	"dart-analyze":  ParseDartAnalyze,
}

// LintMeta is the runner's note about one tool run, written beside its
// output as lint/<tool>.meta.json.
type LintMeta struct {
	Tool   string `json:"tool"`
	Status string `json:"status"`
	Exit   *int   `json:"exit,omitempty"`
	Error  string `json:"error,omitempty"`
	Note   string `json:"note,omitempty"`
}
