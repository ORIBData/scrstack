package qa

import (
	"os"
	"strings"
	"testing"
)

func TestParseRuff(t *testing.T) {
	data := []byte(`[{"cell":null,"code":"F401","end_location":{"column":10,"row":1},"filename":"/work/ab/bundle/src/app/main.py","fix":{"applicability":"safe","edits":[]},"location":{"column":8,"row":1},"message":"` + "`os`" + ` imported but unused","url":"x"},
 {"cell":null,"code":"F821","filename":"/work/ab/bundle/src/app/main.py","fix":null,"location":{"column":1,"row":9},"message":"Undefined name x"},
 {"cell":null,"code":null,"filename":"/work/ab/bundle/src/bad.py","fix":null,"location":{"column":2,"row":3},"message":"SyntaxError: invalid syntax"}]`)
	issues, err := ParseRuff(data)
	if err != nil || len(issues) != 3 {
		t.Fatal(issues, err)
	}
	if issues[0].Path != "app/main.py" || issues[0].Severity != "low" || !issues[0].Fixable || issues[0].Line != 1 {
		t.Fatalf("%+v", issues[0])
	}
	if issues[1].Severity != "medium" || issues[1].Fixable {
		t.Fatalf("%+v", issues[1])
	}
	if issues[2].Rule != "syntax-error" || issues[2].Severity != "high" {
		t.Fatalf("%+v", issues[2])
	}
	// ruff 0.17 reports a syntax error with its own code and marks every
	// rule "severity":"error", so the severity here comes from the rule.
	real := []byte(`[{"cell":null,"code":"invalid-syntax","end_location":{"column":8,"row":3},"filename":"/work/j/bundle/src/app/main.py","fix":null,"location":{"column":7,"row":3},"message":"Expected a parameter or the end of the parameter list","name":"invalid-syntax","noqa_row":null,"severity":"error","url":null},{"cell":null,"code":"F401","filename":"/work/j/bundle/src/app/main.py","fix":{"applicability":"safe","edits":[],"message":"Remove unused import: os"},"location":{"column":8,"row":1},"message":"os imported but unused","severity":"error","url":"x"}]`)
	if got, err := ParseRuff(real); err != nil || len(got) != 2 || got[0].Severity != "high" || got[0].Rule != "invalid-syntax" || got[1].Severity != "low" || !got[1].Fixable {
		t.Fatal(got, err)
	}
	if _, err := ParseRuff([]byte(`{"not":"a list"}`)); err == nil {
		t.Fatal("object accepted")
	}
	if issues, err := ParseRuff([]byte(`[]`)); err != nil || len(issues) != 0 {
		t.Fatal(issues, err)
	}
}

func TestParseGolangci(t *testing.T) {
	data := []byte(`{"Issues":[{"FromLinter":"errcheck","Text":"Error return value is not checked","Severity":"","SourceLines":["secret := x"],"Pos":{"Filename":"internal/a/a.go","Offset":10,"Line":12,"Column":3}},
 {"FromLinter":"misspell","Text":"typo","Severity":"","Pos":{"Filename":"b.go","Line":1,"Column":1},"Replacement":{"NewLines":["x"]}}],"Report":{}}`)
	issues, err := ParseGolangci(data)
	if err != nil || len(issues) != 2 {
		t.Fatal(issues, err)
	}
	if issues[0].Severity != "medium" || issues[0].Path != "internal/a/a.go" || issues[0].Rule != "errcheck" {
		t.Fatalf("%+v", issues[0])
	}
	if issues[1].Severity != "low" || !issues[1].Fixable {
		t.Fatalf("%+v", issues[1])
	}
	if issues, err := ParseGolangci([]byte(`{"Issues":null}`)); err != nil || len(issues) != 0 {
		t.Fatal(issues, err)
	}
}

func TestParseESLint(t *testing.T) {
	data := []byte(`[{"filePath":"/work/ab/bundle/src/web/a.ts","messages":[{"ruleId":"no-unused-vars","severity":2,"message":"x is unused","line":4,"column":7},{"ruleId":"semi","severity":1,"message":"Missing semicolon","line":5,"column":2,"fix":{"range":[1,2],"text":";"}},{"ruleId":null,"severity":2,"fatal":true,"message":"Parsing error","line":1,"column":1}]},{"filePath":"/work/ab/bundle/src/ok.js","messages":[]}]`)
	issues, err := ParseESLint(data)
	if err != nil || len(issues) != 3 {
		t.Fatal(issues, err)
	}
	if issues[0].Severity != "medium" || issues[0].Path != "web/a.ts" {
		t.Fatalf("%+v", issues[0])
	}
	if issues[1].Severity != "low" || !issues[1].Fixable {
		t.Fatalf("%+v", issues[1])
	}
	if issues[2].Rule != "parse-error" || issues[2].Severity != "high" {
		t.Fatalf("%+v", issues[2])
	}
}

func TestLintSpecValidation(t *testing.T) {
	ok := JobSpec{ID: "11111111-2222-4333-8444-555555555555", Kind: KindLint, Threads: 1, TimeoutSeconds: 300, Lint: &Lint{Tools: []string{"ruff"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*JobSpec){
		"no lint settings": func(s *JobSpec) { s.Lint = nil },
		"unknown tool":     func(s *JobSpec) { s.Lint = &Lint{Tools: []string{"rm"}} },
		"duplicate tool":   func(s *JobSpec) { s.Lint = &Lint{Tools: []string{"ruff", "ruff"}} },
		"suites":           func(s *JobSpec) { s.Suites = []Suite{{Dir: "repo"}} },
		"variables":        func(s *JobSpec) { s.Variables = map[string]string{"A": "b"} },
		"base url":         func(s *JobSpec) { s.BaseURL = "https://x.example.com" },
	} {
		bad := ok
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	other := JobSpec{ID: ok.ID, Kind: KindFunctional, BaseURL: "https://x.example.com", Threads: 1, TimeoutSeconds: 300, Suites: []Suite{{Dir: "repo"}}, Lint: &Lint{Tools: []string{"ruff"}}}
	if other.Validate() == nil {
		t.Fatal("lint settings on a functional job accepted")
	}
}

func TestParseLintReport(t *testing.T) {
	outputs := map[string][]byte{"ruff": []byte(`[{"code":"F401","filename":"/w/j/bundle/src/a.py","fix":null,"location":{"row":2,"column":1},"message":"unused"}]`), "eslint": []byte(`not json`)}
	exit := 1
	metas := map[string]LintMeta{
		"ruff":          {Tool: "ruff", Status: "ran", Exit: &exit},
		"eslint":        {Tool: "eslint", Status: "ran", Exit: &exit},
		"golangci-lint": {Tool: "golangci-lint", Status: "unavailable", Error: "not installed"},
	}
	r := parseLint(outputs, metas)
	if len(r.Issues) != 1 || len(r.Tools) != 3 {
		t.Fatalf("%+v", r)
	}
	byTool := map[string]LintToolResult{}
	for _, tr := range r.Tools {
		byTool[tr.Tool] = tr
	}
	if byTool["eslint"].Status != "error" || byTool["golangci-lint"].Status != "unavailable" || byTool["ruff"].Issues != 1 {
		t.Fatalf("%+v", byTool)
	}
	if s := r.Summarize(); s.Issues != 1 || s.Files != 1 || s.ByTool["ruff"] != 1 || s.BySeverity["low"] != 1 {
		t.Fatalf("%+v", s)
	}
}

// The fixtures in testdata/lint are the unedited output of the pinned tools
// (golangci-lint 2.15.0, ESLint 9, ktlint 1.8.0, SwiftLint 0.65.1 static and
// Dart 3.14) on small projects with deliberate problems.
func TestParseRealToolOutput(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile("testdata/lint/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	golangci, err := ParseGolangci(read("golangci.json"))
	if err != nil || len(golangci) != 1 || golangci[0].Rule != "errcheck" || golangci[0].Path != "main.go" || golangci[0].Line != 11 || golangci[0].Severity != "medium" {
		t.Fatal(golangci, err)
	}
	eslint, err := ParseESLint(read("eslint.json"))
	if err != nil || len(eslint) < 3 {
		t.Fatal(eslint, err)
	}
	rules := map[string]LintIssue{}
	for _, i := range eslint {
		rules[i.Rule] = i
	}
	if rules["no-unused-vars"].Severity != "medium" || rules["semi"].Severity != "low" || !rules["semi"].Fixable || rules["semi"].Path != "ts/app.js" && rules["semi"].Path != "/s/ts/app.js" && rules["semi"].Path == "" {
		t.Fatalf("%+v", rules)
	}
	ktlint, err := ParseKtlint(read("ktlint.json"))
	if err != nil || len(ktlint) != 4 || ktlint[0].Rule != "standard:no-wildcard-imports" || ktlint[0].Path != "Main.kt" || ktlint[1].Line != 4 || ktlint[1].Column != 10 {
		t.Fatal(ktlint, err)
	}
	swift, err := ParseSwiftLint(read("swiftlint.json"))
	if err != nil || len(swift) != 3 || swift[0].Rule != "force_cast" || swift[0].Severity != "medium" || swift[0].Line != 3 || swift[0].Column != 11 {
		t.Fatal(swift, err)
	}
	if empty, err := ParseSwiftLint([]byte("  \n")); err != nil || len(empty) != 0 {
		t.Fatal("swiftlint prints nothing when clean", empty, err)
	}
	dart, err := ParseDartAnalyze(read("dart.json"))
	if err != nil || len(dart) != 2 {
		t.Fatal(dart, err)
	}
	if dart[0].Rule != "undefined_identifier" || dart[0].Severity != "high" || dart[0].Line != 4 || dart[1].Rule != "unused_local_variable" || dart[1].Severity != "medium" {
		t.Fatalf("%+v", dart)
	}
	for _, bad := range []func([]byte) ([]LintIssue, error){ParseKtlint, ParseSwiftLint, ParseDartAnalyze} {
		if _, err := bad([]byte(`{"x":`)); err == nil {
			t.Fatal("garbage accepted")
		}
	}
}

func TestParsePythonTools(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile("testdata/lint/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	mypy, err := ParseMypy(read("mypy.json"))
	if err != nil || len(mypy) != 2 || mypy[0].Rule != "return-value" || mypy[0].Severity != "medium" || mypy[0].Path != "app/main.py" || mypy[0].Line != 18 || mypy[0].Column != 12 {
		t.Fatal(mypy, err)
	}
	if empty, err := ParseMypy(nil); err != nil || len(empty) != 0 {
		t.Fatal("mypy prints nothing when clean", empty, err)
	}
	if notes, err := ParseMypy([]byte(`{"file":"a.py","line":1,"column":0,"message":"see","code":null,"severity":"note"}`)); err != nil || len(notes) != 0 {
		t.Fatal("notes are not issues", notes, err)
	}
	if syntax, _ := ParseMypy([]byte(`{"file":"a.py","line":1,"column":1,"message":"bad","code":"syntax","severity":"error"}`)); len(syntax) != 1 || syntax[0].Severity != "high" {
		t.Fatal(syntax)
	}
	if _, err := ParseMypy([]byte("usage: mypy [-h]")); err == nil {
		t.Fatal("text that is not JSON lines is an error")
	}
	bandit, err := ParseBandit(read("bandit.json"))
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]LintIssue{}
	for _, i := range bandit {
		byRule[i.Rule] = i
	}
	if byRule["B602"].Severity != "high" || byRule["B602"].Path != "app/main.py" || !strings.Contains(byRule["B602"].Message, "CWE-78") || byRule["B404"].Severity != "low" || byRule["not-scanned"].Path != "app/broken.py" || byRule["not-scanned"].Severity != "medium" {
		t.Fatalf("%+v", byRule)
	}
	pylint, err := ParsePylint(read("pylint.json"))
	if err != nil || len(pylint) < 5 {
		t.Fatal(pylint, err)
	}
	sym := map[string]LintIssue{}
	for _, i := range pylint {
		sym[i.Rule] = i
	}
	if sym["syntax-error"].Severity != "high" || sym["syntax-error"].Path != "app/broken.py" || sym["bare-except"].Severity != "low" || sym["unused-import"].Path != "app/main.py" || sym["unused-import"].Line == 0 {
		t.Fatalf("%+v", sym)
	}
}

func TestParsePHPAndCTools(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile("testdata/lint/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	stan, err := ParsePHPStan(read("phpstan.json"))
	if err != nil || len(stan) != 4 || stan[0].Rule != "argument.type" || stan[0].Severity != "medium" || stan[0].Path != "php/app.php" || stan[0].Line != 7 {
		t.Fatal(stan, err)
	}
	syntax, err := ParsePHPStan(read("phpstan-syntax.json"))
	if err != nil || len(syntax) != 1 || syntax[0].Severity != "high" || syntax[0].Path != "php/broken.php" {
		t.Fatal(syntax, err)
	}
	if clean, err := ParsePHPStan([]byte(`{"totals":{"errors":0,"file_errors":0},"files":[],"errors":[]}`)); err != nil || len(clean) != 0 {
		t.Fatal("a clean run has files as an empty array", clean, err)
	}
	if _, err := ParsePHPStan([]byte(`{"totals":{},"files":[],"errors":["Path /x does not exist"]}`)); err == nil {
		t.Fatal("errors outside files mean phpstan did not analyse as asked")
	}
	cs, err := ParsePHPCS(read("phpcs.json"))
	if err != nil || len(cs) < 5 {
		t.Fatal(cs, err)
	}
	fixable := 0
	for _, i := range cs {
		if i.Severity != "low" || !strings.HasPrefix(i.Path, "php/") || i.Tool != "phpcs" {
			t.Fatalf("%+v", i)
		}
		if i.Fixable {
			fixable++
		}
	}
	if fixable == 0 {
		t.Fatal("phpcs marks fixable findings")
	}
	if clean, err := ParsePHPCS([]byte(`{"totals":{"errors":0,"warnings":0,"fixable":0},"files":[]}`)); err != nil || len(clean) != 0 {
		t.Fatal(clean, err)
	}
	tidy, err := ParseClangTidy(read("clang-tidy.txt"))
	if err != nil || len(tidy) != 2 {
		t.Fatal(tidy, err)
	}
	if tidy[0].Rule != "clang-analyzer-unix.Malloc" || tidy[0].Severity != "medium" || tidy[0].Path != "c/main.c" || tidy[0].Line != 7 || tidy[0].Column != 12 || tidy[1].Rule != "clang-analyzer-core.NullDereference" {
		t.Fatalf("%+v", tidy)
	}
	if n := ClangTidyMissingIncludes(read("clang-tidy.txt")); n != 1 {
		t.Fatal("a header that is not found is counted, not reported as an issue", n)
	}
}
