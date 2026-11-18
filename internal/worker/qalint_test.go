package worker

import (
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/google/uuid"
)

func TestLintBundleSelectsSource(t *testing.T) {
	archive, err := qa.Pack([]qa.File{
		{Path: "org-repo-abc/app/main.py", Data: []byte("import os\n")},
		{Path: "org-repo-abc/pyproject.toml", Data: []byte("[tool.ruff]\n")},
		{Path: "org-repo-abc/web/node_modules/lib/index.js", Data: []byte("x")},
		{Path: "org-repo-abc/web/app.ts", Data: []byte("let a = 1")},
		{Path: "org-repo-abc/go.mod", Data: []byte("module x\n")},
		{Path: "org-repo-abc/main.go", Data: []byte("package main\n")},
		{Path: "org-repo-abc/README.md", Data: []byte("docs")},
	})
	if err != nil {
		t.Fatal(err)
	}
	files, over, err := lintBundle(archive, []string{"ruff"})
	if err != nil || over != 0 {
		t.Fatal(files, over, err)
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Path)
	}
	if strings.Join(got, ",") != "src/app/main.py,src/pyproject.toml" {
		t.Fatalf("ruff bundle %v", got)
	}
	files, _, _ = lintBundle(archive, []string{"eslint", "golangci-lint"})
	got = nil
	for _, f := range files {
		got = append(got, f.Path)
	}
	if strings.Join(got, ",") != "src/go.mod,src/main.go,src/web/app.ts" {
		t.Fatalf("eslint and go bundle %v", got)
	}
}

func lintRun() assessments.QARun {
	return assessments.QARun{ID: uuid.New(), Kind: qa.KindLint, Commit: "abc123"}
}

func TestLintOutcomeGroupsAndCloses(t *testing.T) {
	report := qa.Report{Lint: &qa.LintReport{
		Tools: []qa.LintToolResult{{Tool: "ruff", Status: "ran", Issues: 3}},
		Issues: []qa.LintIssue{
			{Tool: "ruff", Rule: "F401", Severity: "low", Path: "a.py", Line: 1, Message: "os unused", Fixable: true},
			{Tool: "ruff", Rule: "F401", Severity: "low", Path: "a.py", Line: 7, Message: "sys unused"},
			{Tool: "ruff", Rule: "F821", Severity: "medium", Path: "a.py", Line: 9, Message: "undefined name"},
		},
	}}
	findings, closes := lintOutcome(lintRun(), report, true)
	if len(findings) != 2 || findings[0].Type != "qa_lint" {
		t.Fatalf("%+v", findings)
	}
	first := findings[0]
	if !strings.Contains(first.Title, "(+1 more)") || first.Component.Path != "a.py#ruff/F401" || first.Severity != "low" {
		t.Fatalf("%+v", first)
	}
	if !strings.Contains(string(first.Evidence), `"count":2`) || !strings.Contains(string(first.Guidance), "--fix") {
		t.Fatalf("%s %s", first.Evidence, first.Guidance)
	}
	if strings.Join(closes, ",") != "qa_lint_config,qa_lint" {
		t.Fatalf("closes %v", closes)
	}
	// The same groups keep the same identity when lines move.
	moved := report
	moved.Lint = &qa.LintReport{Tools: report.Lint.Tools, Issues: []qa.LintIssue{{Tool: "ruff", Rule: "F401", Severity: "low", Path: "a.py", Line: 40, Message: "os unused"}}}
	again, _ := lintOutcome(lintRun(), moved, true)
	if len(again) != 1 || again[0].Component.Path != first.Component.Path || again[0].AdvisoryID != first.AdvisoryID {
		t.Fatalf("%+v", again)
	}
}

func TestLintOutcomeDoesNotCloseWhenAToolDidNotRun(t *testing.T) {
	report := qa.Report{Lint: &qa.LintReport{Tools: []qa.LintToolResult{
		{Tool: "ruff", Status: "ran"},
		{Tool: "eslint", Status: "error", Error: "eslint exited 2"},
		{Tool: "golangci-lint", Status: "unavailable"},
	}}}
	findings, closes := lintOutcome(lintRun(), report, true)
	if len(findings) != 2 || findings[0].Type != "qa_lint_config" {
		t.Fatalf("%+v", findings)
	}
	for _, c := range closes {
		if c == "qa_lint" {
			t.Fatal("qa_lint entries closed although a linter did not run")
		}
	}
	// A run that did not execute records and closes nothing.
	if f, c := lintOutcome(lintRun(), report, false); f != nil || c != nil {
		t.Fatal(f, c)
	}
	// An issue list cut at the limit does not close entries either.
	report.Lint = &qa.LintReport{Tools: []qa.LintToolResult{{Tool: "ruff", Status: "ran"}}, Truncated: true}
	if _, closes := lintOutcome(lintRun(), report, true); strings.Contains(strings.Join(closes, ","), "qa_lint,") || closes[len(closes)-1] == "qa_lint" {
		t.Fatalf("closes %v", closes)
	}
}

func TestLintBundleForMobileTools(t *testing.T) {
	archive, err := qa.Pack([]qa.File{
		{Path: "org-repo-abc/android/app/Main.kt", Data: []byte("fun main() {}\n")},
		{Path: "org-repo-abc/android/build.gradle.kts", Data: []byte("plugins {}\n")},
		{Path: "org-repo-abc/.editorconfig", Data: []byte("root = true\n")},
		{Path: "org-repo-abc/ios/App/View.swift", Data: []byte("import UIKit\n")},
		{Path: "org-repo-abc/ios/Pods/Lib/Lib.swift", Data: []byte("x")},
		{Path: "org-repo-abc/ios/.swiftlint.yml", Data: []byte("disabled_rules: []\n")},
		{Path: "org-repo-abc/flutter/pubspec.yaml", Data: []byte("name: app\n")},
		{Path: "org-repo-abc/flutter/analysis_options.yaml", Data: []byte("include: package:lints/recommended.yaml\n")},
		{Path: "org-repo-abc/flutter/lib/main.dart", Data: []byte("void main() {}\n")},
		{Path: "org-repo-abc/flutter/.dart_tool/package_config.json", Data: []byte("{}")},
	})
	if err != nil {
		t.Fatal(err)
	}
	pick := func(tools ...string) string {
		files, _, err := lintBundle(archive, tools)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range files {
			got = append(got, f.Path)
		}
		return strings.Join(got, ",")
	}
	if got := pick("ktlint"); got != "src/.editorconfig,src/android/app/Main.kt,src/android/build.gradle.kts" {
		t.Fatalf("ktlint: %s", got)
	}
	if got := pick("swiftlint"); got != "src/ios/.swiftlint.yml,src/ios/App/View.swift" {
		t.Fatalf("swiftlint: %s", got)
	}
	if got := pick("dart-analyze"); got != "src/flutter/analysis_options.yaml,src/flutter/lib/main.dart,src/flutter/pubspec.yaml" {
		t.Fatalf("dart: %s", got)
	}
}

func TestLintOutcomeNoteBlocksClosing(t *testing.T) {
	report := qa.Report{Lint: &qa.LintReport{Tools: []qa.LintToolResult{{Tool: "golangci-lint", Status: "ran", Note: "some projects were not linted or are incomplete: svc (dependencies could not be installed (go mod))"}}}}
	findings, closes := lintOutcome(lintRun(), report, true)
	if len(findings) != 1 || findings[0].Type != "qa_lint_config" || !strings.Contains(findings[0].Title, "may be incomplete") {
		t.Fatalf("%+v", findings)
	}
	for _, c := range closes {
		if c == "qa_lint" {
			t.Fatal("entries were closed by a result known to be incomplete")
		}
	}
}
