package qarunner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/google/uuid"
)

// TestRealRunnerLint submits a source tree with a deliberate problem in each
// language to a runner that has the real linters installed (the lint image),
// and checks that every linter ran and reported it. It is skipped unless
// SCRS_TEST_RUNNER_URL and SCRS_TEST_RUNNER_TOKEN point at such a runner, so it
// is also a quick acceptance check for a staging runner:
//
//	SCRS_TEST_RUNNER_URL=http://localhost:18090 SCRS_TEST_RUNNER_TOKEN=... \
//	  go test ./internal/qarunner -run TestRealRunnerLint -v
func TestRealRunnerLint(t *testing.T) {
	url, token := os.Getenv("SCRS_TEST_RUNNER_URL"), os.Getenv("SCRS_TEST_RUNNER_TOKEN")
	if url == "" || token == "" {
		t.Skip("needs a runner with the real linters")
	}
	client, err := qa.NewRunner(url, token, "", true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	info, err := client.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runner tools: %v", info.LintTools)
	files := []qa.File{
		{Path: "src/py/app.py", Data: []byte("import os\nimport subprocess\n\n\ndef run(cmd: str) -> int:\n    return subprocess.call(cmd, shell=True)\n\n\nx: int = \"a\"\ny = undefined_name\n")},
		{Path: "src/php/app.php", Data: []byte("<?php\nfunction add(int $a, int $b): int\n{\n    return $a + $b;\n}\n\necho add(\"x\", 2);\necho undefined_fn();\nclass Box {\n  public function get() { return $this->missing; }\n}\n")},
		{Path: "src/c/include/util.h", Data: []byte("int twice(int x);\n")},
		{Path: "src/c/main.c", Data: []byte("#include <stdlib.h>\n#include \"util.h\"\n\nint leak(void) {\n    int *p = malloc(sizeof(int));\n    *p = 1;\n    return twice(*p);\n}\n")},
		{Path: "src/c/third.cpp", Data: []byte("#include <boost/thing.hpp>\nint f() { return 1; }\n")},
		{Path: "src/go/go.mod", Data: []byte("module example.com/sample\n\ngo 1.27\n")},
		{Path: "src/go/main.go", Data: []byte("package main\n\nfunc risky() error { return nil }\n\nfunc main() {\n\trisky()\n}\n")},
		{Path: "src/web/app.js", Data: []byte("const unused = 1\nconsole.log(\"hi\")\n")},
		{Path: "src/web/types.ts", Data: []byte("export const a: any = 1;\nexport function f(x: any) { return x }\n")},
		{Path: "src/android/Main.kt", Data: []byte("import java.util.*\n\nfun main() {\n    val x=1\n    println( x )\n}\n")},
		{Path: "src/ios/main.swift", Data: []byte("import Foundation\nlet a: Int? = nil\nlet b = a as! Int\nprint(b)\n")},
		{Path: "src/app/pubspec.yaml", Data: []byte("name: sample\nenvironment:\n  sdk: ^3.0.0\n")},
		{Path: "src/app/lib/main.dart", Data: []byte("import 'dart:io';\nint f(int a) {\n  var unused = 1;\n  return undefinedThing;\n}\n")},
	}
	bundle, err := qa.Pack(files)
	if err != nil {
		t.Fatal(err)
	}
	spec := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindLint, Threads: 1, TimeoutSeconds: 600, Lint: &qa.Lint{Tools: qa.LintToolNames()}}
	if _, err := client.Submit(ctx, spec, bundle); err != nil {
		t.Fatal(err)
	}
	var status qa.JobStatus
	for !qa.Finished(status.State) {
		time.Sleep(time.Second)
		if status, err = client.Status(ctx, spec.ID); err != nil {
			t.Fatal(err)
		}
	}
	if status.State != qa.StateFailed || status.ReportSHA256 == "" {
		t.Fatalf("status %+v", status)
	}
	archive, err := client.Report(ctx, spec.ID, status.ReportSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("SCRS_TEST_REPORT_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "lint-report.tar.gz"), archive, 0o600)
	}
	report, err := qa.ParseReport(archive)
	if err != nil || report.Lint == nil {
		t.Fatal(report, err)
	}
	byTool := map[string]qa.LintToolResult{}
	for _, tr := range report.Lint.Tools {
		byTool[tr.Tool] = tr
		t.Logf("%-14s %-12s issues=%d %s %s", tr.Tool, tr.Status, tr.Issues, tr.Error, tr.Note)
	}
	for _, tool := range qa.LintToolNames() {
		if r := byTool[tool]; r.Status != "ran" || r.Issues == 0 {
			t.Errorf("%s: %+v", tool, r)
		}
	}
	for _, i := range report.Lint.Issues {
		t.Logf("%s %s %s:%d %s", i.Tool, i.Rule, i.Path, i.Line, i.Message)
	}
	_ = client.Delete(ctx, spec.ID)
}

// TestRealRunnerLintDeps checks the opt-in dependency step: the runner must
// have SCRS_QA_RUNNER_LINT_DEPS=true and network access to the package hosts.
// SCRS_TEST_DEPS_DIR names a directory holding go.sum for the Go sample and
// package.json and package-lock.json for the ESLint project (an ESLint config that imports an
// installed package).
func TestRealRunnerLintDeps(t *testing.T) {
	url, token, deps := os.Getenv("SCRS_TEST_RUNNER_URL"), os.Getenv("SCRS_TEST_RUNNER_TOKEN"), os.Getenv("SCRS_TEST_DEPS_DIR")
	if url == "" || token == "" || deps == "" {
		t.Skip("needs a runner with LINT_DEPS on")
	}
	pkg, _ := os.ReadFile(filepath.Join(deps, "package.json"))
	lock, _ := os.ReadFile(filepath.Join(deps, "package-lock.json"))
	goSum, _ := os.ReadFile(filepath.Join(deps, "go.sum"))
	composerJSON, _ := os.ReadFile(filepath.Join(deps, "composer.json"))
	composerLock, _ := os.ReadFile(filepath.Join(deps, "composer.lock"))
	client, err := qa.NewRunner(url, token, "", true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	files := []qa.File{
		{Path: "src/go/go.mod", Data: []byte("module example.com/d\n\ngo 1.27\n\nrequire github.com/google/uuid v1.6.0\n")},
		{Path: "src/go/go.sum", Data: goSum},
		{Path: "src/go/main.go", Data: []byte("package main\n\nimport (\n\t\"fmt\"\n\n\t\"github.com/google/uuid\"\n)\n\nfunc risky() error { return nil }\n\nfunc main() {\n\trisky()\n\tfmt.Println(uuid.New())\n}\n")},
		{Path: "src/js/package.json", Data: pkg},
		{Path: "src/js/package-lock.json", Data: lock},
		{Path: "src/js/eslint.config.js", Data: []byte("import js from \"@eslint/js\";\nexport default [js.configs.recommended];\n")},
		{Path: "src/js/a.js", Data: []byte("const unused = 1\n")},
		{Path: "src/php/composer.json", Data: composerJSON},
		{Path: "src/php/composer.lock", Data: composerLock},
		{Path: "src/php/app.php", Data: []byte("<?php\nuse Psr\\Log\\LoggerInterface;\n\nfunction f(LoggerInterface $l): void\n{\n    $l->nope();\n}\n")},
		{Path: "src/dart/pubspec.yaml", Data: []byte("name: d\nenvironment:\n  sdk: ^3.0.0\ndependencies:\n  collection: ^1.19.0\n")},
		{Path: "src/dart/lib/m.dart", Data: []byte("import 'package:collection/collection.dart';\nint f(List<int> a) => a.sum;\n")},
	}
	bundle, _ := qa.Pack(files)
	spec := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindLint, Threads: 1, TimeoutSeconds: 600, Lint: &qa.Lint{Tools: []string{"golangci-lint", "eslint", "dart-analyze", "phpstan"}}}
	if _, err := client.Submit(ctx, spec, bundle); err != nil {
		t.Fatal(err)
	}
	var status qa.JobStatus
	for !qa.Finished(status.State) {
		time.Sleep(2 * time.Second)
		if status, err = client.Status(ctx, spec.ID); err != nil {
			t.Fatal(err)
		}
	}
	archive, err := client.Report(ctx, spec.ID, status.ReportSHA256)
	if err != nil {
		t.Fatalf("%+v %v", status, err)
	}
	report, err := qa.ParseReport(archive)
	if err != nil || report.Lint == nil {
		t.Fatal(report, err)
	}
	for _, tr := range report.Lint.Tools {
		t.Logf("%-14s %-8s issues=%d err=%q note=%q", tr.Tool, tr.Status, tr.Issues, tr.Error, tr.Note)
		if tr.Status != "ran" || tr.Note != "" {
			t.Errorf("%+v", tr)
		}
	}
	for _, i := range report.Lint.Issues {
		t.Logf("%s %s %s:%d %s", i.Tool, i.Rule, i.Path, i.Line, i.Message)
	}
	if report.Summary.Lint == nil || report.Summary.Lint.ByTool["golangci-lint"] != 1 || report.Summary.Lint.ByTool["eslint"] != 1 || report.Summary.Lint.ByTool["dart-analyze"] != 0 || report.Summary.Lint.ByTool["phpstan"] != 1 {
		t.Errorf("%+v", report.Summary.Lint)
	}
	_ = client.Delete(ctx, spec.ID)
}
