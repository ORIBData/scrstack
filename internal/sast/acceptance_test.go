package sast

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// archive packs a testdata tree as a provider-style tarball (one top-level
// directory), as the worker sends it.
func archive(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if err := tw.WriteHeader(&tar.Header{Name: "repo/" + filepath.ToSlash(rel), Typeflag: tar.TypeReg, Size: int64(len(data)), Mode: 0o600}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// TestSASTImageAcceptance runs against the scrs-sast image started by
// `make sast-image-test`: an internal-only network, module downloads
// through the go-modules egress proxy, and the OSV Go feed mounted.
func TestSASTImageAcceptance(t *testing.T) {
	url, token := os.Getenv("SCRS_TEST_SAST_URL"), os.Getenv("SCRS_TEST_SAST_TOKEN")
	if url == "" {
		t.Skip("run through make sast-image-test")
	}
	client := NewClient(url, token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	analyzers, reach, err := client.Analyzers(ctx)
	if err != nil || len(analyzers) != 4 || reach == nil || reach.Version != "v1.9.0" {
		t.Fatalf("analyzers %+v %+v %v", analyzers, reach, err)
	}
	for _, a := range analyzers {
		if a.Version == "unavailable" || !a.Enabled {
			t.Fatalf("analyzer %+v", a)
		}
	}

	// AT-27: seeded flaws in Go, Python and TypeScript, with CWE and
	// location; the #nosec line is recorded as suppressed, not dropped.
	resp, err := client.Analyze(ctx, archive(t, "testdata/app"), Request{Analyzers: []string{"gosec", "bandit", "opengrep", "bearer"}})
	if err != nil {
		t.Fatal(err)
	}
	byTool := map[string][]Finding{}
	for _, f := range resp.Findings {
		byTool[f.Tool] = append(byTool[f.Tool], f)
		if f.Path == "" || f.StartLine == 0 || len(f.CodeHash) != 64 {
			t.Fatalf("finding without location %+v", f)
		}
	}
	for _, run := range resp.Runs {
		if run.Status != "ok" {
			t.Fatalf("run %+v", run)
		}
	}
	has := func(tool, rule, path, cwe string) Finding {
		t.Helper()
		for _, f := range byTool[tool] {
			if strings.HasSuffix(f.RuleID, rule) && f.Path == path && (cwe == "" || contains(f.CWE, cwe)) {
				return f
			}
		}
		t.Fatalf("%s did not report %s at %s (%s): %+v", tool, rule, path, cwe, byTool[tool])
		return Finding{}
	}
	has("gosec", "G701", "goapp/main.go", "CWE-89")
	if f := has("gosec", "G401", "goapp/main.go", ""); !f.SuppressedInCode {
		t.Fatalf("#nosec not recorded %+v", f)
	}
	has("bandit", "B602", "py/app.py", "CWE-78")
	eval := has("opengrep", "eval-detected", "web/src/index.ts", "CWE-95")
	has("bearer", "javascript_lang_eval_user_input", "web/src/index.ts", "CWE-95")
	if len(eval.AlsoReportedBy) == 0 {
		t.Fatalf("one eval flagged by two tools not correlated %+v", eval)
	}

	// AT-28: the hostile repository (cgo preamble, go:generate, setup.py)
	// completes; the Makefile target checks no canary file was created.
	// gosec cannot load the cgo package, so its run is partial (the
	// assessment would be incomplete, never pass); nothing fails or hangs.
	hostile, err := client.Analyze(ctx, archive(t, "testdata/hostile"), Request{Reachability: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range hostile.Runs {
		switch {
		case run.Analyzer == "gosec" && run.Status == "partial" && strings.Contains(run.Detail, "cgo"):
		case run.Status == "ok" || run.Status == "skipped":
		default:
			t.Fatalf("hostile run %+v", run)
		}
	}

	// AT-29: a Go module that calls the vulnerable function is reachable
	// with a trace into the project's code; one that only requires the
	// module is not reachable.
	reached, err := client.Analyze(ctx, archive(t, "testdata/reach"), Request{Analyzers: []string{"none"}, Reachability: true})
	if err != nil || reached.Reachability == nil {
		t.Fatal(err)
	}
	if reached.Reachability.Status != "ok" || len(reached.Reachability.Modules) != 2 {
		t.Fatalf("reachability %+v", reached.Reachability)
	}
	status := map[string]string{}
	for _, v := range reached.Reachability.Verdicts {
		if v.Advisory == "GO-2022-1059" {
			status[v.Module+"@"+map[bool]string{true: "calls", false: "imports"}[len(v.Trace) > 0]] = v.Status
			if v.Status == Reachable && v.Trace[len(v.Trace)-1].Path != "calls/main.go" {
				t.Fatalf("trace %+v", v.Trace)
			}
		}
	}
	if status["golang.org/x/text@calls"] != Reachable || status["golang.org/x/text@imports"] != NotReachable {
		t.Fatalf("verdicts %+v", reached.Reachability.Verdicts)
	}
	ok, _, err := client.Validate(ctx, []byte("rules:\n  - id: no-eval\n    pattern: eval(...)\n    message: avoid eval\n    languages: [javascript]\n    severity: ERROR\n"))
	if err != nil || !ok {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if ok, msg, _ := client.Validate(ctx, []byte("rules:\n  - id: broken\n")); ok || msg == "" {
		t.Fatal("invalid rule accepted")
	}
}
