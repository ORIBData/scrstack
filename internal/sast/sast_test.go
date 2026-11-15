package sast

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Parsers read the real outputs of the pinned tools (captured from the
// scrs-sast image against testdata/app).
func TestParsers(t *testing.T) {
	g, err := ParseGosec(fixture(t, "gosec.json"))
	if err != nil || len(g) != 7 {
		t.Fatalf("gosec %d %v", len(g), err)
	}
	if g[0].RuleID != "G701" || g[0].Severity != "high" || g[0].CWE[0] != "CWE-89" || g[0].StartLine != 13 || g[0].Confidence != "high" {
		t.Fatalf("gosec finding %+v", g[0])
	}
	b, err := ParseBandit(fixture(t, "bandit.json"))
	if err != nil || len(b) != 4 {
		t.Fatalf("bandit %d %v", len(b), err)
	}
	shell := b[1]
	if shell.RuleID != "B602" || shell.Severity != "high" || shell.CWE[0] != "CWE-78" || shell.Path != "py/app.py" {
		t.Fatalf("bandit finding %+v", shell)
	}
	o, err := ParseSARIF("opengrep", fixture(t, "opengrep.sarif"), nil)
	if err != nil || len(o) != 4 {
		t.Fatalf("opengrep %d %v", len(o), err)
	}
	flows := 0
	for _, f := range o {
		if len(f.CWE) == 0 || f.Severity == "info" {
			t.Fatalf("opengrep finding without CWE or severity %+v", f)
		}
		if len(f.Flow) > 0 {
			flows++
		}
	}
	if flows == 0 {
		t.Fatal("opengrep data-flow traces (codeFlows) not read")
	}
	meta := BearerRules("testdata")
	if m := meta["javascript_lang_eval_user_input"]; m.Severity != "critical" || len(m.CWE) != 1 || m.CWE[0] != "CWE-95" {
		t.Fatalf("bearer rule metadata %+v", meta)
	}
	br, err := ParseSARIF("bearer", fixture(t, "bearer.sarif"), meta)
	if err != nil || len(br) != 5 {
		t.Fatalf("bearer %d %v", len(br), err)
	}
	if br[0].RuleID != "javascript_lang_eval_user_input" || br[0].Severity != "critical" || br[0].CWE[0] != "CWE-95" {
		t.Fatalf("bearer finding %+v", br[0])
	}
	for _, bad := range [][]byte{[]byte("not json"), []byte(`{"version":"2.0.0","runs":[]}`)} {
		if _, err := ParseSARIF("x", bad, nil); err == nil {
			t.Fatal("invalid SARIF accepted")
		}
	}
	// gosec's report of packages it could not load is a coverage gap.
	gap := []byte(`{"Golang errors":{".":[{"line":0,"column":0,"error":"importing dir \".\": main.go: malformed #cgo argument"}]},"Issues":[],"Stats":{}}`)
	findings, err := ParseGosec(gap)
	var partial *PartialError
	if !errors.As(err, &partial) || len(findings) != 0 || !strings.Contains(partial.Detail, "malformed #cgo") {
		t.Fatalf("gosec load errors: %v %v", findings, err)
	}
	if f, err := ParseGosec([]byte(`{"Golang errors":{},"Issues":[]}`)); err != nil || len(f) != 0 {
		t.Fatalf("clean gosec report: %v", err)
	}
	if got := cwes("CWE-79: XSS", "external/cwe/cwe-079", "OWASP-A03"); len(got) != 1 || got[0] != "CWE-79" {
		t.Fatalf("cwes %v", got)
	}
}

// REA-001 and REA-003 from govulncheck's own output: a call trace is
// reachable, a module that is only required is not reachable, and the
// trace keeps only file and line.
func TestParseGovulncheck(t *testing.T) {
	calls, err := ParseGovulncheck(fixture(t, "govulncheck-calls.json"), "svc")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Verdict{}
	for _, v := range calls {
		byID[v.Advisory] = v
	}
	reach := byID["GO-2022-1059"]
	if reach.Status != Reachable || reach.Method != "call_graph" || len(reach.Trace) != 2 || reach.Trace[1].Path != "svc/main.go" || reach.Trace[1].Line != 10 || reach.Trace[1].ThirdParty || !reach.Trace[0].ThirdParty {
		t.Fatalf("reachable %+v", reach)
	}
	if byID["GO-2026-5970"].Status != NotReachable {
		t.Fatalf("module-only finding %+v", byID["GO-2026-5970"])
	}
	imports, _ := ParseGovulncheck(fixture(t, "govulncheck-imports.json"), ".")
	for _, v := range imports {
		if v.Status != NotReachable {
			t.Fatalf("imports sample %+v", v)
		}
	}
	pkg := `{"config":{"scan_mode":"source"}}
{"finding":{"osv":"GO-1","trace":[{"module":"example.com/lib","version":"v1.0.0"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"example.com/lib","version":"v1.0.0","package":"example.com/lib/p"}]}}
{"finding":{"osv":"GO-2","trace":[{"module":"stdlib","version":"v1.27.4","package":"net/http","function":"Serve"}]}}`
	verdicts, err := ParseGovulncheck([]byte(pkg), ".")
	if err != nil || len(verdicts) != 1 || verdicts[0].Status != ImportedOnly || verdicts[0].Method != "import_graph" {
		t.Fatalf("imported-only and stdlib %+v %v", verdicts, err)
	}
	if _, err := ParseGovulncheck([]byte(`{"finding":{}}`), "."); err == nil {
		t.Fatal("output without a config message accepted")
	}
}

func TestWorkspaceSuppressionsAndIdentity(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(root, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("main.go", "package main\n\nfunc a() {\n\tx := md5.Sum(b)\n}\n")
	write("app.py", "import os\nos.system(cmd)  # nosec B605\n")
	write("node_modules/dep/index.js", "eval(x)\n")
	write("docs/example.ts", "eval(x)\n")
	write("web/index.ts", "// nosemgrep: eval\neval(x)\n")
	ws, truncated, err := NewWorkspace(root, []string{"docs/**"})
	if err != nil || truncated {
		t.Fatal(err)
	}
	if ws.Languages["javascript"] != 0 || ws.Languages["typescript"] != 1 || ws.Languages["go"] != 1 || len(ws.Files) != 3 {
		t.Fatalf("workspace %+v %v", ws.Languages, ws.Files)
	}
	plain := Finding{Tool: "gosec", RuleID: "G401", Path: filepath.Join(root, "main.go"), StartLine: 4}
	ws.locate(&plain)
	if plain.Path != "main.go" || plain.SuppressedInCode || len(plain.CodeHash) != 64 {
		t.Fatalf("plain %+v", plain)
	}
	// Adding a #nosec comment marks the finding without changing its identity.
	write("main.go", "package main\n\nfunc a() {\n\tx := md5.Sum(b) // #nosec G401\n}\n")
	silenced := Finding{Tool: "gosec", RuleID: "G401", Path: "main.go", StartLine: 4}
	ws.locate(&silenced)
	if !silenced.SuppressedInCode || silenced.CodeHash != plain.CodeHash || !strings.Contains(silenced.Suppression, "nosec") {
		t.Fatalf("suppressed %+v / %s", silenced, plain.CodeHash)
	}
	// A line shift keeps the identity too.
	write("main.go", "package main\n\n// comment\nfunc a() {\n\tx := md5.Sum(b)\n}\n")
	shifted := Finding{Tool: "gosec", RuleID: "G401", Path: "main.go", StartLine: 5}
	ws.locate(&shifted)
	if shifted.CodeHash == "" {
		t.Fatal("no hash")
	}
	py := Finding{Tool: "bandit", RuleID: "B605", Path: "app.py", StartLine: 2}
	ws.locate(&py)
	above := Finding{Tool: "opengrep", RuleID: "eval", Path: "web/index.ts", StartLine: 2}
	ws.locate(&above)
	if !py.SuppressedInCode || !above.SuppressedInCode {
		t.Fatalf("markers %+v %+v", py, above)
	}
	if !ruleDisabled([]string{"bandit:B6*"}, py) || ruleDisabled([]string{"gosec:B605"}, py) || !ruleDisabled([]string{"B605"}, py) {
		t.Fatal("rule disabling")
	}
	findings := []Finding{{Tool: "opengrep", RuleID: "a", Path: "x.ts", StartLine: 3, CWE: []string{"CWE-95"}}, {Tool: "bearer", RuleID: "b", Path: "x.ts", StartLine: 3, CWE: []string{"CWE-95"}}, {Tool: "bearer", RuleID: "c", Path: "x.ts", StartLine: 9, CWE: []string{"CWE-95"}}}
	correlate(findings)
	if len(findings[0].AlsoReportedBy) != 1 || findings[0].AlsoReportedBy[0] != "bearer:b" || len(findings[2].AlsoReportedBy) != 0 {
		t.Fatalf("correlate %+v", findings)
	}
	if !thirdParty("node_modules/x/a.js") || thirdParty("src/a.js") {
		t.Fatal("third-party paths")
	}
}

// fakeAnalyzer lets the engine be tested without the tools.
type fakeAnalyzer struct {
	name     string
	findings []Finding
	err      error
	block    bool
}

func (f fakeAnalyzer) Meta() Meta                     { return Meta{Name: f.name, Languages: []string{"go"}} }
func (f fakeAnalyzer) Version(context.Context) string { return "1.0" }
func (f fakeAnalyzer) Rules() int                     { return 1 }
func (f fakeAnalyzer) Applies(ws *Workspace) bool     { return ws.Has("go") }
func (f fakeAnalyzer) Run(ctx context.Context, _ *Workspace, _ Options) ([]Finding, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.findings, f.err
}

func TestEngineBudgetsAndSelection(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "app.dart"), []byte("void main() {}\n"), 0o600)
	e := &Engine{Enabled: map[string]bool{"ok": true, "slow": true, "broken": true}, Analyzers: []Analyzer{
		fakeAnalyzer{name: "ok", findings: []Finding{{Tool: "ok", RuleID: "R1", Path: "main.go", StartLine: 1}, {Tool: "ok", RuleID: "R2", Path: "main.go", StartLine: 1}}},
		fakeAnalyzer{name: "slow", block: true},
		fakeAnalyzer{name: "broken", err: os.ErrPermission},
		fakeAnalyzer{name: "off"},
	}}
	resp := e.Analyze(context.Background(), root, t.TempDir(), Request{DisabledRules: []string{"ok:R2"}, Timeout: 50_000_000})
	status := map[string]string{}
	for _, r := range resp.Runs {
		status[r.Analyzer] = r.Status
	}
	// A breached budget is skipped (verdict incomplete), never ok.
	if status["ok"] != "ok" || status["slow"] != "skipped" || status["broken"] != "failed" || status["off"] != "skipped" {
		t.Fatalf("runs %+v", resp.Runs)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].RuleID != "R1" || resp.Findings[0].ToolVersion != "1.0" {
		t.Fatalf("findings %+v", resp.Findings)
	}
	if len(resp.Unsupported) != 1 || resp.Unsupported[0] != "dart" {
		t.Fatalf("unsupported %v", resp.Unsupported)
	}
	only := e.Analyze(context.Background(), root, t.TempDir(), Request{Analyzers: []string{"broken"}})
	for _, r := range only.Runs {
		if r.Analyzer == "ok" && r.Status != "skipped" {
			t.Fatal("per-asset analyzer selection ignored")
		}
	}
}
