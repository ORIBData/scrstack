package sast

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Paths to the bundled tools and rules in the scrs-sast image.
type Paths struct {
	Gosec, Bandit, OpenGrep, Bearer, Govulncheck, Go string
	OpenGrepRules, BearerRules                       string
}

// DefaultPaths matches deploy/Dockerfile.sast.
var DefaultPaths = Paths{Gosec: "/usr/local/bin/gosec", Bandit: "/usr/local/bin/bandit", OpenGrep: "/usr/local/bin/opengrep", Bearer: "/usr/local/bin/bearer", Govulncheck: "/usr/local/bin/govulncheck", Go: "/usr/local/go/bin/go", OpenGrepRules: "/opt/scrs/opengrep-rules", BearerRules: "/opt/scrs/bearer-rules"}

// isolatedEnv is the environment of analyzers that need no network: no
// proxy, no credentials, no inherited configuration, scratch home.
func isolatedEnv(scratch string, extra ...string) []string {
	env := []string{"HOME=" + scratch, "TMPDIR=" + scratch, "PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "NO_COLOR=1",
		"XDG_CACHE_HOME=" + filepath.Join(scratch, "cache"), "XDG_CONFIG_HOME=" + filepath.Join(scratch, "config"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOTELEMETRY=off", "GOPROXY=off", "GOSUMDB=off",
		"GOCACHE=" + filepath.Join(scratch, "gocache"), "GOMODCACHE=" + filepath.Join(scratch, "gomod")}
	return append(env, extra...)
}

// capped keeps at most limit bytes and records overflow.
type capped struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.limit {
		c.overflow = true
		p = p[:max(c.limit-c.Len(), 0)]
	}
	c.Buffer.Write(p)
	return len(p), nil
}

// execute runs a tool; exit codes in okCodes are success (tools exit 1
// when they find issues).
func execute(ctx context.Context, dir string, env []string, okCodes []int, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	stdout, stderr := &capped{limit: 64 << 20}, &capped{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, stderr.Bytes(), ctx.Err()
	}
	if stdout.overflow {
		return nil, stderr.Bytes(), errors.New(filepath.Base(name) + " output exceeded 64 MiB")
	}
	var exit *exec.ExitError
	if err != nil {
		if !errors.As(err, &exit) {
			return nil, stderr.Bytes(), err
		}
		ok := false
		for _, code := range okCodes {
			ok = ok || exit.ExitCode() == code
		}
		if !ok {
			return nil, stderr.Bytes(), errors.New(filepath.Base(name) + " failed: " + firstLine(stderr.String()))
		}
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func version(ctx context.Context, re *regexp.Regexp, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "unavailable"
	}
	if m := re.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return strings.TrimSpace(firstLine(string(out)))
}

var semverLike = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)

// Gosec analyses Go modules (Apache-2.0). It type-checks with the Go
// toolchain offline: modules that are not vendored still produce findings
// for the code that type-checks.
type Gosec struct{ Bin string }

func (g Gosec) Meta() Meta {
	return Meta{Name: "gosec", Languages: []string{"go"}, License: "Apache-2.0", Redistributable: true}
}
func (g Gosec) Version(ctx context.Context) string {
	return version(ctx, regexp.MustCompile(`Version:\s*v?([0-9][^\s]*)`), g.Bin, "-version")
}
func (g Gosec) Rules() int                 { return -1 }
func (g Gosec) Applies(ws *Workspace) bool { return ws.Has("go") }
func (g Gosec) Run(ctx context.Context, ws *Workspace, opts Options) ([]Finding, error) {
	modules := moduleDirs(ws, "go.mod", 20)
	if len(modules) == 0 {
		modules = []string{"."}
	}
	out := []Finding{}
	for _, dir := range modules {
		// -nosec=true ignores #nosec: SCRS records suppressions itself.
		data, _, err := execute(ctx, filepath.Join(ws.Root, dir), isolatedEnv(opts.Scratch), []int{0, 1}, g.Bin, "-quiet", "-fmt=json", "-nosec=true", "-exclude-generated", "./...")
		if err != nil {
			return out, err
		}
		findings, err := ParseGosec(data)
		if err != nil {
			return out, err
		}
		out = append(out, findings...)
	}
	return out, nil
}

// moduleDirs lists directories holding a manifest, shallowest first.
func moduleDirs(ws *Workspace, manifest string, limit int) []string {
	out := []string{}
	for _, f := range ws.Files {
		if filepath.Base(f) == manifest {
			out = append(out, filepath.Dir(f))
			if len(out) == limit {
				break
			}
		}
	}
	return out
}

// Bandit analyses Python (Apache-2.0); it parses code and never imports it.
type Bandit struct{ Bin string }

func (b Bandit) Meta() Meta {
	return Meta{Name: "bandit", Languages: []string{"python"}, License: "Apache-2.0", Redistributable: true}
}
func (b Bandit) Version(ctx context.Context) string {
	return version(ctx, regexp.MustCompile(`bandit ([0-9][^\s]*)`), b.Bin, "--version")
}
func (b Bandit) Rules() int                 { return -1 }
func (b Bandit) Applies(ws *Workspace) bool { return ws.Has("python") }
func (b Bandit) Run(ctx context.Context, ws *Workspace, opts Options) ([]Finding, error) {
	report := filepath.Join(opts.Scratch, "bandit.json")
	args := []string{"-q", "-r", ".", "-f", "json", "--ignore-nosec", "-o", report, "-x", "./node_modules,./vendor,./.venv,./venv"}
	if _, _, err := execute(ctx, ws.Root, isolatedEnv(opts.Scratch), []int{0, 1}, b.Bin, args...); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(report)
	if err != nil {
		return nil, errors.New("bandit wrote no report")
	}
	return ParseBandit(data)
}

// OpenGrep runs the pinned community rules for JavaScript, TypeScript,
// Java, Kotlin, Swift and other languages (engine LGPL-2.1; rules
// LGPL-2.1 with the Commons Clause: internal use only).
type OpenGrep struct {
	Bin, RuleDir string
	once         sync.Once
	count        int
}

func (o *OpenGrep) Meta() Meta {
	return Meta{Name: "opengrep", Languages: []string{"javascript", "typescript", "java", "kotlin", "swift", "scala", "php", "ruby", "csharp", "c", "rust", "bash", "html"}, License: "LGPL-2.1-only", RulesLicense: "LGPL-2.1-only with Commons Clause", Redistributable: false}
}
func (o *OpenGrep) Version(ctx context.Context) string {
	return version(ctx, semverLike, o.Bin, "--version")
}
func (o *OpenGrep) Rules() int {
	o.once.Do(func() { o.count = countFiles(o.RuleDir, ".yaml", ".yml") })
	return o.count
}
func (o *OpenGrep) Applies(ws *Workspace) bool { return ws.Has(o.Meta().Languages...) }
func (o *OpenGrep) Run(ctx context.Context, ws *Workspace, opts Options) ([]Finding, error) {
	report := filepath.Join(opts.Scratch, "opengrep.sarif")
	for _, d := range []string{"cache", "config"} {
		_ = os.MkdirAll(filepath.Join(opts.Scratch, d), 0o700)
	}
	args := []string{"scan", "--config", o.RuleDir, "--sarif", "--output", report, "--no-git-ignore", "--dataflow-traces", "--timeout", "30", "--jobs", "2", "--max-target-bytes", "1000000", "--quiet"}
	if opts.CustomRules != "" {
		args = append(args, "--config", opts.CustomRules)
	}
	for _, d := range []string{"node_modules", "vendor", "dist", "build"} {
		args = append(args, "--exclude", d)
	}
	args = append(args, ws.Root)
	if _, _, err := execute(ctx, opts.Scratch, isolatedEnv(opts.Scratch, "SEMGREP_SEND_METRICS=off"), []int{0, 1}, o.Bin, args...); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(report)
	if err != nil {
		return nil, errors.New("opengrep wrote no report")
	}
	findings, err := ParseSARIF("opengrep", data, nil)
	for i := range findings {
		// Rule ids are prefixed with the rules directory path.
		findings[i].RuleID = strings.TrimPrefix(strings.ReplaceAll(strings.TrimPrefix(findings[i].RuleID, strings.TrimPrefix(o.RuleDir, "/")), "/", "."), ".")
		findings[i].RuleID = strings.TrimPrefix(findings[i].RuleID, "opt.scrs.opengrep-rules.")
	}
	return findings, err
}

func countFiles(dir string, exts ...string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			for _, e := range exts {
				if strings.HasSuffix(p, e) {
					n++
				}
			}
		}
		return nil
	})
	return n
}

// Bearer runs its pinned rules for JavaScript/TypeScript, Java, PHP and
// Ruby (Elastic License 2.0, internal use only). Its Go and Python rules
// repeat gosec and Bandit and are not bundled.
type Bearer struct {
	Bin, RuleDir string
	once         sync.Once
	meta         map[string]RuleMeta
}

func (b *Bearer) Meta() Meta {
	return Meta{Name: "bearer", Languages: []string{"javascript", "typescript", "java", "php", "ruby"}, License: "Elastic-2.0", RulesLicense: "Elastic-2.0", Redistributable: false}
}
func (b *Bearer) Version(ctx context.Context) string {
	return version(ctx, semverLike, b.Bin, "version")
}
func (b *Bearer) load() map[string]RuleMeta {
	b.once.Do(func() { b.meta = BearerRules(b.RuleDir) })
	return b.meta
}
func (b *Bearer) Rules() int                 { return len(b.load()) }
func (b *Bearer) Applies(ws *Workspace) bool { return ws.Has(b.Meta().Languages...) }
func (b *Bearer) Run(ctx context.Context, ws *Workspace, opts Options) ([]Finding, error) {
	report := filepath.Join(opts.Scratch, "bearer.sarif")
	args := []string{"scan", ws.Root, "--format", "sarif", "--output", report, "--quiet", "--disable-version-check", "--disable-default-rules", "--external-rule-dir", b.RuleDir, "--no-color", "--force", "--scanner", "sast", "--exit-code", "0", "--skip-path", "node_modules,vendor,dist,build"}
	if _, _, err := execute(ctx, opts.Scratch, isolatedEnv(opts.Scratch, "BEARER_DISABLE_VERSION_CHECK=true", "BEARER_SEND_METRICS=false"), []int{0}, b.Bin, args...); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(report)
	if err != nil {
		return nil, errors.New("bearer wrote no report")
	}
	return ParseSARIF("bearer", data, b.load())
}
