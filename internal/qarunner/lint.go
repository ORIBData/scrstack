package qarunner

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ORIBData/scrstack/internal/qa"
)

// lintCommand is how one linter is run in the source root. A repository may
// configure rules (ruff.toml, .golangci.yml, an ESLint config, .editorconfig,
// .swiftlint.yml, analysis_options.yaml) but cannot change the command line
// or where the report is written.
type lintCommand struct {
	args []string
	// stdout says the tool prints its report to standard output, which the
	// runner writes to the output file.
	stdout bool
	// ok are the exit codes that mean the tool ran (with or without issues).
	ok []int
	// needOutput are accepted exit codes that count only when the tool wrote
	// something: mypy exits 2 both for a syntax error (with a report) and for
	// a usage error (without one).
	needOutput []int
}

func (s *Server) lintCommand(tool, dir, out string, fallback bool) lintCommand {
	switch tool {
	case "ruff":
		return lintCommand{args: []string{"check", "--no-cache", "--force-exclude", "--output-format", "json", "--output-file", out, "."}, ok: []int{0, 1}}
	case "mypy":
		// Third-party packages are not installed, so their imports cannot be
		// resolved; those errors would only be noise. Exit 1 is "type errors".
		return lintCommand{args: []string{"--output", "json", "--no-error-summary", "--no-color-output", "--ignore-missing-imports", "--explicit-package-bases", "--cache-dir=" + os.DevNull, "."}, stdout: true, ok: []int{0, 1}, needOutput: []int{2}}
	case "bandit":
		args := []string{"-r", ".", "-f", "json", "-o", out, "-q"}
		if data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil && strings.Contains(string(data), "[tool.bandit") {
			args = append(args, "-c", "pyproject.toml")
		}
		return lintCommand{args: args, ok: []int{0, 1}}
	case "pylint":
		// The exit code is a bit mask of the message kinds found (1 to 31);
		// 32 is a usage error. Imports are not resolvable without the
		// repository's dependencies, so those two checks are off.
		return lintCommand{args: []string{"--recursive=y", "--output-format=json2", "--output=" + out, "--persistent=n", "--disable=import-error,no-name-in-module", "."}, ok: seq(0, 31)}
	case "phpstan":
		// A repository's own phpstan.neon (found in the working directory)
		// sets the paths and the level; without one the runner's config
		// analyses the source at level 5, without vendor/.
		args := []string{"analyse", "--error-format=json", "--no-progress", "--no-interaction", "--memory-limit=1G"}
		if !hasFile(dir, "phpstan.neon", "phpstan.neon.dist", "phpstan.dist.neon") {
			args = append(args, "--configuration="+filepath.Join(filepath.Dir(out), "phpstan.neon"))
		}
		return lintCommand{args: args, stdout: true, ok: []int{0, 1}}
	case "phpcs":
		// A repository's phpcs.xml is found automatically; without one the
		// PSR-12 standard applies.
		args := []string{"--report=json", "--report-file=" + out, "--extensions=php,phtml,inc", "--ignore=*/vendor/*,*/node_modules/*", "-q"}
		if !hasFile(dir, "phpcs.xml", ".phpcs.xml", "phpcs.xml.dist", ".phpcs.xml.dist") {
			args = append(args, "--standard=PSR12")
		}
		// Exit 1 and 2 mean errors or fixable problems were found, 3 both.
		return lintCommand{args: append(args, "."), ok: []int{0, 1, 2, 3}}
	case "golangci-lint":
		return lintCommand{args: []string{"run", "--timeout", "30m", "--max-issues-per-linter", "0", "--max-same-issues", "0", "--issues-exit-code", "1", "--output.json.path", out, "./..."}, ok: []int{0, 1}}
	case "eslint":
		args := []string{"-f", "json", "-o", out, "--no-error-on-unmatched-pattern"}
		// A repository without a flat config is linted with the runner's own
		// (ESLint's recommended rules for JavaScript and TypeScript).
		if s.cfg.ESLintFallback != "" && fallback {
			args = append(args, "--config", s.cfg.ESLintFallback)
		}
		return lintCommand{args: append(args, "."), ok: []int{0, 1}}
	case "ktlint":
		return lintCommand{args: []string{"--relative", "--reporter=json,output=" + out}, ok: []int{0, 1}}
	case "swiftlint":
		return lintCommand{args: []string{"lint", "--quiet", "--no-cache", "--reporter", "json"}, stdout: true, ok: []int{0, 2}}
	case "dart-analyze":
		// 0 clean, 1 infos, 2 warnings, 3 errors.
		return lintCommand{args: []string{"analyze", "--format=json", "."}, stdout: true, ok: []int{0, 1, 2, 3}}
	}
	return lintCommand{}
}

// hasFile reports whether dir holds one of the named files.
func hasFile(dir string, names ...string) bool {
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			return true
		}
	}
	return false
}

// seq lists the integers from lo to hi.
func seq(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}

func (c lintCommand) accepts(code int) bool {
	for _, ok := range c.ok {
		if ok == code {
			return true
		}
	}
	return false
}

func (c lintCommand) acceptsWithOutput(code int) bool {
	for _, ok := range c.needOutput {
		if ok == code {
			return true
		}
	}
	return false
}

func hasOutput(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// lintTools lists the linters installed on this runner, sorted.
func (s *Server) lintTools() []string {
	names := make([]string, 0, len(s.cfg.Lint))
	for name := range s.cfg.Lint {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// runLint runs the requested linters over bundle/src. It is "failed" when
// any linter reported an issue, "passed" when every one that ran was clean,
// and "error" when none could run.
func (s *Server) runLint(ctx context.Context, j *job, console *capture) (string, *int, string) {
	src := filepath.Join(j.dir, "bundle", "src")
	if info, err := os.Stat(src); err != nil || !info.IsDir() {
		return qa.StateError, nil, "the bundle has no src directory"
	}
	outDir := filepath.Join(j.dir, "out", "lint")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return qa.StateError, nil, "could not create the lint output directory"
	}
	if s.cfg.JobUID != 0 {
		_ = os.Chown(outDir, s.cfg.JobUID, s.cfg.JobGID)
	}
	tmp := filepath.Join(j.dir, "tmp")
	home := filepath.Join(j.dir, "home")
	j.extraEnv = []string{
		"GOFLAGS=-buildvcs=false", "GOTOOLCHAIN=local",
		"GOCACHE=" + filepath.Join(tmp, "gocache"), "GOPATH=" + filepath.Join(home, "go"), "GOMODCACHE=" + filepath.Join(home, "go", "pkg", "mod"),
		"XDG_CACHE_HOME=" + filepath.Join(tmp, "cache"), "npm_config_cache=" + filepath.Join(tmp, "npm"),
		"PUB_CACHE=" + filepath.Join(home, ".pub-cache"), "COMPOSER_HOME=" + filepath.Join(home, "composer"), "COMPOSER_CACHE_DIR=" + filepath.Join(tmp, "composer"), "PYLINTHOME=" + filepath.Join(tmp, "pylint"), "PYTHONDONTWRITEBYTECODE=1", "DART_SUPPRESS_ANALYTICS=true", "CI=true",
	}
	ran, issues := 0, 0
	var last *int
	for _, tool := range j.spec.Lint.Tools {
		meta := qa.LintMeta{Tool: tool}
		binary, installed := s.cfg.Lint[tool]
		if !installed {
			meta.Status, meta.Error = "unavailable", tool+" is not installed on this runner"
			console.WriteString("== lint " + tool + ": not installed\n")
		} else {
			s.lintOne(ctx, j, console, tool, binary, src, outDir, &meta)
			if meta.Status == "ran" {
				ran++
				last = meta.Exit
				if n, _ := countIssues(tool, outDir); n > 0 {
					issues += n
				}
			}
			if ctx.Err() != nil {
				return qa.StateError, meta.Exit, "stopped"
			}
		}
		data, _ := json.Marshal(meta)
		_ = os.WriteFile(filepath.Join(outDir, tool+".meta.json"), data, 0o600)
	}
	switch {
	case ran == 0:
		return qa.StateError, nil, "no requested linter could run; see the tool results in the report"
	case issues > 0:
		return qa.StateFailed, last, ""
	}
	return qa.StatePassed, last, ""
}

// lintOne runs one linter and records what happened in meta.
func (s *Server) lintOne(ctx context.Context, j *job, console *capture, tool, binary, src, outDir string, meta *qa.LintMeta) {
	out := filepath.Join(outDir, tool+".json")
	if _, multi := projectMarkers[tool]; multi {
		s.lintProjects(ctx, j, console, tool, binary, src, outDir, meta)
		return
	}
	switch tool {
	case "clang-tidy":
		s.lintClangTidy(ctx, j, console, binary, src, out, meta)
		return
	case "phpstan":
		// Every Composer project of the repository (monorepos have several):
		// install its locked dependencies when enabled, and load its autoloader
		// so PHPStan can resolve the packages' classes.
		var autoloads []string
		var failed []string
		for _, root := range rootsOf([]string{"composer.json"}, true, src) {
			dir := filepath.Join(src, filepath.FromSlash(root))
			if s.cfg.LintDeps {
				if note := s.installDeps(ctx, j, console, tool, dir); note != "" {
					failed = append(failed, root+" ("+note+")")
				}
			}
			if hasFile(dir, "vendor/autoload.php") {
				autoloads = append(autoloads, filepath.Join(dir, "vendor", "autoload.php"))
			}
		}
		if len(failed) > 0 {
			meta.Note = "dependencies are missing or incomplete, so classes from packages may be reported as unknown: " + strings.Join(failed, "; ")
		}
		if !hasFile(src, "phpstan.neon", "phpstan.neon.dist", "phpstan.dist.neon") {
			// The configuration lives outside the source, so Composer's
			// autoloader is named in it (PHPStan looks for it beside the config).
			cfg := "parameters:\n    level: 5\n    paths:\n        - " + src + "\n    excludePaths:\n        analyse:\n            - " + src + "/vendor (?)\n            - " + src + "/*/vendor/* (?)\n            - " + src + "/node_modules (?)\n"
			if len(autoloads) > 0 {
				cfg += "    bootstrapFiles:\n"
				for _, a := range autoloads {
					cfg += "        - " + a + "\n"
				}
			}
			if err := os.WriteFile(filepath.Join(outDir, "phpstan.neon"), []byte(cfg), 0o644); err != nil {
				meta.Status, meta.Error = "error", "could not write the phpstan configuration"
				return
			}
		}
	}
	cmd := s.lintCommand(tool, src, out, false)
	console.WriteString("== lint " + tool + "\n")
	if cmd.stdout {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
		if err != nil {
			meta.Status, meta.Error = "error", "could not open the output file"
			return
		}
		defer f.Close()
		if s.cfg.JobUID != 0 {
			_ = f.Chown(s.cfg.JobUID, s.cfg.JobGID)
		}
		j.stdout = f
		defer func() { j.stdout = nil }()
	}
	code, err := s.command(ctx, j, binary, cmd.args, src, console)
	meta.Exit = &code
	switch {
	case err != nil:
		meta.Status, meta.Error, meta.Exit = "error", tool+" could not start: "+err.Error(), nil
	case ctx.Err() != nil:
		meta.Status, meta.Error = "error", "stopped"
	case !cmd.accepts(code) && !(cmd.acceptsWithOutput(code) && hasOutput(out)):
		meta.Status, meta.Error = "error", tool+" exited "+itoa(code)+"; see console.log"
	default:
		if _, problem := countIssues(tool, outDir); problem != "" {
			meta.Status, meta.Error = "error", problem
			return
		}
		meta.Status = "ran"
	}
}

// countIssues parses a tool's output file and counts its issues. A missing
// or unreadable file is a problem, never a clean result.
func countIssues(tool, outDir string) (int, string) {
	data, err := os.ReadFile(filepath.Join(outDir, tool+".json"))
	if err != nil {
		return 0, tool + " wrote no output file"
	}
	issues, err := qa.LintParsers[tool](data)
	if err != nil {
		return 0, err.Error()
	}
	return len(issues), ""
}

// maxProjects bounds how many projects of one repository a tool lints.
const maxProjects = 20

// projectMarkers name, for the tools that work on one project at a time, the
// files that mark a project's root. Go needs the module root, ESLint the
// directory of its flat config (and of package-lock.json, for dependencies),
// Dart the package root (pubspec.yaml, for `dart pub get`).
var projectMarkers = map[string][]string{
	"golangci-lint": {"go.mod"},
	"eslint":        {"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts", "eslint.config.mts", "eslint.config.cts"},
	"dart-analyze":  {"pubspec.yaml"},
}

// projectRoots lists the project directories of a tool, relative to src ("."
// is the root). A project nested in another is covered by the outer one.
// Without any marker the repository is linted from its root.
func projectRoots(tool, src string) []string {
	return rootsOf(projectMarkers[tool], tool == "golangci-lint", src)
}

// rootsOf finds the directories holding one of the marker files. With
// nested, a project inside another still gets its own root.
func rootsOf(names []string, nested bool, src string) []string {
	markers := map[string]bool{}
	for _, m := range names {
		markers[m] = true
	}
	var dirs []string
	_ = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git", ".dart_tool", "Pods":
				return filepath.SkipDir
			}
			return nil
		}
		if markers[d.Name()] {
			rel, _ := filepath.Rel(src, filepath.Dir(p))
			dirs = append(dirs, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(dirs)
	var roots []string
	for _, dir := range dirs {
		switch {
		case len(roots) > 0 && roots[len(roots)-1] == dir:
			continue
		case !nested && covered(roots, dir):
			continue // ESLint and Dart cover nested projects from the outer one
		case len(roots) >= maxProjects:
			continue
		}
		roots = append(roots, dir)
	}
	if len(roots) == 0 {
		return []string{"."}
	}
	return roots
}

// covered reports whether dir is inside one of the roots.
func covered(roots []string, dir string) bool {
	for _, r := range roots {
		if r == "." || strings.HasPrefix(dir, r+"/") {
			return true
		}
	}
	return false
}

// installDeps fetches one project's dependencies so the linter can resolve
// its imports: `go mod download`, `npm ci` without install scripts, `dart pub
// get`, `composer install` without scripts or plugins (only from composer.lock). It runs only when the operator enabled it (SCRS_QA_RUNNER_LINT_DEPS)
// and only for a project that pins its dependencies. A problem is returned
// for the tool's note: the linter still runs, and its result is marked
// incomplete.
func (s *Server) installDeps(ctx context.Context, j *job, console *capture, tool, dir string) string {
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil }
	var name string
	var args []string
	switch {
	case tool == "golangci-lint" && !exists("vendor"):
		name, args = "go", []string{"mod", "download"}
	case tool == "eslint" && exists("package.json") && exists("package-lock.json"):
		name, args = "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund"}
	case tool == "phpstan" && exists("composer.json") && exists("composer.lock") && !exists("vendor"):
		// Only what composer.lock pins, with no scripts or plugins (both run
		// package code at install time).
		name, args = "composer", []string{"install", "--no-scripts", "--no-plugins", "--no-interaction", "--no-progress", "--prefer-dist", "--ignore-platform-reqs"}
	case tool == "dart-analyze" && exists("pubspec.yaml"):
		name, args = "dart", []string{"pub", "get"}
	default:
		return ""
	}
	path, err := lookPath(name)
	if err != nil {
		return name + " is not installed, so dependencies were not fetched"
	}
	console.WriteString("== deps " + tool + ": " + name + " " + args[0] + "\n")
	if code, err := s.command(ctx, j, path, args, dir, console); err != nil || code != 0 {
		return "dependencies could not be installed (" + name + " " + args[0] + ")"
	}
	return ""
}

// lintProjects runs a tool in each project of the repository and merges the
// reports into <tool>.json. A project that cannot be linted is named in the
// tool's note; the tool as a whole is an error only when no project could be
// linted.
func (s *Server) lintProjects(ctx context.Context, j *job, console *capture, tool, binary, src, outDir string, meta *qa.LintMeta) {
	var merged []json.RawMessage
	var failed []string
	linted := 0
	var lastExit *int
	for i, project := range projectRoots(tool, src) {
		dir := filepath.Join(src, filepath.FromSlash(project))
		out := filepath.Join(outDir, tool+"-"+itoa(i)+".part.json")
		cmd := s.lintCommand(tool, dir, out, project == "." && !projectHasMarker(tool, dir))
		if s.cfg.LintDeps {
			if note := s.installDeps(ctx, j, console, tool, dir); note != "" {
				failed = append(failed, project+" ("+note+")")
			}
		}
		console.WriteString("== lint " + tool + " " + project + "\n")
		var stdout *os.File
		if cmd.stdout {
			f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
			if err != nil {
				failed = append(failed, project+" (could not open the output file)")
				continue
			}
			if s.cfg.JobUID != 0 {
				_ = f.Chown(s.cfg.JobUID, s.cfg.JobGID)
			}
			stdout, j.stdout = f, f
		}
		code, err := s.command(ctx, j, binary, cmd.args, dir, console)
		if stdout != nil {
			stdout.Close()
			j.stdout = nil
		}
		if ctx.Err() != nil {
			meta.Status, meta.Error = "error", "stopped"
			return
		}
		if err != nil || !cmd.accepts(code) {
			failed = append(failed, project+" ("+tool+" exited "+itoa(code)+")")
			continue
		}
		data, err := os.ReadFile(out)
		if err != nil {
			failed = append(failed, project+" (no output)")
			continue
		}
		_ = os.Remove(out)
		items, ok := splitReport(tool, data, project)
		if !ok {
			failed = append(failed, project+" (unreadable output)")
			continue
		}
		linted++
		lastExit = &code
		merged = append(merged, items...)
	}
	if linted == 0 {
		meta.Status, meta.Error = "error", tool+" could not lint any project ("+strings.Join(failed, "; ")+"); see console.log"
		return
	}
	if len(failed) > 0 {
		note := "some projects were not linted or are incomplete: " + strings.Join(failed, "; ")
		if meta.Note != "" {
			note = meta.Note + "; " + note
		}
		meta.Note = note
	}
	data, _ := json.Marshal(combine(tool, merged))
	if err := os.WriteFile(filepath.Join(outDir, tool+".json"), data, 0o600); err != nil {
		meta.Status, meta.Error = "error", "could not write the merged report"
		return
	}
	meta.Status, meta.Exit = "ran", lastExit
}

func projectHasMarker(tool, dir string) bool {
	for _, m := range projectMarkers[tool] {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}

// splitReport returns one project's report items. Go reports are relative to
// the module, so its paths gain the module's directory; ESLint and Dart print
// absolute paths that the parser makes relative.
func splitReport(tool string, data []byte, project string) ([]json.RawMessage, bool) {
	switch tool {
	case "golangci-lint":
		var r struct {
			Issues []map[string]any `json:"Issues"`
		}
		if json.Unmarshal(data, &r) != nil {
			return nil, false
		}
		out := make([]json.RawMessage, 0, len(r.Issues))
		for _, issue := range r.Issues {
			if pos, ok := issue["Pos"].(map[string]any); ok {
				if name, ok := pos["Filename"].(string); ok {
					pos["Filename"] = strings.TrimPrefix(path.Join(project, name), "./")
				}
			}
			raw, _ := json.Marshal(issue)
			out = append(out, raw)
		}
		return out, true
	case "eslint":
		var r []json.RawMessage
		return r, json.Unmarshal(data, &r) == nil
	case "dart-analyze":
		var r struct {
			Diagnostics []json.RawMessage `json:"diagnostics"`
		}
		return r.Diagnostics, json.Unmarshal(data, &r) == nil
	}
	return nil, false
}

// combine writes the merged items in the tool's own report shape.
func combine(tool string, items []json.RawMessage) any {
	if items == nil {
		items = []json.RawMessage{}
	}
	switch tool {
	case "golangci-lint":
		return map[string]any{"Issues": items}
	case "dart-analyze":
		return map[string]any{"diagnostics": items}
	}
	return items
}

// maxClangFiles bounds how many sources one clang-tidy run analyses, and
// clangBatch how many it hands to one invocation.
const (
	maxClangFiles = 3000
	maxClangIncs  = 100
	clangBatch    = 25
)

// clangChecks apply when the repository has no .clang-tidy of its own: the
// static analyzer and the bug-prone checks.
const clangChecks = "-*,clang-analyzer-*,bugprone-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier"

// lintClangTidy is clang-tidy without a build system. A committed
// compile_commands.json points at another machine, so the runner compiles each
// source on its own, with every directory that holds a header on the include
// path. Project headers resolve; a third-party header does not, and the
// tool's note says how many sources stopped at one.
func (s *Server) lintClangTidy(ctx context.Context, j *job, console *capture, binary, src, out string, meta *qa.LintMeta) {
	var sources []string
	incs := map[string]bool{}
	hasConfig := false
	_ = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git", "third_party", "external", "build", "Pods":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		rel = filepath.ToSlash(rel)
		switch strings.ToLower(path.Ext(rel)) {
		case ".c", ".cc", ".cpp", ".cxx", ".c++":
			if len(sources) < maxClangFiles {
				sources = append(sources, rel)
			}
		case ".h", ".hh", ".hpp", ".hxx", ".h++", ".ipp":
			if dir := path.Dir(rel); len(incs) < maxClangIncs {
				incs[dir] = true
			}
		}
		if d.Name() == ".clang-tidy" {
			hasConfig = true
		}
		return nil
	})
	sort.Strings(sources)
	if len(sources) == 0 {
		// Headers only: there is nothing to compile.
		_ = os.WriteFile(out, nil, 0o600)
		meta.Status, meta.Note = "ran", "the repository has no C or C++ source files, only headers, which clang-tidy cannot analyse on their own"
		return
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
	if err != nil {
		meta.Status, meta.Error = "error", "could not open the output file"
		return
	}
	defer f.Close()
	if s.cfg.JobUID != 0 {
		_ = f.Chown(s.cfg.JobUID, s.cfg.JobGID)
	}
	j.stdout = f
	defer func() { j.stdout = nil }()
	flags := []string{"--", "-I."}
	dirs := make([]string, 0, len(incs))
	for d := range incs {
		if d != "." {
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		flags = append(flags, "-I"+d)
	}
	console.WriteString("== lint clang-tidy " + itoa(len(sources)) + " sources\n")
	failed, last := 0, (*int)(nil)
	for i := 0; i < len(sources); i += clangBatch {
		args := []string{"--quiet", "--use-color=false"}
		if !hasConfig {
			args = append(args, "--checks="+clangChecks)
		}
		args = append(args, sources[i:min(i+clangBatch, len(sources))]...)
		code, err := s.command(ctx, j, binary, append(args, flags...), src, console)
		last = &code
		if ctx.Err() != nil {
			meta.Status, meta.Error = "error", "stopped"
			return
		}
		// 0 is clean or warnings, 1 is a compile error in a source.
		if err != nil || code > 1 {
			failed++
		}
	}
	meta.Exit = last
	data, _ := os.ReadFile(out)
	switch {
	case failed*clangBatch >= len(sources):
		meta.Status, meta.Error = "error", "clang-tidy failed on every batch of sources; see console.log"
		return
	}
	var notes []string
	if failed > 0 {
		notes = append(notes, itoa(failed)+" batch(es) of sources could not be analysed")
	}
	if n := qa.ClangTidyMissingIncludes(data); n > 0 {
		notes = append(notes, itoa(n)+" include(s) of third-party or generated headers were not found (dependencies are not installed), so the analysis of those sources is incomplete")
	}
	meta.Note = strings.Join(notes, "; ")
	meta.Status = "ran"
}
