// Package sast runs bundled static analyzers (gosec, Bandit, OpenGrep and
// Bearer) and Go reachability (govulncheck) as sandboxed child processes in
// the scrs-sast image, and normalises their results (SAST-001 to SAST-012,
// REA-001 to REA-007). SCRS reads analyzer results; it writes no analysis
// engine of its own (ADR-018).
package sast

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Meta is an analyzer's static metadata (SAST-001, SAST-010).
type Meta struct {
	Name      string   `json:"name"`
	Languages []string `json:"languages"`
	License   string   `json:"license"`
	// RulesLicense is the licence of the bundled rule set, when separate.
	RulesLicense string `json:"rules_license,omitempty"`
	// Redistributable is false for analyzers or rules whose terms bar
	// shipping them outside CreditChek (Elastic License 2.0, Commons Clause).
	Redistributable     bool `json:"redistributable"`
	NeedsNetwork        bool `json:"needs_network"`
	ExecutesProjectCode bool `json:"executes_project_code"`
}

// Analyzer is one bundled tool (SAST-001).
type Analyzer interface {
	Meta() Meta
	Version(ctx context.Context) string
	// Rules counts the rules the analyzer loads, or -1 when unknown.
	Rules() int
	// Applies reports whether the workspace has files for the analyzer.
	Applies(ws *Workspace) bool
	Run(ctx context.Context, ws *Workspace, opts Options) ([]Finding, error)
}

// Options apply to one analyzer run.
type Options struct {
	// CustomRules is a directory of extra OpenGrep rules, if any.
	CustomRules string
	Scratch     string
}

// Finding is the normalised result of SAST-005.
type Finding struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	// Severity is critical, high, medium, low or info.
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence,omitempty"`
	CWE        []string `json:"cwe"`
	Path       string   `json:"path"`
	StartLine  int      `json:"start_line"`
	EndLine    int      `json:"end_line"`
	// CodeHash is the SHA-256 of the normalised surrounding code, so line
	// shifts and added suppression comments do not change the identity.
	CodeHash string `json:"code_hash"`
	// SuppressedInCode is set when an inline marker (nosec, nosemgrep,
	// bearer:disable) silences the finding (SAST-007).
	SuppressedInCode bool   `json:"suppressed_in_code"`
	Suppression      string `json:"suppression,omitempty"`
	Help             string `json:"help,omitempty"`
	Flow             []Step `json:"flow,omitempty"`
	// AlsoReportedBy lists other analyzers' rules at the same place and CWE.
	AlsoReportedBy []string `json:"also_reported_by,omitempty"`
}

// Step is one data-flow step (SAST-008): file and line only, no code.
type Step struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	// ThirdParty marks steps inside dependencies (REA-010).
	ThirdParty bool `json:"third_party,omitempty"`
}

// Workspace is an extracted source tree with its file index.
type Workspace struct {
	Root  string
	Files []string
	// Languages detected from file extensions and manifests (SAST-002).
	Languages map[string]int
	excludes  []string
}

// Limits bound one workspace (SAST-011).
const (
	MaxFiles    = 50000
	maxFileSize = 2 << 20
)

var languageByExt = map[string]string{
	".go": "go", ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
	".dart": "dart", ".php": "php", ".rb": "ruby", ".cs": "csharp", ".scala": "scala", ".rs": "rust", ".c": "c", ".h": "c",
	".sh": "bash", ".html": "html",
}

// skippedDirs are dependency and build directories never analysed as the
// project's own code.
var skippedDirs = map[string]bool{"node_modules": true, "vendor": true, ".git": true, "dist": true, "build": true, "target": true, ".venv": true, "venv": true, "__pycache__": true, "Pods": true, ".dart_tool": true}

// NewWorkspace indexes root. Excludes are path globs ("docs/**").
func NewWorkspace(root string, excludes []string) (*Workspace, bool, error) {
	ws := &Workspace{Root: root, Languages: map[string]int{}, excludes: excludes}
	truncated := false
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (skippedDirs[d.Name()] || ws.Excluded(rel+"/")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || ws.Excluded(rel) {
			return nil
		}
		if len(ws.Files) >= MaxFiles {
			truncated = true
			return filepath.SkipAll
		}
		ws.Files = append(ws.Files, rel)
		if lang, ok := languageByExt[strings.ToLower(path.Ext(rel))]; ok {
			ws.Languages[lang]++
		}
		return nil
	})
	return ws, truncated, err
}

// Excluded applies the asset's path excludes.
func (ws *Workspace) Excluded(rel string) bool {
	for _, glob := range ws.excludes {
		if globMatch(glob, strings.TrimSuffix(rel, "/")) || (strings.HasSuffix(glob, "/**") && strings.HasPrefix(rel, strings.TrimSuffix(glob, "**"))) {
			return true
		}
	}
	return false
}

// Has reports whether the workspace contains any of the languages.
func (ws *Workspace) Has(languages ...string) bool {
	for _, l := range languages {
		if ws.Languages[l] > 0 {
			return true
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pattern, name []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if matchSegments(pattern[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, _ := path.Match(pattern[0], name[0]); !ok {
			return false
		}
		pattern, name = pattern[1:], name[1:]
	}
	return len(name) == 0
}

// Inline suppression markers honoured by the analyzers (SAST-007).
var suppressionMarker = regexp.MustCompile(`(?i)(#\s*nosec\b[^\n]*|//\s*#?nosec\b[^\n]*|nosemgrep\b[^\n]*|bearer:disable\b[^\n]*)`)

// locate reads the finding's lines from the workspace and sets CodeHash and
// the inline-suppression flag. Analyzers run with inline suppressions
// ignored, so SCRS records them instead of losing the finding.
func (ws *Workspace) locate(f *Finding) {
	f.Path = cleanPath(ws.Root, f.Path)
	if f.EndLine < f.StartLine {
		f.EndLine = f.StartLine
	}
	sum := sha256.New()
	sum.Write([]byte(f.Tool + "\x00" + f.RuleID + "\x00" + f.Path + "\x00"))
	full := filepath.Join(ws.Root, filepath.FromSlash(f.Path))
	data, err := os.ReadFile(full)
	if err == nil && len(data) <= maxFileSize && f.StartLine > 0 {
		lines := strings.Split(string(data), "\n")
		from, to := max(f.StartLine-3, 0), min(f.EndLine+2, len(lines))
		for i := from; i < to; i++ {
			line := lines[i]
			// The flagged line and the line above carry inline markers.
			if i >= f.StartLine-2 && i <= f.EndLine-1 {
				if m := suppressionMarker.FindString(line); m != "" {
					f.SuppressedInCode, f.Suppression = true, strings.TrimSpace(m)
				}
			}
			normalised := strings.Join(strings.Fields(suppressionMarker.ReplaceAllString(line, "")), " ")
			normalised = strings.TrimRight(strings.TrimRight(normalised, " "), "/#")
			sum.Write([]byte(strings.TrimSpace(normalised) + "\n"))
		}
	}
	f.CodeHash = hex.EncodeToString(sum.Sum(nil))
}

// cleanPath turns an analyzer path into one relative to the workspace.
func cleanPath(root, p string) string {
	p = strings.TrimPrefix(p, "file://")
	if strings.HasPrefix(p, root) {
		p = strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
	}
	for _, prefix := range []string{"/src/", "./"} {
		p = strings.TrimPrefix(p, prefix)
	}
	return path.Clean("/" + p)[1:]
}

// thirdParty reports dependency paths (REA-010).
func thirdParty(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "node_modules" || seg == "vendor" || seg == "site-packages" || seg == "Pods" {
			return true
		}
	}
	return strings.HasPrefix(p, "pkg/mod/")
}

// correlate records the other analyzers that flagged the same place and
// CWE, so one weakness found twice is visibly one issue.
func correlate(findings []Finding) {
	type key struct {
		path string
		line int
		cwe  string
	}
	seen := map[key][]int{}
	for i, f := range findings {
		for _, cwe := range f.CWE {
			k := key{f.Path, f.StartLine, cwe}
			seen[k] = append(seen[k], i)
		}
	}
	for _, list := range seen {
		for _, i := range list {
			for _, j := range list {
				if findings[i].Tool != findings[j].Tool {
					ref := findings[j].Tool + ":" + findings[j].RuleID
					if !contains(findings[i].AlsoReportedBy, ref) {
						findings[i].AlsoReportedBy = append(findings[i].AlsoReportedBy, ref)
					}
				}
			}
		}
	}
	for i := range findings {
		sort.Strings(findings[i].AlsoReportedBy)
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Run is one analyzer's stage result.
type Run struct {
	Analyzer string  `json:"analyzer"`
	Version  string  `json:"version"`
	Status   string  `json:"status"`
	Detail   string  `json:"detail,omitempty"`
	Findings int     `json:"findings"`
	Seconds  float64 `json:"seconds"`
}

// Request is one analysis job.
type Request struct {
	Analyzers     []string `json:"analyzers"`
	DisabledRules []string `json:"disabled_rules"`
	Excludes      []string `json:"excludes"`
	// CustomRules are OpenGrep rule documents (YAML), by name.
	CustomRules  map[string]string `json:"custom_rules,omitempty"`
	Reachability bool              `json:"reachability"`
	Timeout      time.Duration     `json:"timeout"`
}

// Response is what the analyzer service returns.
type Response struct {
	Runs         []Run          `json:"runs"`
	Findings     []Finding      `json:"findings"`
	Languages    map[string]int `json:"languages"`
	Reachability *Reachability  `json:"reachability,omitempty"`
	// Unsupported lists detected languages no enabled analyzer covers.
	Unsupported []string `json:"unsupported_languages"`
	Truncated   bool     `json:"truncated"`
}

// ruleDisabled matches "tool:rule" or a bare rule id, with "*" globs.
func ruleDisabled(disabled []string, f Finding) bool {
	for _, d := range disabled {
		tool, rule, qualified := strings.Cut(d, ":")
		if !qualified {
			tool, rule = "*", d
		}
		if ok, _ := path.Match(tool, f.Tool); !ok {
			continue
		}
		if ok, _ := path.Match(rule, f.RuleID); ok {
			return true
		}
	}
	return false
}
