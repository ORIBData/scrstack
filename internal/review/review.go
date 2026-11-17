// Package review prepares and checks the language-model code review (the
// "AI assessment"): which source files to read, the prompt, the answer's
// schema and a validating parser. It has no dependency on the database or the
// model client.
//
// A review is advisory. The model reads one file at a time and reports
// production risks, logic bugs, lint-class problems, security weaknesses and
// performance problems. Its answer is untrusted text: it is parsed against a
// schema, line numbers are checked against the file, and anything that does
// not fit is dropped and counted. Results never gate a verdict.
package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/ORIBData/scrstack/internal/llm/guard"
)

// PromptVersion is recorded with every stored result so a statement can be
// traced to the prompt that produced it.
const PromptVersion = "code-review-1"

// DefaultMaxFileBytes bounds one file sent to the model, about 16,000 tokens.
// Larger files are skipped and counted rather than cut, because a model asked
// about half a file reports problems that are not there. SCRS_AI_REVIEW_MAX_FILE_BYTES
// changes it (4 KiB to 256 KiB): lower it for a model on CPU, and keep it well
// inside the model server's context window.
const DefaultMaxFileBytes = 48 << 10

// MaxFileBytes is the limit in force, read once at start.
var MaxFileBytes = maxFileBytes()

func maxFileBytes() int64 {
	n, err := strconv.ParseInt(os.Getenv("SCRS_AI_REVIEW_MAX_FILE_BYTES"), 10, 64)
	if err != nil || n < 4<<10 || n > 256<<10 {
		return DefaultMaxFileBytes
	}
	return n
}

// MaxIssuesPerFile bounds what is kept from one answer.
const MaxIssuesPerFile = 10

// Categories of issue.
var Categories = []string{"production_risk", "logic_bug", "lint", "security", "performance"}

var levels = []string{"low", "medium", "high"}

// Issue is one validated finding of the model.
type Issue struct {
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	Confidence   string `json:"confidence"`
	Title        string `json:"title"`
	Explanation  string `json:"explanation"`
	SuggestedFix string `json:"suggested_fix"`
	LineStart    int    `json:"line_start"`
	LineEnd      int    `json:"line_end"`
}

// Schema is the JSON Schema of the model's answer. Every field is required,
// as strict structured output demands.
var Schema = json.RawMessage(`{
 "type":"object",
 "properties":{"findings":{"type":"array","items":{
  "type":"object",
  "properties":{
   "category":{"type":"string","enum":["production_risk","logic_bug","lint","security","performance"]},
   "severity":{"type":"string","enum":["low","medium","high"]},
   "confidence":{"type":"string","enum":["low","medium","high"]},
   "title":{"type":"string"},
   "explanation":{"type":"string"},
   "suggested_fix":{"type":"string"},
   "line_start":{"type":"integer"},
   "line_end":{"type":"integer"}},
  "required":["category","severity","confidence","title","explanation","suggested_fix","line_start","line_end"],
  "additionalProperties":false}}},
 "required":["findings"],
 "additionalProperties":false}`)

// SystemPrompt instructs the model. Code arrives inside <untrusted-data>.
var SystemPrompt = `You are a senior software engineer reviewing one source file. Find defects a careful human reviewer would raise, in these categories:
- production_risk: what can break in production (unhandled errors, missing timeouts, unbounded retries or growth, resource leaks, races, panics on bad input, unsafe defaults).
- logic_bug: wrong conditions, off-by-one errors, wrong operators, misuse of null or nil, incorrect error handling.
- lint: dead or unused code, shadowed names, inconsistent error handling, deprecated APIs, style problems that hide bugs.
- security: injection, unsafe deserialization, missing authorisation, weak cryptography, path traversal, SSRF.
- performance: queries in loops, quadratic work, blocking calls in hot paths.

Rules:
- Report only problems you can point to in this file. Use the line numbers printed before each line.
- Prefer a few real problems to many doubtful ones. At most ` + fmt.Sprint(MaxIssuesPerFile) + `. An empty list is a correct answer.
- severity is high only when a concrete failure or exploit is evident from the code shown; confidence says how sure you are.
- Do not quote code beyond a short identifier, and never output credentials, keys or tokens.
- suggested_fix says in words what to change.
- ` + guard.DataRule + `
- Answer with JSON that matches the schema and nothing else.`

// UserPrompt wraps a file, with line numbers, as untrusted data.
func UserPrompt(filePath, code string) string {
	return "Review this " + Language(filePath) + " file: " + filePath + "\n\n" + guard.Untrusted("source:"+filePath, NumberLines(code))
}

// NumberLines prefixes every line with its number, so the model's line
// references can be checked.
func NumberLines(code string) string {
	lines := strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n")
	var b strings.Builder
	for i, l := range lines {
		fmt.Fprintf(&b, "%d: %s\n", i+1, l)
	}
	return b.String()
}

// CountLines returns the number of lines NumberLines would print.
func CountLines(code string) int {
	return strings.Count(strings.ReplaceAll(code, "\r\n", "\n"), "\n") + 1
}

var languages = map[string]string{
	".go": "Go", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
	".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".rs": "Rust", ".c": "C", ".cc": "C++", ".cpp": "C++",
	".swift": "Swift", ".scala": "Scala", ".sh": "Shell",
}

// Language names a file's language from its extension, or "source".
func Language(p string) string {
	if l, ok := languages[strings.ToLower(path.Ext(p))]; ok {
		return l
	}
	return "source"
}

var skipDirs = map[string]bool{"node_modules": true, "vendor": true, "dist": true, "build": true, "target": true, ".git": true, "testdata": true, "fixtures": true, "__pycache__": true, ".venv": true, "venv": true, "third_party": true, "generated": true, "mocks": true, "migrations": true, "e2e": true, "__tests__": true, "test": true, "tests": true}

// IsTest reports a test file by its name or directory.
func IsTest(p string) bool {
	base := path.Base(p)
	if strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") || strings.HasSuffix(base, "_test.py") || strings.HasSuffix(base, "Test.java") || strings.HasSuffix(base, "Test.kt") || strings.HasSuffix(base, "Tests.cs") {
		return true
	}
	for _, part := range strings.Split(path.Dir(p), "/") {
		if part == "test" || part == "tests" || part == "__tests__" {
			return true
		}
	}
	return false
}

// Candidate reports whether a file is worth reviewing: a known source
// language, not a test, not vendored, generated or minified, and small
// enough to send whole.
func Candidate(rel string, size int64) bool {
	if size <= 0 || size > MaxFileBytes {
		return false
	}
	if _, ok := languages[strings.ToLower(path.Ext(rel))]; !ok || IsTest(rel) {
		return false
	}
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if skipDirs[part] {
			return false
		}
	}
	base := strings.ToLower(path.Base(rel))
	return !(strings.Contains(base, ".min.") || strings.HasSuffix(base, ".pb.go") || strings.HasSuffix(base, "_gen.go") || strings.Contains(base, ".generated.") || strings.HasSuffix(base, ".d.ts"))
}

// hot words in a path mark code that tends to hold production risk.
var hot = []string{"auth", "login", "session", "token", "crypto", "password", "payment", "billing", "checkout", "handler", "controller", "route", "api", "service", "db", "repo", "sql", "query", "client", "http", "queue", "worker", "job", "retry", "config", "middleware", "upload", "webhook"}

// Rank orders candidate paths for review: files whose names suggest risk
// first, then by a moderate size (very small files hold little), then by
// name, so the choice is repeatable.
func Rank(paths []string, size func(string) int) []string {
	type scored struct {
		path  string
		score int
	}
	items := make([]scored, 0, len(paths))
	for _, p := range paths {
		lower := strings.ToLower(p)
		score := 0
		for _, w := range hot {
			if strings.Contains(lower, w) {
				score += 3
			}
		}
		if n := size(p); n >= 800 && n <= 24<<10 {
			score += 2
		}
		items = append(items, scored{p, score})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].path < items[j].path
	})
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.path
	}
	return out
}

func oneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Parse validates a model's answer for a file of the given number of lines.
// It accepts JSON alone or inside a code fence. An issue that does not fit the
// schema, names a line outside the file, or has no title is dropped and
// described in problems; at most MaxIssuesPerFile are kept.
func Parse(text string, lines int) (issues []Issue, problems []string) {
	start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, []string{"the answer contains no JSON object"}
	}
	var raw struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &raw); err != nil {
		return nil, []string{"the answer is not valid JSON for the schema"}
	}
	for i, item := range raw.Findings {
		var in Issue
		if err := json.Unmarshal(item, &in); err != nil {
			problems = append(problems, fmt.Sprintf("finding %d: wrong field types", i+1))
			continue
		}
		in.Title, in.Explanation, in.SuggestedFix = clip(in.Title, 200), clip(in.Explanation, 1500), clip(in.SuggestedFix, 1000)
		switch {
		case in.Title == "":
			problems = append(problems, fmt.Sprintf("finding %d: no title", i+1))
			continue
		case !oneOf(in.Category, Categories):
			problems = append(problems, fmt.Sprintf("finding %d: unknown category %q", i+1, clip(in.Category, 30)))
			continue
		case in.LineStart < 1 || in.LineStart > lines:
			problems = append(problems, fmt.Sprintf("finding %d: line %d is outside the file", i+1, in.LineStart))
			continue
		}
		if !oneOf(in.Severity, levels) {
			in.Severity = "low"
		}
		if !oneOf(in.Confidence, levels) {
			in.Confidence = "low"
		}
		if in.LineEnd < in.LineStart {
			in.LineEnd = in.LineStart
		}
		in.LineEnd = min(in.LineEnd, lines)
		if len(issues) == MaxIssuesPerFile {
			problems = append(problems, fmt.Sprintf("more than %d findings; the rest were dropped", MaxIssuesPerFile))
			break
		}
		issues = append(issues, in)
	}
	return issues, problems
}
