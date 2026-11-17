// Package summarize prepares the language-model advisories and summaries of
// an assessment: which findings may be described to a model, the prompts, the
// answer schemas, and validating parsers.
//
// It is built on an allowlist. Only findings of the types in AllowedTypes are
// described, and only through the Finding struct below: identifiers, titles,
// severities, package names and versions, fixed versions and advisory text.
// Evidence, file paths, code and the entries of the AI code review, SAST and
// secret detection never reach a prompt, so these calls are safe to send to a
// hosted provider. Upstream text (titles, advisory details) can be written by
// an attacker, so it is passed as untrusted data and the answers are
// validated: a finding ID must be one that was sent, URLs are removed (a model
// invents links), and lengths are bounded.
package summarize

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ORIBData/scrstack/internal/llm/guard"
)

// PromptVersion is stored with every generated document.
const PromptVersion = "advisory-summary-1"

// AllowedTypes are the finding types whose text may be sent to a model. They
// describe packages, licences, build integrity and configuration, not code.
// Everything else is excluded: ai_review (model-written text about code),
// sast, secret and code (paths and code identifiers), malware, yara and ioc
// matches (file content), posture and qa entries.
var AllowedTypes = map[string]bool{
	"vulnerability": true, "dt_vulnerability": true, "malicious_dependency": true,
	"license": true, "integrity": true, "misconfiguration": true,
}

// Allowed reports whether findings of a type may be described to a model.
func Allowed(findingType string) bool { return AllowedTypes[findingType] }

// Finding is everything about a finding that may reach a prompt.
type Finding struct {
	ID         string
	Type       string
	Severity   string
	Title      string
	AdvisoryID string
	Aliases    []string
	Package    string
	Version    string
	Ecosystem  string
	Status     string
	Fixed      []string
	KEV        bool
	EPSS       float64
	New        bool
	// Detail is the upstream advisory's summary or details.
	Detail string
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// Rank orders findings for attention: severity, then known exploitation (KEV),
// then exploit likelihood (EPSS), then newness, then ID, so the order is
// repeatable.
func Rank(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case severityRank[a.Severity] != severityRank[b.Severity]:
			return severityRank[a.Severity] > severityRank[b.Severity]
		case a.KEV != b.KEV:
			return a.KEV
		case a.EPSS != b.EPSS:
			return a.EPSS > b.EPSS
		case a.New != b.New:
			return a.New
		}
		return a.ID < b.ID
	})
	return out
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Block describes one finding as a short block of lines. Only Finding's
// fields appear.
func (f Finding) Block() string {
	var b strings.Builder
	fmt.Fprintf(&b, "finding_id: %s\nseverity: %s\ntype: %s\ntitle: %s\n", f.ID, f.Severity, f.Type, clip(f.Title, 300))
	if f.AdvisoryID != "" {
		ids := append([]string{f.AdvisoryID}, f.Aliases...)
		if len(ids) > 6 {
			ids = ids[:6]
		}
		fmt.Fprintf(&b, "advisory: %s\n", strings.Join(ids, ", "))
	}
	if f.Package != "" {
		fmt.Fprintf(&b, "package: %s %s (%s)\n", clip(f.Package, 200), clip(f.Version, 80), clip(f.Ecosystem, 40))
	}
	if len(f.Fixed) > 0 {
		fixed := f.Fixed
		if len(fixed) > 5 {
			fixed = fixed[:5]
		}
		fmt.Fprintf(&b, "fixed_in: %s\n", clip(strings.Join(fixed, ", "), 200))
	}
	fmt.Fprintf(&b, "status: %s\n", f.Status)
	if f.KEV {
		b.WriteString("known_exploited: yes\n")
	}
	if f.EPSS > 0 {
		fmt.Fprintf(&b, "exploit_probability: %.2f\n", f.EPSS)
	}
	if f.New {
		b.WriteString("new_in_this_assessment: yes\n")
	}
	if f.Detail != "" {
		fmt.Fprintf(&b, "advisory_text: %s\n", clip(f.Detail, 700))
	}
	return b.String()
}

// Levels of overall risk.
var RiskLevels = []string{"low", "moderate", "high", "critical"}

// Urgencies of a recommended action.
var Urgencies = []string{"immediate", "soon", "scheduled", "monitor"}

// Context is what the assessment summary may know besides the findings.
type Context struct {
	Asset    string // repository or image name
	Ref      string
	Commit   string
	Verdict  string
	Counts   map[string]int // findings by severity, among all allowed types
	Excluded int            // findings of types never described to a model
	Previous string         // the previous summary's text, if any
}

const systemCommon = "You are a security analyst writing for engineers and managers. " +
	"Use only the facts given. Do not invent vulnerabilities, versions, dates or links, and do not include URLs. " +
	"Never output credentials, keys or tokens. " + guard.DataRule + " Answer with JSON that matches the schema and nothing else."

// AssessmentSystem instructs the assessment summary.
const AssessmentSystem = "Write an assessment summary from the findings of one software assessment. " +
	"Give a short headline, an overall risk_level, a plain summary of what matters and why, up to 8 priorities " +
	"(each names one finding_id from the list, what to do and why), and a progress_note comparing with the previous summary when one is given (what was fixed, what is new, what is stuck). " + systemCommon

// AdvisorySystem instructs the per-finding advisories.
const AdvisorySystem = "Write one advisory for each finding in the list: what the problem is in plain words, what to do about it " +
	"(prefer the fixed version when one is given) and how urgent it is. Keep each explanation under 120 words. " + systemCommon

// AssessmentSchema is the JSON Schema of the assessment summary.
var AssessmentSchema = json.RawMessage(`{
 "type":"object",
 "properties":{
  "headline":{"type":"string"},
  "risk_level":{"type":"string","enum":["low","moderate","high","critical"]},
  "summary":{"type":"string"},
  "priorities":{"type":"array","items":{"type":"object","properties":{"finding_id":{"type":"string"},"action":{"type":"string"},"why":{"type":"string"}},"required":["finding_id","action","why"],"additionalProperties":false}},
  "progress_note":{"type":"string"}},
 "required":["headline","risk_level","summary","priorities","progress_note"],
 "additionalProperties":false}`)

// AdvisorySchema is the JSON Schema of a batch of advisories.
var AdvisorySchema = json.RawMessage(`{
 "type":"object",
 "properties":{"advisories":{"type":"array","items":{"type":"object","properties":{
  "finding_id":{"type":"string"},
  "explanation":{"type":"string"},
  "recommended_action":{"type":"string"},
  "urgency":{"type":"string","enum":["immediate","soon","scheduled","monitor"]}},
  "required":["finding_id","explanation","recommended_action","urgency"],"additionalProperties":false}}},
 "required":["advisories"],
 "additionalProperties":false}`)

// AssessmentPrompt builds the user message of an assessment summary.
func AssessmentPrompt(c Context, findings []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Assessment of %s (ref %s, commit %s). Verdict: %s.\n", clip(c.Asset, 200), clip(c.Ref, 100), clip(c.Commit, 12), c.Verdict)
	fmt.Fprintf(&b, "Findings by severity: critical %d, high %d, medium %d, low %d.", c.Counts["critical"], c.Counts["high"], c.Counts["medium"], c.Counts["low"])
	if c.Excluded > 0 {
		fmt.Fprintf(&b, " %d further findings (code analysis and secret detection) are not described here.", c.Excluded)
	}
	b.WriteString("\n\n")
	if c.Previous != "" {
		b.WriteString("Previous summary of this asset:\n" + guard.Untrusted("previous_summary", clip(c.Previous, 1500)) + "\n\n")
	}
	b.WriteString("The most important findings:\n")
	b.WriteString(guard.Untrusted("findings", blocks(findings)))
	return b.String()
}

// AdvisoryPrompt builds the user message of a batch of advisories.
func AdvisoryPrompt(findings []Finding) string {
	return "Write an advisory for each of these findings:\n" + guard.Untrusted("findings", blocks(findings))
}

func blocks(findings []Finding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = f.Block()
	}
	return strings.Join(parts, "\n")
}

var urlPattern = regexp.MustCompile(`(?i)\b(?:https?|ftp)://\S+|\bwww\.\S+`)

// StripURLs removes links from model text; a model invents them, and a
// reader may follow one.
func StripURLs(s string) string { return urlPattern.ReplaceAllString(s, "[link removed]") }

func clean(s string, n int) string { return clip(StripURLs(s), n) }

func oneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// Priority is one prioritised action.
type Priority struct {
	FindingID string `json:"finding_id"`
	Action    string `json:"action"`
	Why       string `json:"why"`
}

// Assessment is a validated assessment summary.
type Assessment struct {
	Headline     string     `json:"headline"`
	RiskLevel    string     `json:"risk_level"`
	Summary      string     `json:"summary"`
	Priorities   []Priority `json:"priorities"`
	ProgressNote string     `json:"progress_note"`
}

func object(text string) ([]byte, bool) {
	start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, false
	}
	return []byte(text[start : end+1]), true
}

// ParseAssessment validates an assessment summary. known holds the finding
// IDs that were sent; a priority naming another ID is dropped.
func ParseAssessment(text string, known map[string]bool) (Assessment, []string) {
	var a Assessment
	raw, ok := object(text)
	if !ok || json.Unmarshal(raw, &a) != nil {
		return a, []string{"the answer is not valid JSON for the schema"}
	}
	var problems []string
	a.Headline, a.Summary, a.ProgressNote = clean(a.Headline, 200), clean(a.Summary, 2500), clean(a.ProgressNote, 800)
	if a.Headline == "" || a.Summary == "" {
		return a, []string{"the answer has no headline or summary"}
	}
	if !oneOf(a.RiskLevel, RiskLevels) {
		problems = append(problems, fmt.Sprintf("unknown risk_level %q", clip(a.RiskLevel, 30)))
		a.RiskLevel = "moderate"
	}
	kept := a.Priorities[:0]
	for _, p := range a.Priorities {
		p.FindingID = strings.TrimSpace(p.FindingID)
		p.Action, p.Why = clean(p.Action, 300), clean(p.Why, 300)
		switch {
		case !known[p.FindingID]:
			problems = append(problems, "a priority names a finding that was not described")
		case p.Action == "":
			problems = append(problems, "a priority has no action")
		case len(kept) >= 8:
			problems = append(problems, "more than 8 priorities; the rest were dropped")
		default:
			kept = append(kept, p)
		}
	}
	a.Priorities = kept
	return a, problems
}

// Advisory is a validated advisory for one finding.
type Advisory struct {
	FindingID         string `json:"finding_id"`
	Explanation       string `json:"explanation"`
	RecommendedAction string `json:"recommended_action"`
	Urgency           string `json:"urgency"`
}

// ParseAdvisories validates a batch of advisories. known holds the finding
// IDs that were sent; one answer per finding is kept.
func ParseAdvisories(text string, known map[string]bool) ([]Advisory, []string) {
	raw, ok := object(text)
	var parsed struct {
		Advisories []Advisory `json:"advisories"`
	}
	if !ok || json.Unmarshal(raw, &parsed) != nil {
		return nil, []string{"the answer is not valid JSON for the schema"}
	}
	var out []Advisory
	var problems []string
	seen := map[string]bool{}
	for _, a := range parsed.Advisories {
		a.FindingID = strings.TrimSpace(a.FindingID)
		a.Explanation, a.RecommendedAction = clean(a.Explanation, 1200), clean(a.RecommendedAction, 600)
		switch {
		case !known[a.FindingID]:
			problems = append(problems, "an advisory names a finding that was not described")
		case seen[a.FindingID]:
			problems = append(problems, "an advisory repeats a finding")
		case a.Explanation == "" || a.RecommendedAction == "":
			problems = append(problems, "an advisory is incomplete")
		default:
			if !oneOf(a.Urgency, Urgencies) {
				a.Urgency = "scheduled"
			}
			seen[a.FindingID] = true
			out = append(out, a)
		}
	}
	return out, problems
}

// Notice marks every stored text as written by a model.
const Notice = "Written by a language model from the findings and advisory text above; not verified."

// RenderAssessment is the stored text of an assessment summary.
func RenderAssessment(a Assessment, titles map[string]string, c Context) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nRisk level: %s\nAssessment of %s (ref %s, commit %s), verdict %s.\n\n%s\n", a.Headline, a.RiskLevel, c.Asset, c.Ref, clip(c.Commit, 8), c.Verdict, a.Summary)
	if len(a.Priorities) > 0 {
		b.WriteString("\nPriorities:\n")
		for i, p := range a.Priorities {
			fmt.Fprintf(&b, "%d. %s Why: %s [%s]\n", i+1, p.Action, p.Why, clip(titles[p.FindingID], 120))
		}
	}
	if a.ProgressNote != "" {
		fmt.Fprintf(&b, "\nProgress: %s\n", a.ProgressNote)
	}
	b.WriteString("\n" + Notice + "\n")
	return b.String()
}

// RenderAdvisory is the stored text of one advisory.
func RenderAdvisory(a Advisory, f Finding) string {
	return fmt.Sprintf("%s\nSeverity: %s. Urgency: %s.\n\n%s\n\nRecommended action: %s\n\n%s\n", clip(f.Title, 300), f.Severity, a.Urgency, a.Explanation, a.RecommendedAction, Notice)
}
