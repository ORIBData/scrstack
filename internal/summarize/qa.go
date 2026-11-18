package summarize

import (
	"fmt"
	"strings"

	"github.com/ORIBData/scrstack/internal/llm/guard"
)

// QAPromptVersion is stored with every QA triage document.
const QAPromptVersion = "qa-triage-1"

// QATypes are the finding types of QA runs that may be triaged by a model.
// Unlike AllowedTypes, their facts include file paths, test and rule names
// and the tool's own message, and a failing test's error text can echo what
// the target returned. A triage therefore goes only to a provider that may
// receive source code (self-hosted, or hosted and acknowledged).
var QATypes = map[string]bool{"qa_failure": true, "qa_performance": true, "qa_untested": true, "qa_lint": true, "qa_lint_config": true, "qa_config": true}

// QAFinding is one QA entry as a model may see it: identifiers, severity,
// title and a few short facts (location, rule, message, thresholds). It never
// holds source code, request or response bodies, or credentials.
type QAFinding struct {
	ID       string
	Type     string
	Severity string
	Title    string
	Facts    []string
}

// Clip shortens text for a prompt on a rune boundary.
func Clip(s string, n int) string { return clip(s, n) }

// Block describes a QA entry as lines.
func (f QAFinding) Block() string {
	var b strings.Builder
	fmt.Fprintf(&b, "finding_id: %s\nseverity: %s\ntype: %s\ntitle: %s\n", f.ID, f.Severity, f.Type, clip(f.Title, 300))
	for i, fact := range f.Facts {
		if i >= 10 {
			break
		}
		fmt.Fprintf(&b, "%s\n", clip(fact, 500))
	}
	return b.String()
}

const qaCommon = "You help an engineering team fix problems found by automated QA: API tests, load tests and linters. " +
	"Use only the facts given. Do not invent files, functions, endpoints, rule meanings or links, and do not include URLs. " +
	"Never output credentials, keys or tokens. " + guard.DataRule + " Answer with JSON that matches the schema and nothing else."

// QAAdvisorySystem instructs the per-entry QA advisories.
const QAAdvisorySystem = "For each QA entry in the list, explain in plain words what went wrong, the most likely cause, and the concrete steps to fix it. " +
	"Say whether the application or the test (or the linter configuration) is the more likely thing to change, and why. " +
	"For a lint entry give the change to make for the rule named; for a failed scenario use the failure text; for a breached load threshold name what to measure first; " +
	"for an untested operation say what a first test should check. If the facts are not enough to be sure, say what to look at first instead of guessing. " +
	"Keep each explanation under 120 words. " + qaCommon

// QASummarySystem instructs the QA run summary.
const QASummarySystem = "Write a summary of one QA run for the engineers who must fix it: a short headline, an overall risk_level for shipping this commit, " +
	"a plain summary of what failed and what it probably means, up to 8 priorities (each names one finding_id from the list, what to do and why), " +
	"and a progress_note comparing with the previous summary when one is given. " + qaCommon

// QAAdvisoryPrompt builds the user message of a batch of QA advisories.
func QAAdvisoryPrompt(findings []QAFinding) string {
	return "Write an advisory for each of these QA entries:\n" + guard.Untrusted("qa_findings", qaBlocks(findings))
}

// QAContext is what the QA summary may know besides the entries.
type QAContext struct {
	Asset, Ref, Commit string
	Kind, Status       string
	Counts             map[string]int
	Passed, Failed     int // scenarios, for a functional run
	Issues             int // lint issues, for a lint run
	Previous           string
}

// QASummaryPrompt builds the user message of a QA run summary.
func QASummaryPrompt(c QAContext, findings []QAFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "QA %s run of %s (ref %s, commit %s) ended %s.\n", clip(c.Kind, 20), clip(c.Asset, 200), clip(c.Ref, 100), clip(c.Commit, 12), clip(c.Status, 20))
	switch c.Kind {
	case "functional":
		fmt.Fprintf(&b, "Scenarios: %d passed, %d failed.\n", c.Passed, c.Failed)
	case "lint":
		fmt.Fprintf(&b, "Lint issues: %d.\n", c.Issues)
	}
	fmt.Fprintf(&b, "Entries by severity: critical %d, high %d, medium %d, low %d.\n\n", c.Counts["critical"], c.Counts["high"], c.Counts["medium"], c.Counts["low"])
	if c.Previous != "" {
		b.WriteString("Previous QA summary of this asset:\n" + guard.Untrusted("previous_summary", clip(c.Previous, 1500)) + "\n\n")
	}
	b.WriteString("The most important entries:\n")
	b.WriteString(guard.Untrusted("qa_findings", qaBlocks(findings)))
	return b.String()
}

func qaBlocks(findings []QAFinding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = f.Block()
	}
	return strings.Join(parts, "\n")
}

// RenderQASummary is the stored text of a QA run summary.
func RenderQASummary(a Assessment, titles map[string]string, c QAContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nRisk level: %s\nQA %s run of %s (ref %s, commit %s), %s.\n\n%s\n", a.Headline, a.RiskLevel, c.Kind, c.Asset, c.Ref, clip(c.Commit, 8), c.Status, a.Summary)
	if len(a.Priorities) > 0 {
		b.WriteString("\nPriorities:\n")
		for i, p := range a.Priorities {
			fmt.Fprintf(&b, "%d. %s Why: %s [%s]\n", i+1, p.Action, p.Why, clip(titles[p.FindingID], 120))
		}
	}
	if a.ProgressNote != "" {
		fmt.Fprintf(&b, "\nProgress: %s\n", a.ProgressNote)
	}
	b.WriteString("\n" + QANotice + "\n")
	return b.String()
}

// QANotice marks every stored QA text as written by a model.
const QANotice = "Written by a language model from the QA results above; not verified. Check the cause before changing code."

// RenderQAAdvisory is the stored text of one QA advisory.
func RenderQAAdvisory(a Advisory, f QAFinding) string {
	return fmt.Sprintf("%s\nSeverity: %s. Urgency: %s.\n\n%s\n\nRecommended action: %s\n\n%s\n", clip(f.Title, 300), f.Severity, a.Urgency, a.Explanation, a.RecommendedAction, QANotice)
}
