package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// YARA rulesets: team rules written in the Web UI and third-party packs. The
// API validates and stores them; the scanner compiles and runs them with
// YARA-X. Name is the ruleset's namespace and never changes.

// RuleSet is one enabled ruleset as sent to the scanner.
type RuleSet struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`     // hunt, alert or block
	Severity string `json:"severity"` // default when a rule has no severity meta
	Rules    string `json:"rules"`
}

// RulePack is every enabled ruleset, sent as the "rules" scan request part.
type RulePack struct {
	RuleSets []RuleSet `json:"rulesets"`
}

// Limits shared by the API and the scanner, so a saved ruleset is always scannable.
const (
	MaxRuleSetBytes = 16 << 20
	MaxRulePackSize = 32 << 20
	MaxRuleSets     = 200
)

// RuleSeverityScore lists the severities a ruleset or rule meta may name.
var RuleSeverityScore = map[string]int{"critical": 60, "high": 45, "medium": 25, "low": 10, "info": 0}

var (
	RuleSetName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	// include reads files on the scanner host and echoes them in errors.
	includeDirective = regexp.MustCompile(`(?m)^\s*include\s*"`)
	ruleDeclaration  = regexp.MustCompile(`(?m)^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_][A-Za-z0-9_]*`)
)

// Diagnostic is one compiler error or warning, located in the ruleset text.
type Diagnostic struct {
	Level   string `json:"level"` // error or warning
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

// RuleError reports rules that do not compile; Diagnostics locate the cause.
type RuleError struct{ Diagnostics []Diagnostic }

func (e *RuleError) Error() string {
	for _, d := range e.Diagnostics {
		if d.Level == "error" {
			return fmt.Sprintf("rules do not compile: line %d: %s", d.Line, d.Message)
		}
	}
	return "rules do not compile"
}

// CountRules approximates the rules declared in a ruleset, for display.
func CountRules(rules string) int { return len(ruleDeclaration.FindAllStringIndex(rules, -1)) }

// CheckRuleText applies the limits enforced before the compiler runs.
func CheckRuleText(rules string) error {
	switch {
	case len(rules) == 0 || len(rules) > MaxRuleSetBytes:
		return &RuleError{Diagnostics: []Diagnostic{{Level: "error", Message: "rules must be 1 byte to 16 MiB"}}}
	case strings.ContainsRune(rules, 0):
		return &RuleError{Diagnostics: []Diagnostic{{Level: "error", Message: "rules must be text"}}}
	case includeDirective.MatchString(rules):
		return &RuleError{Diagnostics: []Diagnostic{{Level: "error", Message: "include directives are not supported; paste the included rules instead"}}}
	case CountRules(rules) == 0:
		return &RuleError{Diagnostics: []Diagnostic{{Level: "error", Message: "no rule declarations found"}}}
	}
	return nil
}

// CheckPack validates a pack and returns its content version.
func CheckPack(p RulePack) (string, error) {
	if len(p.RuleSets) == 0 || len(p.RuleSets) > MaxRuleSets {
		return "", errors.New("invalid rule pack")
	}
	hash := sha256.New()
	seen := map[string]bool{}
	total := 0
	for _, set := range p.RuleSets {
		total += len(set.Rules)
		if !RuleSetName.MatchString(set.Name) || seen[set.Name] || total > MaxRulePackSize || CheckRuleText(set.Rules) != nil {
			return "", errors.New("invalid rule pack")
		}
		switch set.Mode {
		case "hunt", "alert", "block":
		default:
			return "", errors.New("invalid rule pack mode")
		}
		if _, ok := RuleSeverityScore[set.Severity]; !ok {
			return "", errors.New("invalid rule pack severity")
		}
		seen[set.Name] = true
		fmt.Fprintf(hash, "%d:%s\x00%d:%s\x00", len(set.Name), set.Name, len(set.Rules), set.Rules)
	}
	return hex.EncodeToString(hash.Sum(nil))[:16], nil
}
