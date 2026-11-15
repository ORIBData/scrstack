package license

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Effects of a policy decision, from most to least lenient.
const (
	Allow  = "allow"
	Review = "review"
	Deny   = "deny"
)

// Distribution models (LIC-005).
const (
	Internal    = "internal"
	SaaS        = "saas"
	Distributed = "distributed"
)

// Distributions lists the asset distribution models.
var Distributions = []string{Internal, SaaS, Distributed}

// ValidDistribution reports whether d is a distribution model.
func ValidDistribution(d string) bool { return d == Internal || d == SaaS || d == Distributed }

func rank(effect string) int {
	switch effect {
	case Deny:
		return 2
	case Review:
		return 1
	}
	return 0
}

// Policy is a licence policy document (LIC-004), validated against
// data/policy.schema.json (served at GET /schemas/license-policy).
type Policy struct {
	Name        string                       `json:"name"`
	Description string                       `json:"description,omitempty"`
	Enforcing   bool                         `json:"enforcing"`
	Default     string                       `json:"default"`
	Severity    map[string]string            `json:"severity,omitempty"`
	Matrix      map[string]map[string]string `json:"matrix"`
	Rules       []Rule                       `json:"rules"`
}

// Rule matches licences by id, category or package, optionally narrowed by
// path, dependency scope, asset and distribution.
type Rule struct {
	Effect        string      `json:"effect"`
	Licenses      []string    `json:"licenses,omitempty"`
	Categories    []string    `json:"categories,omitempty"`
	Packages      []string    `json:"packages,omitempty"`
	Paths         []string    `json:"paths,omitempty"`
	Scope         string      `json:"scope,omitempty"`
	Assets        []uuid.UUID `json:"assets,omitempty"`
	Distributions []string    `json:"distributions,omitempty"`
	Reason        string      `json:"reason,omitempty"`
}

// Schema returns the policy JSON Schema.
func Schema() json.RawMessage {
	raw, _ := data.ReadFile("data/policy.schema.json")
	return raw
}

// CorporateDefault returns the built-in corporate-default policy.
func CorporateDefault() Policy {
	raw, _ := data.ReadFile("data/corporate-default.json")
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		panic(err)
	}
	return p
}

// ErrPolicy wraps a policy validation failure.
var ErrPolicy = errors.New("invalid licence policy")

var policyName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ParsePolicy decodes and validates a policy document, rejecting unknown
// fields. The checks mirror the published schema.
func ParsePolicy(raw []byte) (Policy, error) {
	var p Policy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	if decoder.More() {
		return p, fmt.Errorf("%w: trailing data", ErrPolicy)
	}
	return p, p.Validate()
}

// Validate checks a policy against the schema's constraints.
func (p Policy) Validate() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, args...))
	}
	if !policyName.MatchString(p.Name) {
		return fail("name must match %s", policyName)
	}
	if len(p.Description) > 1000 {
		return fail("description too long")
	}
	if rank(p.Default) == 0 && p.Default != Allow {
		return fail("default must be allow, review or deny")
	}
	if p.Matrix == nil {
		return fail("matrix is required")
	}
	for category, row := range p.Matrix {
		if !ValidCategory(category) {
			return fail("unknown category %q", category)
		}
		for distribution, effect := range row {
			if !ValidDistribution(distribution) || (effect != Allow && effect != Review && effect != Deny) {
				return fail("matrix.%s.%s is invalid", category, distribution)
			}
		}
	}
	for effect, severity := range p.Severity {
		allowed := map[string]bool{"high": true, "medium": true, "low": true}
		if effect == Deny {
			allowed["critical"] = true
		} else if effect != Review {
			return fail("severity applies to deny and review only")
		}
		if !allowed[severity] {
			return fail("severity.%s is invalid", effect)
		}
	}
	if len(p.Rules) > 500 {
		return fail("at most 500 rules")
	}
	for i, r := range p.Rules {
		if r.Effect != Allow && r.Effect != Review && r.Effect != Deny {
			return fail("rules[%d].effect is invalid", i)
		}
		if len(r.Licenses)+len(r.Categories)+len(r.Packages) == 0 {
			return fail("rules[%d] needs licenses, categories or packages", i)
		}
		if len(r.Licenses) > 200 || len(r.Categories) > 9 || len(r.Packages) > 200 || len(r.Paths) > 50 || len(r.Assets) > 200 || len(r.Distributions) > 3 || len(r.Reason) > 500 {
			return fail("rules[%d] exceeds a list limit", i)
		}
		for _, id := range r.Licenses {
			if _, ok := canonicalID(id); !ok && id != NoAssertion {
				return fail("rules[%d].licenses: %q is not an SPDX id or LicenseRef", i, id)
			}
		}
		for _, c := range r.Categories {
			if !ValidCategory(c) {
				return fail("rules[%d].categories: unknown category %q", i, c)
			}
		}
		for _, purl := range r.Packages {
			if !strings.HasPrefix(purl, "pkg:") || len(purl) > 512 {
				return fail("rules[%d].packages must be package URL prefixes", i)
			}
		}
		for _, glob := range r.Paths {
			if glob == "" || len(glob) > 256 {
				return fail("rules[%d].paths is invalid", i)
			}
			if _, err := path.Match(strings.ReplaceAll(glob, "**", "*"), ""); err != nil {
				return fail("rules[%d].paths: bad pattern %q", i, glob)
			}
		}
		if r.Scope != "" && r.Scope != "dev" && r.Scope != "runtime" {
			return fail("rules[%d].scope must be dev or runtime", i)
		}
		for _, d := range r.Distributions {
			if !ValidDistribution(d) {
				return fail("rules[%d].distributions: unknown model %q", i, d)
			}
		}
	}
	return nil
}

// Subject is the component a licence decision is about.
type Subject struct {
	Expression   string
	Distribution string
	Asset        uuid.UUID
	PURL         string
	Path         string
	// Dev is true for development-only dependencies.
	Dev bool
}

// Decision is the policy result for one component (LIC-004).
type Decision struct {
	Effect     string `json:"effect"`
	Expression string `json:"expression"`
	// Category is the category of the licence that decided the effect.
	Category string `json:"category"`
	// Basis names what decided: "rule:<n>", "matrix:<category>/<distribution>" or "default".
	Basis  string `json:"basis"`
	Reason string `json:"reason,omitempty"`
	// Licenses are the licence ids that determined the outcome; for OR the
	// most lenient choice, for AND the strictest member.
	Licenses []string `json:"licenses"`
}

// SeverityFor returns the register severity for a decision's effect.
func (p Policy) SeverityFor(effect string) string {
	if s := p.Severity[effect]; s != "" {
		return s
	}
	if effect == Deny {
		return "high"
	}
	return "medium"
}

// Evaluate decides a component's licence against the policy. An expression
// that does not parse, and NOASSERTION, are evaluated as category unknown.
func (p Policy) Evaluate(c *Catalog, s Subject) Decision {
	n, err := Parse(s.Expression)
	if err != nil || s.Expression == NoAssertion {
		d := p.leaf(c, &Node{ID: NoAssertion}, Unknown, s)
		d.Expression = NoAssertion
		return d
	}
	d := p.node(c, n, s)
	d.Expression = n.String()
	return d
}

func (p Policy) node(c *Catalog, n *Node, s Subject) Decision {
	if n.Op == "" {
		return p.leaf(c, n, c.LeafCategory(n), s)
	}
	left, right := p.node(c, n.Left, s), p.node(c, n.Right, s)
	pickLeft := rank(left.Effect) >= rank(right.Effect)
	if n.Op == "OR" {
		pickLeft = rank(left.Effect) <= rank(right.Effect)
	}
	if pickLeft {
		if n.Op == "AND" && rank(left.Effect) == rank(right.Effect) {
			left.Licenses = append(left.Licenses, right.Licenses...)
		}
		return left
	}
	return right
}

func (p Policy) leaf(c *Catalog, n *Node, category string, s Subject) Decision {
	id := n.ID
	label := n.String()
	for i, r := range p.Rules {
		if r.matches(id, category, s) {
			return Decision{Effect: r.Effect, Category: category, Basis: fmt.Sprintf("rule:%d", i), Reason: r.Reason, Licenses: []string{label}}
		}
	}
	if effect := p.Matrix[category][s.Distribution]; effect != "" {
		return Decision{Effect: effect, Category: category, Basis: "matrix:" + category + "/" + s.Distribution, Licenses: []string{label}}
	}
	return Decision{Effect: p.Default, Category: category, Basis: "default", Licenses: []string{label}}
}

func (r Rule) matches(id, category string, s Subject) bool {
	if len(r.Licenses) > 0 && !containsFold(r.Licenses, id) {
		return false
	}
	if len(r.Categories) > 0 && !contains(r.Categories, category) {
		return false
	}
	if len(r.Packages) > 0 {
		matched := false
		for _, prefix := range r.Packages {
			if strings.HasPrefix(strings.ToLower(s.PURL), strings.ToLower(prefix)) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	if len(r.Paths) > 0 {
		matched := false
		for _, glob := range r.Paths {
			if globMatch(glob, s.Path) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	if (r.Scope == "dev" && !s.Dev) || (r.Scope == "runtime" && s.Dev) {
		return false
	}
	if len(r.Assets) > 0 {
		matched := false
		for _, a := range r.Assets {
			matched = matched || a == s.Asset
		}
		if !matched {
			return false
		}
	}
	if len(r.Distributions) > 0 && !contains(r.Distributions, s.Distribution) {
		return false
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(list []string, id string) bool {
	for _, x := range list {
		if canonical, ok := canonicalID(x); x == id || (ok && canonical == id) {
			return true
		}
	}
	return false
}

// globMatch matches a slash-separated path; "**" matches any number of
// directories, other segments use path.Match.
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
