// Package license normalises licence data to SPDX license expressions
// (LIC-002), maps licences to categories (LIC-003), evaluates licence policy
// per asset distribution model (LIC-004, LIC-005) and detects licence texts
// (LIC-001). It is a policy aid, not legal advice.
package license

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed data/spdx.json data/categories.json data/policy.schema.json data/corporate-default.json
var data embed.FS

// NoAssertion is the SPDX keyword for "no licence information found".
const NoAssertion = "NOASSERTION"

// Built-in LicenseRefs for common declarations that name no SPDX licence.
// Each has a fixed category; any other unrecognised text becomes
// LicenseRef-scrs-<hash> with category unknown.
var builtinRefs = map[string]struct{ name, category string }{
	"LicenseRef-scrs-public-domain":      {"Public domain dedication (unspecified)", "public_domain"},
	"LicenseRef-scrs-proprietary":        {"Proprietary or commercial licence", "proprietary"},
	"LicenseRef-scrs-bsd-unversioned":    {"BSD licence (variant not stated)", "permissive"},
	"LicenseRef-scrs-mit-style":          {"MIT-style licence (variant not stated)", "permissive"},
	"LicenseRef-scrs-apache-unversioned": {"Apache licence (version not stated)", "permissive"},
	"LicenseRef-scrs-permissive":         {"Permissive licence (not identified)", "permissive"},
	"LicenseRef-scrs-gpl-unversioned":    {"GNU GPL (version not stated)", "strong_copyleft"},
	"LicenseRef-scrs-lgpl-unversioned":   {"GNU LGPL (version not stated)", "weak_copyleft"},
	"LicenseRef-scrs-agpl-unversioned":   {"GNU AGPL (version not stated)", "network_copyleft"},
	"LicenseRef-scrs-mpl-unversioned":    {"Mozilla Public License (version not stated)", "weak_copyleft"},
	"LicenseRef-scrs-artistic":           {"Artistic License (version not stated)", "weak_copyleft"},
	"LicenseRef-scrs-afl-unversioned":    {"Academic Free License (version not stated)", "permissive"},
}

type spdxData struct {
	ListVersion string `json:"license_list_version"`
	Licenses    []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Deprecated bool   `json:"deprecated"`
		OSI        bool   `json:"osi"`
		FSF        bool   `json:"fsf"`
	} `json:"licenses"`
	Exceptions []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Deprecated bool   `json:"deprecated"`
		Linking    bool   `json:"linking"`
	} `json:"exceptions"`
}

// Info describes one SPDX licence.
type Info struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Deprecated bool   `json:"deprecated,omitempty"`
	OSI        bool   `json:"osi_approved,omitempty"`
	FSF        bool   `json:"fsf_libre,omitempty"`
}

var (
	loadOnce    sync.Once
	listVersion string
	licenses    map[string]Info   // lower-case id -> info
	exceptions  map[string]string // lower-case id -> canonical id
	linking     map[string]bool   // canonical exception id -> weakens copyleft
)

func load() {
	loadOnce.Do(func() {
		raw, err := data.ReadFile("data/spdx.json")
		if err != nil {
			panic(err)
		}
		var d spdxData
		if err := json.Unmarshal(raw, &d); err != nil {
			panic(err)
		}
		listVersion = d.ListVersion
		licenses = make(map[string]Info, len(d.Licenses))
		for _, l := range d.Licenses {
			licenses[strings.ToLower(l.ID)] = Info{ID: l.ID, Name: l.Name, Deprecated: l.Deprecated, OSI: l.OSI, FSF: l.FSF}
		}
		exceptions = make(map[string]string, len(d.Exceptions))
		linking = map[string]bool{}
		for _, e := range d.Exceptions {
			exceptions[strings.ToLower(e.ID)] = e.ID
			linking[e.ID] = e.Linking
		}
	})
}

// ListVersion is the embedded SPDX License List version.
func ListVersion() string { load(); return listVersion }

// Lookup returns the SPDX licence with this id (case-insensitive).
func Lookup(id string) (Info, bool) {
	load()
	if ref, ok := builtinRefs[id]; ok {
		return Info{ID: id, Name: ref.name}, true
	}
	i, ok := licenses[strings.ToLower(id)]
	return i, ok
}

// Node is a parsed SPDX license expression.
type Node struct {
	// Op is "AND" or "OR" for compound nodes and "" for a licence.
	Op          string
	Left, Right *Node
	// ID is an SPDX licence id or LicenseRef; Exception the WITH exception.
	ID        string
	Exception string
}

func (n *Node) String() string {
	if n == nil {
		return NoAssertion
	}
	if n.Op == "" {
		if n.Exception != "" {
			return n.ID + " WITH " + n.Exception
		}
		return n.ID
	}
	side := func(c *Node) string {
		// AND binds tighter than OR: an OR operand of AND needs parentheses.
		if c.Op == "OR" && n.Op == "AND" {
			return "(" + c.String() + ")"
		}
		return c.String()
	}
	return side(n.Left) + " " + n.Op + " " + side(n.Right)
}

// Leaves returns the licence nodes of an expression, left to right.
func (n *Node) Leaves() []*Node {
	if n == nil {
		return nil
	}
	if n.Op == "" {
		return []*Node{n}
	}
	return append(n.Left.Leaves(), n.Right.Leaves()...)
}

var tokenPattern = regexp.MustCompile(`\(|\)|[A-Za-z0-9.+:-]+`)

// ErrSyntax means the text is not a valid SPDX license expression.
var ErrSyntax = errors.New("invalid SPDX license expression")

// Parse reads a strict SPDX license expression. Operators are accepted in
// any case; licence ids must be SPDX ids or LicenseRef-/DocumentRef- refs.
func Parse(expression string) (*Node, error) {
	load()
	if len(expression) > 2000 {
		return nil, ErrSyntax
	}
	stripped := tokenPattern.ReplaceAllString(expression, "")
	if strings.TrimSpace(stripped) != "" {
		return nil, ErrSyntax
	}
	tokens := tokenPattern.FindAllString(expression, -1)
	if len(tokens) == 0 || len(tokens) > 400 {
		return nil, ErrSyntax
	}
	p := &parser{tokens: tokens}
	n, err := p.or()
	if err != nil || p.pos != len(tokens) {
		return nil, ErrSyntax
	}
	return n, nil
}

type parser struct {
	tokens []string
	pos    int
	depth  int
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *parser) or() (*Node, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "OR") {
		p.pos++
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		left = &Node{Op: "OR", Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) and() (*Node, error) {
	left, err := p.term()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "AND") {
		p.pos++
		right, err := p.term()
		if err != nil {
			return nil, err
		}
		left = &Node{Op: "AND", Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) term() (*Node, error) {
	t := p.peek()
	switch {
	case t == "(":
		if p.depth++; p.depth > 20 {
			return nil, ErrSyntax
		}
		p.pos++
		n, err := p.or()
		if err != nil || p.peek() != ")" {
			return nil, ErrSyntax
		}
		p.pos++
		p.depth--
		return n, nil
	case t == "" || t == ")" || isOperator(t):
		return nil, ErrSyntax
	}
	p.pos++
	id, ok := canonicalID(t)
	if !ok {
		return nil, ErrSyntax
	}
	n := &Node{ID: id}
	if modern, ok := deprecatedWith[id]; ok {
		n.ID, n.Exception = modern[0], modern[1]
		return n, nil
	}
	if strings.EqualFold(p.peek(), "WITH") {
		p.pos++
		e, ok := exceptions[strings.ToLower(p.peek())]
		if !ok {
			return nil, ErrSyntax
		}
		p.pos++
		n.Exception = e
	}
	return n, nil
}

func isOperator(t string) bool {
	return strings.EqualFold(t, "AND") || strings.EqualFold(t, "OR") || strings.EqualFold(t, "WITH")
}

var refPattern = regexp.MustCompile(`^(DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$`)

// deprecatedWith maps deprecated "licence-with-exception" ids to the
// WITH form that replaced them.
var deprecatedWith = map[string][2]string{
	"GPL-2.0-with-autoconf-exception":  {"GPL-2.0-only", "Autoconf-exception-2.0"},
	"GPL-2.0-with-bison-exception":     {"GPL-2.0-only", "Bison-exception-2.2"},
	"GPL-2.0-with-classpath-exception": {"GPL-2.0-only", "Classpath-exception-2.0"},
	"GPL-2.0-with-font-exception":      {"GPL-2.0-only", "Font-exception-2.0"},
	"GPL-2.0-with-GCC-exception":       {"GPL-2.0-only", "GCC-exception-2.0"},
	"GPL-3.0-with-autoconf-exception":  {"GPL-3.0-only", "Autoconf-exception-3.0"},
	"GPL-3.0-with-GCC-exception":       {"GPL-3.0-only", "GCC-exception-3.1"},
	"eCos-2.0":                         {"GPL-2.0-or-later", "eCos-exception-2.0"},
	"wxWindows":                        {"LGPL-2.0-or-later", "WxWindows-exception-3.1"},
}

// deprecatedGNU maps deprecated GNU ids to their -only/-or-later forms.
var deprecatedGNU = regexp.MustCompile(`^(?i)(A?GPL|LGPL|GFDL)-([0-9.]+)(\+?)$`)

// canonicalID returns the canonical SPDX id for a token, mapping deprecated
// GNU ids (GPL-2.0, GPL-2.0+) to their current forms.
func canonicalID(token string) (string, bool) {
	if refPattern.MatchString(token) {
		return token, true
	}
	if m := deprecatedGNU.FindStringSubmatch(token); m != nil {
		if _, ok := licenses[strings.ToLower(m[1]+"-"+m[2])]; ok {
			suffix := "-only"
			if m[3] == "+" {
				suffix = "-or-later"
			}
			if info, ok := licenses[strings.ToLower(m[1]+"-"+m[2]+suffix)]; ok {
				return info.ID, true
			}
		}
	}
	if info, ok := licenses[strings.ToLower(token)]; ok {
		return info.ID, true
	}
	// "Apache-2.0+" style: an SPDX id followed by "+".
	if base, ok := strings.CutSuffix(token, "+"); ok {
		if info, ok := licenses[strings.ToLower(base)]; ok {
			return info.ID + "+", true
		}
	}
	return "", false
}

// Normalized is the result of normalising free-form licence text.
type Normalized struct {
	// Expression is a valid SPDX license expression, or NOASSERTION.
	Expression string `json:"expression"`
	// Refs maps each LicenseRef in Expression that SCRS invented to the
	// original text it stands for (SPDX hasExtractedLicensingInfos).
	Refs map[string]string `json:"refs,omitempty"`
	// Exact is true when the input was already a valid SPDX expression.
	Exact bool `json:"exact"`
}

// Normalize turns declared licence text (an SPDX expression, a common name
// such as "Apache License, Version 2.0", a Debian short name or a Python
// classifier) into an SPDX expression (LIC-002). Unrecognised text becomes a
// LicenseRef-scrs-<hash> with category unknown.
func Normalize(raw string) Normalized {
	load()
	text := strings.TrimSpace(raw)
	if len(text) > 2000 {
		text = text[:2000]
	}
	switch strings.ToUpper(text) {
	case "", "NOASSERTION", "NONE", "UNKNOWN", "N/A", "NULL", "-":
		return Normalized{Expression: NoAssertion}
	}
	if n, err := Parse(text); err == nil {
		return Normalized{Expression: n.String(), Exact: true}
	}
	refs := map[string]string{}
	n := normalizeLoose(text, refs, 0)
	out := Normalized{Expression: n.String()}
	if len(refs) > 0 {
		out.Refs = refs
	}
	return out
}

var (
	looseOr  = regexp.MustCompile(`(?i)\s+or\s+|\s*/\s*|\s*\|\|?\s*`)
	looseAnd = regexp.MustCompile(`(?i)\s+and\s+|\s*[,;&]\s*|\s+\+\s+`)
	looseWth = regexp.MustCompile(`(?i)^(.+?)\s+with\s+(.+?)(?:\s+exception)?$`)
	parens   = regexp.MustCompile(`^(.*?)\s*\(([^()]+)\)$`)
)

// normalizeLoose handles free text: whole-string aliases first, then
// " or "/"/" alternatives, then " and "/","/";" conjunctions.
func normalizeLoose(text string, refs map[string]string, depth int) *Node {
	text = strings.Trim(strings.TrimSpace(text), `"'`)
	if n, err := Parse(text); err == nil {
		return n
	}
	if id, ok := alias(text); ok {
		return mustParse(id)
	}
	// "MIT License (MIT)" or "GNU General Public License v2 (GPLv2)".
	if m := parens.FindStringSubmatch(text); m != nil {
		if id, ok := alias(m[2]); ok {
			return mustParse(id)
		}
		if id, ok := alias(m[1]); ok {
			return mustParse(id)
		}
	}
	if depth < 3 {
		if parts := splitLoose(looseOr, text); len(parts) > 1 {
			return join("OR", parts, refs, depth)
		}
		if parts := splitLoose(looseAnd, text); len(parts) > 1 {
			return join("AND", parts, refs, depth)
		}
		if m := looseWth.FindStringSubmatch(text); m != nil {
			base := normalizeLoose(m[1], refs, depth+1)
			if base.Op == "" && !strings.HasPrefix(base.ID, "LicenseRef-scrs-") {
				if e, ok := exceptionAlias(m[2], base.ID); ok {
					base.Exception = e
				}
				// An unknown exception is dropped: the base licence alone is
				// the stricter reading.
				return base
			}
		}
	}
	ref := "LicenseRef-scrs-" + shortHash(strings.ToLower(text))
	refs[ref] = text
	return &Node{ID: ref}
}

func splitLoose(pattern *regexp.Regexp, text string) []string {
	parts := []string{}
	for _, p := range pattern.Split(text, -1) {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func join(op string, parts []string, refs map[string]string, depth int) *Node {
	var n *Node
	seen := map[string]bool{}
	for _, p := range parts {
		leaf := normalizeLoose(p, refs, depth+1)
		key := leaf.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if n == nil {
			n = leaf
		} else {
			n = &Node{Op: op, Left: n, Right: leaf}
		}
	}
	return n
}

func mustParse(expression string) *Node {
	n, err := Parse(expression)
	if err != nil {
		panic("license alias is not a valid expression: " + expression)
	}
	return n
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// IDs returns the distinct licence ids in an expression, sorted.
func IDs(expression string) []string {
	n, err := Parse(expression)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, l := range n.Leaves() {
		seen[l.ID] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// And combines expressions with AND, dropping duplicates and NOASSERTION.
func And(expressions ...string) string {
	var n *Node
	seen := map[string]bool{}
	for _, e := range expressions {
		if e == "" || e == NoAssertion || seen[e] {
			continue
		}
		seen[e] = true
		next, err := Parse(e)
		if err != nil {
			continue
		}
		if n == nil {
			n = next
		} else {
			n = &Node{Op: "AND", Left: n, Right: next}
		}
	}
	if n == nil {
		return NoAssertion
	}
	return n.String()
}
