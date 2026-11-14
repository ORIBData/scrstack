package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// STIX 2.1 import (TIF). Indicator objects whose patterns can be checked
// against files at rest become SCRS indicators; pattern_type yara becomes
// YARA rules. Every other object or pattern is counted by reason.

const (
	MaxSTIXBytes        = 32 << 20
	MaxSTIXObjects      = 200000
	MaxSTIXYaraPatterns = 200
	maxPatternBytes     = 64 << 10
	maxPatternDepth     = 32
	maxDisjuncts        = 64
	maxSkipSamples      = 50
)

// Reasons an indicator object is skipped, as reported to the importer.
const (
	SkipRevoked         = "revoked"
	SkipExpired         = "expired"
	SkipVersion         = "unsupported_version"
	SkipPatternType     = "unsupported_pattern_type"
	SkipObservations    = "combines_observations"
	SkipTimeWindow      = "time_window"
	SkipObject          = "unsupported_object"
	SkipHash            = "unsupported_hash"
	SkipOperator        = "unsupported_operator"
	SkipConditions      = "combines_conditions"
	SkipValue           = "unsupported_value"
	SkipInvalid         = "invalid_pattern"
	SkipYara            = "invalid_yara"
	SkipTooManyYara     = "too_many_yara"
	SkipDuplicateRule   = "duplicate_rule_name"
	SkipRulesetFull     = "ruleset_full"
	SkipSuperseded      = "superseded"
	SkipTooManyImported = "too_many_indicators"
)

// STIXSkip is one skipped object, as a sample in the report.
type STIXSkip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// STIXReport counts what an upload produced.
type STIXReport struct {
	Objects    int            `json:"objects"`
	Indicators int            `json:"indicators"`
	Imported   int            `json:"imported"`
	Yara       int            `json:"yara_patterns"`
	Partial    int            `json:"partial"`
	Skipped    map[string]int `json:"skipped"`
	Samples    []STIXSkip     `json:"samples"`
}

// Skip counts one skipped object and keeps the first samples.
func (r *STIXReport) Skip(id, reason, detail string) {
	r.Skipped[reason]++
	if len(r.Samples) < maxSkipSamples {
		r.Samples = append(r.Samples, STIXSkip{ID: id, Reason: reason, Detail: clip(detail, 200)})
	}
}

// YaraPattern is the rule text of one pattern_type yara indicator.
type YaraPattern struct {
	ID         string
	Rules      string
	Confidence *int
	ValidUntil time.Time
}

// STIXImport is a parsed upload. Touched lists every indicator object ID in
// the bundle, so a merge can drop what those objects no longer produce.
type STIXImport struct {
	BundleID   string
	Indicators []Indicator
	Yara       []YaraPattern
	Touched    []string
	Report     STIXReport
}

type stixObject struct {
	Type        string     `json:"type"`
	SpecVersion string     `json:"spec_version"`
	ID          string     `json:"id"`
	Modified    time.Time  `json:"modified"`
	Pattern     string     `json:"pattern"`
	PatternType string     `json:"pattern_type"`
	ValidUntil  *time.Time `json:"valid_until"`
	Confidence  *int       `json:"confidence"`
	Revoked     bool       `json:"revoked"`
}

var (
	stixBundleID    = regexp.MustCompile(`^bundle--[0-9a-fA-F-]{36}$`)
	stixIndicatorID = regexp.MustCompile(`^indicator--[0-9a-fA-F-]{36}$`)
)

// ParseSTIX reads a STIX 2.1 bundle. Indicators without valid_until expire
// validFor after now. When a bundle holds several versions of one indicator,
// the latest modified wins.
func ParseSTIX(raw []byte, now time.Time, validFor time.Duration) (STIXImport, error) {
	imp := STIXImport{Report: STIXReport{Skipped: map[string]int{}, Samples: []STIXSkip{}}}
	var bundle struct {
		Type    string            `json:"type"`
		ID      string            `json:"id"`
		Objects []json.RawMessage `json:"objects"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if len(raw) > MaxSTIXBytes || d.Decode(&bundle) != nil || d.Decode(new(any)) != io.EOF {
		return imp, errors.New("invalid STIX bundle")
	}
	if bundle.Type != "bundle" || !stixBundleID.MatchString(bundle.ID) || len(bundle.Objects) > MaxSTIXObjects {
		return imp, errors.New("not a STIX 2.1 bundle: type bundle and a bundle-- id are required")
	}
	return ParseSTIXObjects(bundle.Objects, strings.ToLower(bundle.ID), now, validFor), nil
}

// ParseSTIXObjects reads STIX objects outside a bundle, such as a TAXII
// page; version names the import in the source's version.
func ParseSTIXObjects(objects []json.RawMessage, version string, now time.Time, validFor time.Duration) STIXImport {
	imp := STIXImport{BundleID: version, Report: STIXReport{Objects: len(objects), Skipped: map[string]int{}, Samples: []STIXSkip{}}}
	latest := map[string]stixObject{}
	for _, item := range objects {
		var o stixObject
		if json.Unmarshal(item, &o) != nil || o.Type != "indicator" {
			continue
		}
		imp.Report.Indicators++
		o.ID = strings.ToLower(o.ID)
		if !stixIndicatorID.MatchString(o.ID) {
			imp.Report.Skip(clip(o.ID, 64), SkipInvalid, "indicator id is not indicator--<uuid>")
			continue
		}
		if seen, ok := latest[o.ID]; ok {
			imp.Report.Skip(o.ID, SkipSuperseded, "a later version of this indicator is in the bundle")
			if !o.Modified.After(seen.Modified) {
				continue
			}
		}
		latest[o.ID] = o
	}
	ids := make([]string, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	imp.Touched = ids
	for _, id := range ids {
		o := latest[id]
		until := now.Add(validFor)
		if o.ValidUntil != nil {
			until = *o.ValidUntil
		}
		switch {
		case o.SpecVersion != "2.1":
			imp.Report.Skip(id, SkipVersion, "spec_version "+clip(o.SpecVersion, 16))
			continue
		case o.Revoked:
			imp.Report.Skip(id, SkipRevoked, "")
			continue
		case !now.Before(until):
			imp.Report.Skip(id, SkipExpired, "valid_until "+until.UTC().Format(time.RFC3339))
			continue
		case o.Confidence != nil && (*o.Confidence < 0 || *o.Confidence > 100):
			imp.Report.Skip(id, SkipInvalid, "confidence is outside 0 to 100")
			continue
		}
		switch o.PatternType {
		case "yara":
			if len(imp.Yara) >= MaxSTIXYaraPatterns {
				imp.Report.Skip(id, SkipTooManyYara, fmt.Sprintf("at most %d YARA patterns per upload", MaxSTIXYaraPatterns))
				continue
			}
			if err := CheckRuleText(o.Pattern); err != nil {
				imp.Report.Skip(id, SkipYara, err.Error())
				continue
			}
			imp.Yara = append(imp.Yara, YaraPattern{ID: id, Rules: o.Pattern, Confidence: o.Confidence, ValidUntil: until})
			imp.Report.Yara++
			continue
		case "stix":
		default:
			imp.Report.Skip(id, SkipPatternType, "pattern_type "+clip(o.PatternType, 32))
			continue
		}
		matches, partial, reason, detail := checkablePattern(o.Pattern)
		if len(matches) == 0 {
			imp.Report.Skip(id, reason, detail)
			continue
		}
		if len(imp.Indicators)+len(matches) > MaxImportIndicators {
			imp.Report.Skip(id, SkipTooManyImported, fmt.Sprintf("at most %d indicators per upload", MaxImportIndicators))
			continue
		}
		if partial {
			imp.Report.Partial++
		}
		for n, m := range matches {
			i := Indicator{ID: id, Type: m.kind, Value: m.value, Confidence: o.Confidence, ValidUntil: until}
			if len(matches) > 1 {
				i.ID = id + "#" + strconv.Itoa(n+1)
			}
			imp.Indicators = append(imp.Indicators, i)
		}
	}
	imp.Report.Imported = len(imp.Indicators)
	return imp
}

// CheckYara compiles each YARA pattern alone and drops, as invalid_yara, any
// that does not compile. Errors other than a *RuleError stop the check.
func (imp *STIXImport) CheckYara(ctx context.Context, compile func(ctx context.Context, rules string) error) error {
	kept := imp.Yara[:0]
	for _, y := range imp.Yara {
		err := compile(ctx, y.Rules)
		var rule *RuleError
		switch {
		case err == nil:
			kept = append(kept, y)
		case errors.As(err, &rule):
			imp.Report.Yara--
			imp.Report.Skip(y.ID, SkipYara, rule.Error())
		default:
			return err
		}
	}
	imp.Yara = kept
	return nil
}

// match is one indicator a pattern produces.
type match struct{ kind, value string }

// checkablePattern returns the indicators a STIX pattern produces. Top-level
// alternatives ([a] OR [b]) are independent; when only some can be checked,
// partial is true. Otherwise reason names why nothing could be checked.
func checkablePattern(pattern string) (out []match, partial bool, reason, detail string) {
	if len(pattern) > maxPatternBytes {
		return nil, false, SkipInvalid, "pattern is over 64 KiB"
	}
	tokens, err := lexPattern(pattern)
	if err != nil {
		return nil, false, SkipInvalid, err.Error()
	}
	p := &patternParser{tokens: tokens}
	tree, err := p.observations(0)
	if err == nil && p.peek().kind != tokEOF {
		err = fmt.Errorf("unexpected %q", p.peek().text)
	}
	if err != nil {
		return nil, false, SkipInvalid, err.Error()
	}
	seen := map[match]bool{}
	failed := false
	for _, b := range tree.branches() {
		var found []match
		if b.reason == "" {
			found, b.reason, b.detail = b.expr.matches()
		}
		if b.reason != "" {
			failed = true
			if reason == "" {
				reason, detail = b.reason, b.detail
			}
			continue
		}
		for _, m := range found {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out, failed && len(out) > 0, reason, detail
}

// ---- lexer

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokLBracket
	tokRBracket
	tokLParen
	tokRParen
	tokComma
	tokString
	tokLiteral // numbers, booleans, t'', h'' and b'' values
	tokPath
	tokOp
	tokWord
)

type token struct {
	kind tokenKind
	text string
}

var stixKeywords = map[string]bool{"AND": true, "OR": true, "NOT": true, "FOLLOWEDBY": true, "WITHIN": true, "REPEATS": true, "TIMES": true, "START": true, "STOP": true, "SECONDS": true, "LIKE": true, "MATCHES": true, "IN": true, "ISSUBSET": true, "ISSUPERSET": true, "EXISTS": true}

func identByte(c byte) bool {
	return c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// quoted reads a '...' literal starting at s[i]; \' and \\ are escapes.
func quoted(s string, i int) (string, int, error) {
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			if j+1 >= len(s) || (s[j+1] != '\'' && s[j+1] != '\\') {
				return "", 0, errors.New("invalid escape in string")
			}
			j++
			b.WriteByte(s[j])
		case '\'':
			return b.String(), j + 1, nil
		default:
			b.WriteByte(s[j])
		}
	}
	return "", 0, errors.New("unterminated string")
}

func lexPattern(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '[':
			out, i = append(out, token{tokLBracket, "["}), i+1
		case c == ']':
			out, i = append(out, token{tokRBracket, "]"}), i+1
		case c == '(':
			out, i = append(out, token{tokLParen, "("}), i+1
		case c == ')':
			out, i = append(out, token{tokRParen, ")"}), i+1
		case c == ',':
			out, i = append(out, token{tokComma, ","}), i+1
		case c == '\'':
			text, next, err := quoted(s, i)
			if err != nil {
				return nil, err
			}
			out, i = append(out, token{tokString, text}), next
		case c == '=' || c == '!' || c == '<' || c == '>':
			op := string(c)
			if i+1 < len(s) && s[i+1] == '=' {
				op += "="
			}
			if op == "!" {
				return nil, errors.New("unexpected !")
			}
			out, i = append(out, token{tokOp, op}), i+len(op)
		case identByte(c) || c == '+' || c == '.':
			j := i
			for j < len(s) && (identByte(s[j]) || s[j] == '+' || s[j] == '.') {
				j++
			}
			word := s[i:j]
			if j < len(s) && s[j] == '\'' && (word == "t" || word == "h" || word == "b") {
				text, next, err := quoted(s, j)
				if err != nil {
					return nil, err
				}
				out, i = append(out, token{tokLiteral, word + "'" + text + "'"}), next
				continue
			}
			if j < len(s) && s[j] == ':' {
				path, next, err := lexPath(s, i, j)
				if err != nil {
					return nil, err
				}
				out, i = append(out, token{tokPath, path}), next
				continue
			}
			if stixKeywords[strings.ToUpper(word)] {
				out = append(out, token{tokWord, strings.ToUpper(word)})
			} else {
				out = append(out, token{tokLiteral, word})
			}
			i = j
		default:
			return nil, fmt.Errorf("unexpected %q", string(c))
		}
	}
	return append(out, token{tokEOF, ""}), nil
}

// lexPath reads an object path such as file:hashes.'SHA-256' or
// file:extensions.'x'.sections[*].name. Quoted steps are unquoted.
func lexPath(s string, start, colon int) (string, int, error) {
	var b strings.Builder
	b.WriteString(strings.ToLower(s[start:colon]))
	b.WriteByte(':')
	i := colon + 1
	for first := true; ; first = false {
		if !first {
			if i >= len(s) || s[i] != '.' {
				break
			}
			b.WriteByte('.')
			i++
		}
		if i < len(s) && s[i] == '\'' {
			text, next, err := quoted(s, i)
			if err != nil {
				return "", 0, err
			}
			b.WriteString(text)
			i = next
		} else {
			j := i
			for j < len(s) && identByte(s[j]) {
				j++
			}
			if j == i {
				return "", 0, errors.New("invalid object path")
			}
			b.WriteString(s[i:j])
			i = j
		}
		// A list index follows a step directly: sections[*] or sections[0].
		if i < len(s) && s[i] == '[' {
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return "", 0, errors.New("invalid list index")
			}
			index := s[i+1 : i+j]
			if _, err := strconv.Atoi(index); index != "*" && err != nil {
				return "", 0, errors.New("invalid list index")
			}
			b.WriteString(s[i : i+j+1])
			i += j + 1
		}
	}
	return b.String(), i, nil
}

// ---- parser

// comparison is one object path test; values holds IN alternatives.
type comparison struct {
	path    string
	op      string
	negated bool
	values  []token
}

type expr struct {
	op   string // and, or, cmp
	kids []*expr
	cmp  *comparison
}

type observation struct {
	op        string // obs, or, and, followedby
	kids      []*observation
	expr      *expr
	qualified bool
}

type patternParser struct {
	tokens []token
	pos    int
}

func (p *patternParser) peek() token { return p.tokens[p.pos] }
func (p *patternParser) next() token { t := p.tokens[p.pos]; p.pos++; return t }
func (p *patternParser) word(w string) bool {
	if t := p.peek(); t.kind == tokWord && t.text == w {
		p.pos++
		return true
	}
	return false
}

// observations parses FOLLOWEDBY, then OR, then AND, from loosest binding.
func (p *patternParser) observations(depth int) (*observation, error) {
	return p.observationLevel(depth, 0)
}

var observationOps = []string{"FOLLOWEDBY", "OR", "AND"}

func (p *patternParser) observationLevel(depth, level int) (*observation, error) {
	if level == len(observationOps) {
		return p.qualifiedObservation(depth)
	}
	left, err := p.observationLevel(depth, level+1)
	if err != nil {
		return nil, err
	}
	for p.word(observationOps[level]) {
		right, err := p.observationLevel(depth, level+1)
		if err != nil {
			return nil, err
		}
		left = &observation{op: strings.ToLower(observationOps[level]), kids: []*observation{left, right}}
	}
	return left, nil
}

func (p *patternParser) qualifiedObservation(depth int) (*observation, error) {
	if depth > maxPatternDepth {
		return nil, errors.New("pattern nests too deeply")
	}
	var o *observation
	switch t := p.next(); t.kind {
	case tokLBracket:
		e, err := p.comparisons(depth+1, 0)
		if err != nil {
			return nil, err
		}
		if p.next().kind != tokRBracket {
			return nil, errors.New("missing ]")
		}
		o = &observation{op: "obs", expr: e}
	case tokLParen:
		inner, err := p.observations(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.next().kind != tokRParen {
			return nil, errors.New("missing )")
		}
		o = inner
	default:
		return nil, fmt.Errorf("expected [ or ( but found %q", t.text)
	}
	for {
		switch {
		case p.word("WITHIN"):
			if p.next().kind != tokLiteral || !p.word("SECONDS") {
				return nil, errors.New("WITHIN needs a number of SECONDS")
			}
		case p.word("REPEATS"):
			if p.next().kind != tokLiteral || !p.word("TIMES") {
				return nil, errors.New("REPEATS needs a number of TIMES")
			}
		case p.word("START"):
			if p.next().kind != tokLiteral || !p.word("STOP") || p.next().kind != tokLiteral {
				return nil, errors.New("START needs a STOP timestamp")
			}
		default:
			return o, nil
		}
		o = &observation{op: o.op, kids: o.kids, expr: o.expr, qualified: true}
	}
}

var comparisonOps = []string{"OR", "AND"}

func (p *patternParser) comparisons(depth, level int) (*expr, error) {
	if depth > maxPatternDepth {
		return nil, errors.New("pattern nests too deeply")
	}
	if level == len(comparisonOps) {
		return p.comparison(depth)
	}
	left, err := p.comparisons(depth, level+1)
	if err != nil {
		return nil, err
	}
	for p.word(comparisonOps[level]) {
		right, err := p.comparisons(depth, level+1)
		if err != nil {
			return nil, err
		}
		left = &expr{op: strings.ToLower(comparisonOps[level]), kids: []*expr{left, right}}
	}
	return left, nil
}

func (p *patternParser) comparison(depth int) (*expr, error) {
	if p.peek().kind == tokLParen {
		p.next()
		e, err := p.comparisons(depth+1, 0)
		if err != nil {
			return nil, err
		}
		if p.next().kind != tokRParen {
			return nil, errors.New("missing )")
		}
		return e, nil
	}
	if p.word("EXISTS") {
		if p.next().kind != tokPath {
			return nil, errors.New("EXISTS needs an object path")
		}
		return &expr{op: "cmp", cmp: &comparison{op: "EXISTS"}}, nil
	}
	path := p.next()
	if path.kind != tokPath {
		return nil, fmt.Errorf("expected an object path but found %q", path.text)
	}
	c := &comparison{path: path.text, negated: p.word("NOT")}
	switch t := p.next(); {
	case t.kind == tokOp:
		c.op = t.text
	case t.kind == tokWord && (t.text == "LIKE" || t.text == "MATCHES" || t.text == "IN" || t.text == "ISSUBSET" || t.text == "ISSUPERSET"):
		c.op = t.text
	default:
		return nil, fmt.Errorf("expected an operator but found %q", t.text)
	}
	if c.op == "IN" {
		if p.next().kind != tokLParen {
			return nil, errors.New("IN needs a list")
		}
		for {
			v := p.next()
			if v.kind != tokString && v.kind != tokLiteral {
				return nil, errors.New("invalid IN list")
			}
			c.values = append(c.values, v)
			if p.peek().kind == tokRParen {
				p.next()
				break
			}
			if p.next().kind != tokComma {
				return nil, errors.New("invalid IN list")
			}
		}
	} else {
		v := p.next()
		if v.kind != tokString && v.kind != tokLiteral {
			return nil, errors.New("expected a value")
		}
		c.values = []token{v}
	}
	return &expr{op: "cmp", cmp: c}, nil
}

// ---- evaluation

type branch struct {
	expr           *expr
	reason, detail string
}

// branches splits top-level OR alternatives; anything else that joins or
// qualifies observations cannot be checked against one file at rest.
func (o *observation) branches() []branch {
	switch {
	case o.qualified:
		return []branch{{reason: SkipTimeWindow, detail: "WITHIN, REPEATS and START/STOP need event history"}}
	case o.op == "obs":
		return []branch{{expr: o.expr}}
	case o.op == "or":
		return append(o.kids[0].branches(), o.kids[1].branches()...)
	}
	return []branch{{reason: SkipObservations, detail: strings.ToUpper(o.op) + " joins separate observations"}}
}

// dnf expands an expression into alternatives of conjoined comparisons.
func (e *expr) dnf() ([][]*comparison, bool) {
	switch e.op {
	case "cmp":
		return [][]*comparison{{e.cmp}}, true
	case "or":
		left, ok := e.kids[0].dnf()
		right, ok2 := e.kids[1].dnf()
		out := append(left, right...)
		return out, ok && ok2 && len(out) <= maxDisjuncts
	}
	left, ok := e.kids[0].dnf()
	right, ok2 := e.kids[1].dnf()
	if !ok || !ok2 || len(left)*len(right) > maxDisjuncts {
		return nil, false
	}
	var out [][]*comparison
	for _, l := range left {
		for _, r := range right {
			out = append(out, append(append([]*comparison{}, l...), r...))
		}
	}
	return out, true
}

// matches maps one observation to indicators. Every alternative must be
// checkable. In a conjunction with a file hash, the hash identifies the file
// and the other conditions are dropped; otherwise a conjunction cannot be
// checked with single-value indicators.
func (e *expr) matches() ([]match, string, string) {
	alternatives, ok := e.dnf()
	if !ok {
		return nil, SkipInvalid, "pattern has too many alternatives"
	}
	var out []match
	for _, conj := range alternatives {
		var hashes []match
		for _, c := range conj {
			if strings.HasPrefix(c.path, "file:hashes.") && !c.negated && c.op == "=" {
				if found, reason, _ := c.matches(); reason == "" {
					hashes = append(hashes, found...)
				}
			}
		}
		switch {
		case len(hashes) > 0:
			out = append(out, hashes...)
		case len(conj) == 1:
			found, reason, detail := conj[0].matches()
			if reason != "" {
				return nil, reason, detail
			}
			out = append(out, found...)
		default:
			for _, c := range conj {
				if object, _, _ := strings.Cut(c.path, ":"); c.op != "EXISTS" && !checkableObjects[object] {
					_, reason, detail := c.matches()
					return nil, reason, detail
				}
			}
			return nil, SkipConditions, "AND of conditions other than a file hash"
		}
	}
	return out, "", ""
}

var stixHashes = map[string]string{"md5": "md5", "sha-1": "sha1", "sha1": "sha1", "sha-256": "sha256", "sha256": "sha256"}

// checkableObjects are STIX object types matched against files at rest.
var checkableObjects = map[string]bool{"file": true, "domain-name": true, "ipv4-addr": true, "ipv6-addr": true, "url": true}

func (c *comparison) matches() ([]match, string, string) {
	object, property, _ := strings.Cut(c.path, ":")
	if c.op == "EXISTS" {
		return nil, SkipOperator, "EXISTS"
	}
	if !checkableObjects[object] {
		detail := object + " objects are not present in files at rest"
		if object == "network-traffic" {
			detail = "network traffic is not observable in files at rest"
		}
		return nil, SkipObject, detail
	}
	var kind string
	switch {
	case object == "file" && strings.HasPrefix(property, "hashes."):
		kind = stixHashes[strings.ToLower(strings.TrimPrefix(property, "hashes."))]
		if kind == "" {
			return nil, SkipHash, strings.TrimPrefix(property, "hashes.") + " is not supported; use MD5, SHA-1 or SHA-256"
		}
	case object == "file" && property == "name":
		kind = "file_path_regex"
	case object != "file" && property == "value":
		kind = map[string]string{"domain-name": "domain", "ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "url": "url"}[object]
	default:
		return nil, SkipObject, c.path + " is not matched"
	}
	if c.negated || (c.op != "=" && c.op != "IN") {
		op := c.op
		if c.negated {
			op = "NOT " + op
		}
		return nil, SkipOperator, op + " on " + c.path
	}
	var out []match
	for _, v := range c.values {
		if v.kind != tokString {
			return nil, SkipValue, c.path + " needs a string"
		}
		value := v.text
		switch kind {
		case "file_path_regex":
			if value == "" || strings.ContainsAny(value, "/\x00") {
				return nil, SkipValue, "file name " + clip(value, 64)
			}
			// File names match the last path element exactly.
			value = `(?:^|/)` + regexp.QuoteMeta(value) + `$`
		case "ipv4", "ipv6":
			if base, bits, ok := strings.Cut(value, "/"); ok {
				if (kind == "ipv4" && bits != "32") || (kind == "ipv6" && bits != "128") {
					return nil, SkipValue, "address ranges are not matched: " + clip(value, 64)
				}
				value = base
			}
		}
		normalized, err := normalize(kind, value)
		if err != nil {
			return nil, SkipValue, err.Error() + ": " + clip(v.text, 64)
		}
		out = append(out, match{kind, normalized})
	}
	return out, "", ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
