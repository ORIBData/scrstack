package compliance

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// STIG import (CMP-004). The owner uploads a DISA STIG benchmark in XCCDF
// (the "-xccdf.xml" file, or the zip DISA publishes); SCRS ships no DISA
// content. The import turns every rule into a category and applies SCRS's
// starter mapping of CWEs and finding types to the rules its own scans can
// give evidence for. Rules without a mapping are reported as not evidenced
// by SCRS, never as passed.

const (
	maxSTIGRules    = 2000
	maxXCCDFSize    = 32 << 20
	maxSTIGZipFiles = 200
)

var stigSeverity = map[string]bool{"CAT I": true, "CAT II": true, "CAT III": true}

// ErrSTIG wraps an XCCDF import failure.
var ErrSTIG = errors.New("invalid STIG benchmark")

// stigMapping is SCRS's starter mapping for the Application Security and
// Development (ASD) STIG, keyed by STIG id.
type stigMapping struct {
	Benchmark string                 `json:"benchmark"`
	Note      string                 `json:"note"`
	Rules     map[string]stigRuleMap `json:"rules"`
	// Types maps finding types without a CWE to a STIG id.
	Types map[string]string `json:"types"`
}

type stigRuleMap struct {
	CWEs []int `json:"cwes"`
}

//go:embed stig/asd-mapping.json
var asdMappingRaw []byte

var asdMapping = func() stigMapping {
	var m stigMapping
	if err := json.Unmarshal(asdMappingRaw, &m); err != nil {
		panic(err)
	}
	return m
}()

// STIGImport reports how the starter mapping applied to a benchmark.
type STIGImport struct {
	Pack Pack `json:"pack"`
	// Mapped counts rules that SCRS findings can give evidence for.
	Mapped int `json:"rules_mapped"`
	// Unmatched lists starter-mapping STIG ids missing from the benchmark
	// (renamed or withdrawn rules); review them before relying on the pack.
	Unmatched []string `json:"mapping_unmatched"`
}

// xccdf is the part of an XCCDF 1.1 or 1.2 benchmark the import reads.
// Element names are matched without namespaces.
type xccdf struct {
	XMLName   xml.Name `xml:"Benchmark"`
	ID        string   `xml:"id,attr"`
	Title     string   `xml:"title"`
	Version   string   `xml:"version"`
	PlainText []struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"plain-text"`
	Groups []struct {
		ID   string `xml:"id,attr"`
		Rule []struct {
			ID       string `xml:"id,attr"`
			Severity string `xml:"severity,attr"`
			Version  string `xml:"version"`
			Title    string `xml:"title"`
			Idents   []struct {
				System string `xml:"system,attr"`
				Value  string `xml:",chardata"`
			} `xml:"ident"`
		} `xml:"Rule"`
	} `xml:"Group"`
}

var (
	stigID      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	benchmarkID = regexp.MustCompile(`[^a-z0-9]+`)
)

// xccdfDocument returns the XCCDF XML from an upload: the XML itself, or
// the first "*xccdf.xml" file in a zip (DISA's distribution format).
func xccdfDocument(raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, []byte("PK\x03\x04")) {
		return raw, nil
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable zip", ErrSTIG)
	}
	if len(archive.File) > maxSTIGZipFiles {
		return nil, fmt.Errorf("%w: zip has too many files", ErrSTIG)
	}
	for _, f := range archive.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), "xccdf.xml") {
			continue
		}
		if f.UncompressedSize64 > maxXCCDFSize {
			return nil, fmt.Errorf("%w: XCCDF file too large", ErrSTIG)
		}
		r, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: unreadable zip entry", ErrSTIG)
		}
		defer r.Close()
		// The declared size is not trusted: read at most the limit.
		data, err := io.ReadAll(io.LimitReader(r, maxXCCDFSize+1))
		if err != nil || len(data) > maxXCCDFSize {
			return nil, fmt.Errorf("%w: XCCDF file too large or corrupt", ErrSTIG)
		}
		return data, nil
	}
	return nil, fmt.Errorf("%w: the zip holds no *xccdf.xml file", ErrSTIG)
}

// ImportSTIG builds a stig pack from an uploaded benchmark. Go's XML
// decoder does not resolve external entities or DTDs, so the upload cannot
// read files or reach the network.
func ImportSTIG(raw []byte) (STIGImport, error) {
	doc, err := xccdfDocument(raw)
	if err != nil {
		return STIGImport{}, err
	}
	var b xccdf
	decoder := xml.NewDecoder(bytes.NewReader(doc))
	decoder.Strict = true
	if err := decoder.Decode(&b); err != nil {
		return STIGImport{}, fmt.Errorf("%w: not an XCCDF benchmark", ErrSTIG)
	}
	title := clean(b.Title, 300)
	if b.ID == "" || title == "" {
		return STIGImport{}, fmt.Errorf("%w: the benchmark has no id or title", ErrSTIG)
	}
	release := ""
	for _, t := range b.PlainText {
		if t.ID == "release-info" {
			release = clean(t.Text, 200)
		}
	}
	id := "stig-" + strings.Trim(benchmarkID.ReplaceAllString(strings.ToLower(clean(b.ID, 200)), "-"), "-")
	if v := strings.Trim(benchmarkID.ReplaceAllString(strings.ToLower(clean(b.Version, 20)), "-"), "-"); v != "" {
		id += "-v" + v
	}
	if len(id) > 64 {
		id = strings.TrimRight(id[:64], "-")
	}
	p := Pack{ID: id, Name: title, Version: clean(b.Version, 64), Kind: KindSTIG, Source: "DISA XCCDF benchmark uploaded by an administrator; CWE and finding-type mapping by SCRS (" + asdMapping.Note + ")", Benchmark: &Benchmark{ID: clean(b.ID, 200), Title: title, Version: clean(b.Version, 64), Release: release}, TypeCategories: map[string]string{}}
	if p.Version == "" {
		p.Version = "unversioned"
	}
	seen := map[string]bool{}
	for _, g := range b.Groups {
		for _, rule := range g.Rule {
			sid := clean(rule.Version, 64)
			if !stigID.MatchString(sid) {
				// Some benchmarks carry no STIG id; the rule id is stable
				// within a release.
				sid = clean(rule.ID, 64)
			}
			if !stigID.MatchString(sid) || seen[sid] {
				continue
			}
			seen[sid] = true
			c := Category{ID: sid, Name: clean(rule.Title, 500), CWEs: []int{}, Severity: catOf(rule.Severity), VulnID: clean(g.ID, 64), RuleID: clean(rule.ID, 128), CCIs: []string{}}
			if c.Name == "" {
				c.Name = sid
			}
			for _, ident := range rule.Idents {
				if v := clean(ident.Value, 32); strings.HasPrefix(v, "CCI-") && len(c.CCIs) < 50 {
					c.CCIs = append(c.CCIs, v)
				}
			}
			p.Categories = append(p.Categories, c)
			if len(p.Categories) > maxSTIGRules {
				return STIGImport{}, fmt.Errorf("%w: more than %d rules", ErrSTIG, maxSTIGRules)
			}
		}
	}
	if len(p.Categories) == 0 {
		return STIGImport{}, fmt.Errorf("%w: the benchmark has no rules", ErrSTIG)
	}
	out := STIGImport{Unmatched: []string{}}
	for i := range p.Categories {
		if m, ok := asdMapping.Rules[p.Categories[i].ID]; ok {
			p.Categories[i].CWEs = append([]int{}, m.CWEs...)
		}
	}
	for kind, sid := range asdMapping.Types {
		if seen[sid] {
			p.TypeCategories[kind] = sid
		}
	}
	for i := range p.Categories {
		c := p.Categories[i]
		if len(c.CWEs) > 0 || hasValue(p.TypeCategories, c.ID) {
			out.Mapped++
		}
	}
	for sid := range asdMapping.Rules {
		if !seen[sid] {
			out.Unmatched = append(out.Unmatched, sid)
		}
	}
	sort.Strings(out.Unmatched)
	p.TypeCategoriesNote = "Finding types without a CWE are mapped to one STIG rule each; rules without a mapping are not evidenced by SCRS scans and need manual review."
	if _, err := ParsePack(mustJSON(p)); err != nil {
		return STIGImport{}, fmt.Errorf("%w: %v", ErrSTIG, err)
	}
	out.Pack = p
	return out, nil
}

func catOf(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high":
		return "CAT I"
	case "low":
		return "CAT III"
	}
	return "CAT II"
}

func hasValue(m map[string]string, v string) bool {
	for _, x := range m {
		if x == v {
			return true
		}
	}
	return false
}

// clean trims and collapses white space and bounds the length.
func clean(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		s = s[:limit]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
