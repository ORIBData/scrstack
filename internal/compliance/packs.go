// Package compliance builds framework evidence reports (CMP-001 to
// CMP-006): OWASP Top 10 (2021 and 2025), the CWE Top 25 and PCI DSS v4.0.1
// requirement 6.3 views. Reports are evidence for discussion with an
// assessor; they contain no compliance verdict.
package compliance

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

//go:embed packs/*.json pack.schema.json
var files embed.FS

// Pack kinds.
const (
	KindCWEMapping = "cwe_mapping"
	KindPCIDSS     = "pci_dss"
)

// Pack is a versioned framework data pack (CMP-001).
type Pack struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Kind       string     `json:"kind"`
	Source     string     `json:"source"`
	URL        string     `json:"url,omitempty"`
	Builtin    bool       `json:"builtin"`
	Categories []Category `json:"categories,omitempty"`
	// TypeCategories maps finding types that carry no CWE of their own
	// (a vulnerable dependency, an integrity change) to a category.
	TypeCategories     map[string]string `json:"type_categories,omitempty"`
	TypeCategoriesNote string            `json:"type_categories_note,omitempty"`
	Requirements       []Requirement     `json:"requirements,omitempty"`
}

// Category maps CWE ids to one framework category.
type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	CWEs []int  `json:"cwes"`
}

// Requirement is one PCI DSS evidence view.
type Requirement struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

var builtin []Pack

func init() {
	entries, err := files.ReadDir("packs")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		raw, err := files.ReadFile("packs/" + e.Name())
		if err != nil {
			panic(err)
		}
		var p Pack
		if err := json.Unmarshal(raw, &p); err != nil {
			panic(err)
		}
		p.Builtin = true
		builtin = append(builtin, p)
	}
	sort.Slice(builtin, func(i, j int) bool { return builtin[i].ID < builtin[j].ID })
}

// Builtin lists the packs that ship in the release.
func Builtin() []Pack { return append([]Pack(nil), builtin...) }

// BuiltinPack returns one shipped pack.
func BuiltinPack(id string) (Pack, bool) {
	for _, p := range builtin {
		if p.ID == id {
			return p, true
		}
	}
	return Pack{}, false
}

// Schema returns the custom pack JSON Schema (CMP-005).
func Schema() json.RawMessage {
	raw, _ := files.ReadFile("pack.schema.json")
	return raw
}

// ErrPack wraps a custom pack validation failure.
var ErrPack = errors.New("invalid framework pack")

var packID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,63}$`)

// ParsePack validates an uploaded CWE-mapping pack (CMP-005). Custom
// packs cannot replace shipped ones.
func ParsePack(raw []byte) (Pack, error) {
	var p Pack
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrPack, err)
	}
	fail := func(format string, args ...any) (Pack, error) {
		return p, fmt.Errorf("%w: %s", ErrPack, fmt.Sprintf(format, args...))
	}
	if !packID.MatchString(p.ID) {
		return fail("id must match %s", packID)
	}
	if _, ok := BuiltinPack(p.ID); ok {
		return fail("id %s is a shipped pack", p.ID)
	}
	if p.Kind != KindCWEMapping {
		return fail("custom packs must be kind cwe_mapping")
	}
	if p.Name == "" || len(p.Name) > 200 || p.Version == "" || len(p.Version) > 64 || len(p.Source) > 500 || len(p.URL) > 500 || len(p.TypeCategoriesNote) > 1000 {
		return fail("name and version are required; text fields are bounded")
	}
	if p.Builtin || len(p.Requirements) > 0 {
		return fail("builtin and requirements are not allowed")
	}
	if len(p.Categories) == 0 || len(p.Categories) > 200 {
		return fail("1 to 200 categories required")
	}
	ids := map[string]bool{}
	for i, c := range p.Categories {
		if c.ID == "" || len(c.ID) > 64 || c.Name == "" || len(c.Name) > 200 || ids[c.ID] {
			return fail("categories[%d] needs a unique id and a name", i)
		}
		ids[c.ID] = true
		if len(c.CWEs) > 2000 {
			return fail("categories[%d] lists too many CWEs", i)
		}
		for _, cwe := range c.CWEs {
			if cwe < 1 || cwe > 99999 {
				return fail("categories[%d] has an invalid CWE id %d", i, cwe)
			}
		}
	}
	for kind, category := range p.TypeCategories {
		if len(kind) > 64 || !ids[category] {
			return fail("type_categories.%s must name a category id", kind)
		}
	}
	return p, nil
}
