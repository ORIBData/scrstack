package license

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
)

// Categories (LIC-003), from least to most restrictive for corporate use.
const (
	Permissive                = "permissive"
	PublicDomain              = "public_domain"
	WeakCopyleft              = "weak_copyleft"
	StrongCopyleft            = "strong_copyleft"
	NetworkCopyleft           = "network_copyleft"
	SourceAvailableRestricted = "source_available_restricted"
	NonCommercial             = "non_commercial"
	Proprietary               = "proprietary"
	Unknown                   = "unknown"
)

// CategoryNames lists every category.
var CategoryNames = []string{Permissive, PublicDomain, WeakCopyleft, StrongCopyleft, NetworkCopyleft, SourceAvailableRestricted, NonCommercial, Proprietary, Unknown}

// ValidCategory reports whether c is a category name.
func ValidCategory(c string) bool {
	for _, name := range CategoryNames {
		if c == name {
			return true
		}
	}
	return false
}

// Catalog maps licence ids to categories: the embedded SCRS mapping plus
// operator overrides (LIC-003). The zero value is not usable; use
// NewCatalog.
type Catalog struct {
	// Version names the embedded mapping; Revision counts override changes.
	Version   string            `json:"version"`
	Source    string            `json:"source"`
	Revision  int64             `json:"revision"`
	Overrides map[string]string `json:"overrides"`
	base      map[string]string
}

var (
	embeddedOnce sync.Once
	embedded     struct {
		Version    string            `json:"version"`
		Source     string            `json:"source"`
		Categories map[string]string `json:"categories"`
	}
)

func loadEmbedded() {
	embeddedOnce.Do(func() {
		raw, err := data.ReadFile("data/categories.json")
		if err != nil {
			panic(err)
		}
		if err := json.Unmarshal(raw, &embedded); err != nil {
			panic(err)
		}
	})
}

// ErrCategory means an override names an unknown licence or category.
var ErrCategory = errors.New("override must map an SPDX id or LicenseRef to a known category")

// NewCatalog returns the embedded mapping with overrides applied.
func NewCatalog(revision int64, overrides map[string]string) (*Catalog, error) {
	loadEmbedded()
	load()
	c := &Catalog{Version: embedded.Version, Source: embedded.Source, Revision: revision, Overrides: map[string]string{}, base: embedded.Categories}
	if len(overrides) > 2000 {
		return nil, ErrCategory
	}
	for id, category := range overrides {
		canonical, ok := canonicalID(id)
		if !ok || !ValidCategory(category) {
			return nil, ErrCategory
		}
		c.Overrides[canonical] = category
	}
	return c, nil
}

// DefaultCatalog is the embedded mapping without overrides.
func DefaultCatalog() *Catalog {
	c, _ := NewCatalog(0, nil)
	return c
}

// Category returns the category of one licence id (without exception).
func (c *Catalog) Category(id string) string {
	if category, ok := c.Overrides[id]; ok {
		return category
	}
	id = strings.TrimSuffix(id, "+")
	if category, ok := c.base[id]; ok {
		return category
	}
	if ref, ok := builtinRefs[id]; ok {
		return ref.category
	}
	return Unknown
}

// LeafCategory applies a WITH exception: a linking or runtime exception
// (Classpath, GCC runtime) turns strong copyleft into weak copyleft.
func (c *Catalog) LeafCategory(n *Node) string {
	category := c.Category(n.ID)
	if n.Exception != "" && linking[n.Exception] && category == StrongCopyleft {
		return WeakCopyleft
	}
	return category
}

// Entries lists every mapped id with its effective category.
func (c *Catalog) Entries() map[string]string {
	out := make(map[string]string, len(c.base)+len(builtinRefs)+len(c.Overrides))
	for id, category := range c.base {
		out[id] = category
	}
	for id, ref := range builtinRefs {
		out[id] = ref.category
	}
	for id, category := range c.Overrides {
		out[id] = category
	}
	return out
}

// Counts returns how many ids map to each category.
func (c *Catalog) Counts() map[string]int {
	out := map[string]int{}
	for _, category := range c.Entries() {
		out[category]++
	}
	return out
}

// BuiltinRefs lists the LicenseRefs SCRS assigns, sorted.
func BuiltinRefs() []Info {
	out := make([]Info, 0, len(builtinRefs))
	for id, ref := range builtinRefs {
		out = append(out, Info{ID: id, Name: ref.name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
