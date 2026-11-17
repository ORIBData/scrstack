// Package semver compares versions by Semantic Versioning 2.0 precedence, as
// the OSV SEMVER range type and most ecosystems (npm, Go, crates.io) define
// it. It exists so local advisories (OSV-008) can name ranges. It is not a
// general version library: ecosystems with their own ordering (PyPI's PEP 440,
// Maven, Debian, RubyGems) are not covered.
package semver

import (
	"strconv"
	"strings"
)

// Version is a parsed version.
type Version struct {
	Major, Minor, Patch uint64
	// Pre holds the dot-separated prerelease identifiers; empty for a release.
	Pre []string
}

// Parse reads a version. A leading `v` (Go) is accepted, and so are versions
// with fewer than three numbers ("1.2" is 1.2.0), because lockfiles carry
// them. Build metadata after `+` is ignored, as precedence ignores it.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return Version{}, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v Version
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre {
		if pre == "" {
			return Version{}, false
		}
		v.Pre = strings.Split(pre, ".")
		for _, id := range v.Pre {
			if id == "" || !identifier(id) {
				return Version{}, false
			}
			if numeric(id) && len(id) > 1 && id[0] == '0' {
				return Version{}, false
			}
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return Version{}, false
	}
	nums := [3]uint64{}
	for i, p := range parts {
		if p == "" || !numeric(p) || (len(p) > 1 && p[0] == '0') {
			return Version{}, false
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Version{}, false
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, true
}

func numeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func identifier(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return false
		}
	}
	return true
}

// Compare orders two versions: negative when a < b, zero when equal, positive
// when a > b. A prerelease is lower than its release.
func Compare(a, b Version) int {
	for _, d := range [3][2]uint64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		x, y := a.Pre[i], b.Pre[i]
		if x == y {
			continue
		}
		xn, yn := numeric(x), numeric(y)
		switch {
		case xn && yn:
			xi, _ := strconv.ParseUint(x, 10, 64)
			yi, _ := strconv.ParseUint(y, 10, 64)
			if xi < yi {
				return -1
			}
			return 1
		case xn:
			return -1 // numeric identifiers rank below alphanumeric ones
		case yn:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a.Pre) < len(b.Pre):
		return -1
	case len(a.Pre) > len(b.Pre):
		return 1
	}
	return 0
}

// Range is one OSV interval: affected from Introduced (inclusive; empty means
// from the first version) until Fixed (exclusive) or LastAffected (inclusive).
// At most one of Fixed and LastAffected is set; with neither the interval has
// no upper end.
type Range struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Valid reports whether the range's bounds all parse and it is not empty.
func (r Range) Valid() bool {
	if r.Fixed != "" && r.LastAffected != "" {
		return false
	}
	var lower, upper *Version
	if r.Introduced != "" && r.Introduced != "0" {
		v, ok := Parse(r.Introduced)
		if !ok {
			return false
		}
		lower = &v
	}
	for _, bound := range []string{r.Fixed, r.LastAffected} {
		if bound == "" {
			continue
		}
		v, ok := Parse(bound)
		if !ok {
			return false
		}
		upper = &v
	}
	if lower != nil && upper != nil {
		c := Compare(*lower, *upper)
		return c < 0 || (c == 0 && r.LastAffected != "")
	}
	return true
}

// Contains reports whether version falls inside the range. A version that does
// not parse is never contained: a range cannot judge what it cannot order.
func (r Range) Contains(version string) bool {
	v, ok := Parse(version)
	if !ok || !r.Valid() {
		return false
	}
	if r.Introduced != "" && r.Introduced != "0" {
		lo, _ := Parse(r.Introduced)
		if Compare(v, lo) < 0 {
			return false
		}
	}
	switch {
	case r.Fixed != "":
		hi, _ := Parse(r.Fixed)
		return Compare(v, hi) < 0
	case r.LastAffected != "":
		hi, _ := Parse(r.LastAffected)
		return Compare(v, hi) <= 0
	}
	return true
}

// Supported reports whether an OSV ecosystem orders its versions by semantic
// versioning, so a range can be applied to it. The ecosystem may carry a
// suffix after `:`.
func Supported(ecosystem string) bool {
	base, _, _ := strings.Cut(ecosystem, ":")
	switch strings.ToLower(base) {
	case "npm", "go", "crates.io", "hex", "pub", "swifturl", "nuget":
		return true
	}
	return false
}
