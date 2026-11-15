// Package versions evaluates OSV affected ranges with each ecosystem's own
// version ordering and computes safe versions (VUL-008).
package versions

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Range is an OSV affected range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Affected is one OSV affected entry for a package.
type Affected struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Ranges    []Range  `json:"ranges,omitempty"`
	Versions  []string `json:"versions,omitempty"`
}

// Advisory is an OSV record reduced to one package's affected entries.
type Advisory struct {
	ID        string     `json:"id"`
	Withdrawn bool       `json:"withdrawn,omitempty"`
	Affected  []Affected `json:"affected"`
}

// Package groups every known advisory for one package (from the local OSV
// mirror's index, or only the matched ones when the index is missing).
type Package struct {
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Advisories []Advisory `json:"advisories"`
	// Complete is true when Advisories came from the full mirror index.
	Complete bool `json:"complete"`
}

// ErrUnsupported means SCRS cannot order versions of this ecosystem.
var ErrUnsupported = errors.New("version ordering not supported for this ecosystem")

func base(ecosystem string) string {
	b, _, _ := strings.Cut(ecosystem, ":")
	return b
}

// Compare orders two versions of one ecosystem: -1, 0 or +1.
func Compare(ecosystem, a, b string) (int, error) {
	v, err := semantic.Parse(a, base(ecosystem))
	if err != nil {
		if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
			return 0, ErrUnsupported
		}
		return 0, err
	}
	return v.CompareStr(b)
}

// rangeEcosystem is the ordering a range uses: SEMVER ranges are SemVer
// 2.0 whatever the package's ecosystem; GIT ranges cannot be evaluated.
func rangeEcosystem(r Range, ecosystem string) (string, bool) {
	switch r.Type {
	case "SEMVER":
		return "npm", true
	case "ECOSYSTEM":
		return ecosystem, true
	}
	return "", false
}

// Affects reports whether version is affected by the advisory's entries
// for this ecosystem and package name, following the OSV schema's
// evaluation of sorted events.
func Affects(ecosystem, name, version string, a Advisory) (bool, error) {
	if a.Withdrawn {
		return false, nil
	}
	for _, entry := range a.Affected {
		if !sameEcosystem(entry.Ecosystem, ecosystem) || !strings.EqualFold(entry.Name, name) {
			continue
		}
		for _, v := range entry.Versions {
			if v == version {
				return true, nil
			}
		}
		for _, r := range entry.Ranges {
			kind, ok := rangeEcosystem(r, ecosystem)
			if !ok {
				continue
			}
			hit, err := inRange(kind, version, r.Events)
			if err != nil {
				return false, err
			}
			if hit {
				return true, nil
			}
		}
	}
	return false, nil
}

// sameEcosystem matches "Debian:12" exactly and ecosystems without a
// release suffix by name.
func sameEcosystem(entry, component string) bool {
	if entry == component {
		return true
	}
	return !strings.Contains(entry, ":") && !strings.Contains(component, ":") && strings.EqualFold(entry, component)
}

type sortable struct {
	event   Event
	version string
	zero    bool
}

func inRange(ecosystem, version string, events []Event) (bool, error) {
	list := make([]sortable, 0, len(events))
	for _, e := range events {
		s := sortable{event: e}
		switch {
		case e.Introduced != "":
			s.version, s.zero = e.Introduced, e.Introduced == "0"
		case e.Fixed != "":
			s.version = e.Fixed
		case e.LastAffected != "":
			s.version = e.LastAffected
		default:
			continue
		}
		list = append(list, s)
	}
	var sortErr error
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].zero != list[j].zero {
			return list[i].zero
		}
		if list[i].zero {
			return false
		}
		c, err := Compare(ecosystem, list[i].version, list[j].version)
		if err != nil {
			sortErr = err
		}
		return c < 0
	})
	if sortErr != nil {
		return false, sortErr
	}
	affected := false
	for _, s := range list {
		e := s.event
		switch {
		case e.Introduced != "":
			if s.zero {
				affected = true
				continue
			}
			c, err := Compare(ecosystem, version, e.Introduced)
			if err != nil {
				return false, err
			}
			if c >= 0 {
				affected = true
			}
		case e.Fixed != "":
			c, err := Compare(ecosystem, version, e.Fixed)
			if err != nil {
				return false, err
			}
			if c >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			c, err := Compare(ecosystem, version, e.LastAffected)
			if err != nil {
				return false, err
			}
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, nil
}

// Fixes lists the distinct fixed versions an advisory names for a package.
func Fixes(ecosystem, name string, a Advisory) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, entry := range a.Affected {
		if !sameEcosystem(entry.Ecosystem, ecosystem) || !strings.EqualFold(entry.Name, name) {
			continue
		}
		for _, r := range entry.Ranges {
			if _, ok := rangeEcosystem(r, ecosystem); !ok {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

var (
	pypiPre   = regexp.MustCompile(`(?i)(a|b|c|rc|alpha|beta|pre|preview|dev)[0-9]*`)
	mavenPre  = regexp.MustCompile(`(?i)(snapshot|alpha|beta|[.-]rc|[.-]m[0-9]|milestone|preview|[.-]cr[0-9])`)
	rubyPre   = regexp.MustCompile(`[A-Za-z]`)
	semverPre = regexp.MustCompile(`-`)
)

// Prerelease reports whether a version is a pre-release in its ecosystem.
func Prerelease(ecosystem, version string) bool {
	switch base(ecosystem) {
	case "PyPI":
		return pypiPre.MatchString(version)
	case "Maven":
		return mavenPre.MatchString(version)
	case "RubyGems":
		return rubyPre.MatchString(version)
	case "npm", "Go", "crates.io", "NuGet", "Pub", "Packagist", "Hex", "SwiftURL":
		return semverPre.MatchString(strings.SplitN(version, "+", 2)[0])
	}
	return false
}

// Safe is the VUL-008 result for one component.
type Safe struct {
	// Fixed lists the versions the matched advisories name as fixes.
	Fixed []string `json:"fixed_versions"`
	// Safe lists, in ascending order and capped at ten, candidate versions
	// above the current one that no known advisory for the package affects.
	Safe []string `json:"safe_versions"`
	// SmallestUpgrade is the lowest safe version above the current one.
	SmallestUpgrade string `json:"smallest_safe_upgrade,omitempty"`
	// Latest is the highest safe version, named only when a full version
	// list was available.
	Latest string `json:"latest_safe,omitempty"`
	Basis  Basis  `json:"safe_basis"`
}

// Basis records what a safe-version answer rests on.
type Basis struct {
	// Advisories is the number of advisories checked; Mirror is true when
	// they are every record the local OSV mirror holds for the package.
	Advisories int  `json:"advisories"`
	Mirror     bool `json:"full_mirror"`
	// Versions is "registry" when a published version list was used and
	// "advisory_fixes" when only the advisories' fixed versions were.
	Versions   string `json:"versions"`
	Candidates int    `json:"candidates"`
	Error      string `json:"error,omitempty"`
}

// SafeVersions computes fixed and safe versions for a component at current
// (VUL-008). matched are the advisories found for the component; pkg, when
// non-nil, holds every known advisory for the package; published is the
// registry's version list (nil when unavailable).
func SafeVersions(ecosystem, name, current string, matched []Advisory, pkg *Package, published []string) Safe {
	out := Safe{Fixed: []string{}, Safe: []string{}}
	known := matched
	if pkg != nil && len(pkg.Advisories) > 0 {
		known, out.Basis.Mirror = pkg.Advisories, pkg.Complete
	}
	out.Basis.Advisories = len(known)
	seen := map[string]bool{}
	for _, a := range matched {
		for _, f := range Fixes(ecosystem, name, a) {
			if !seen[f] {
				seen[f] = true
				out.Fixed = append(out.Fixed, f)
			}
		}
	}
	candidates := published
	out.Basis.Versions = "registry"
	if len(published) == 0 {
		out.Basis.Versions = "advisory_fixes"
		candidates = nil
		all := map[string]bool{}
		for _, a := range known {
			for _, f := range Fixes(ecosystem, name, a) {
				if !all[f] {
					all[f] = true
					candidates = append(candidates, f)
				}
			}
		}
	}
	allowPre := Prerelease(ecosystem, current)
	above := []string{}
	for _, v := range candidates {
		if !allowPre && Prerelease(ecosystem, v) {
			continue
		}
		c, err := Compare(ecosystem, v, current)
		if err != nil {
			out.Basis.Error = err.Error()
			return out
		}
		if c > 0 {
			above = append(above, v)
		}
	}
	out.Basis.Candidates = len(above)
	var sortErr error
	sort.SliceStable(above, func(i, j int) bool {
		c, err := Compare(ecosystem, above[i], above[j])
		if err != nil {
			sortErr = err
		}
		return c < 0
	})
	if sortErr != nil {
		out.Basis.Error = sortErr.Error()
		return out
	}
	safe := []string{}
	for _, v := range above {
		clean := true
		for _, a := range known {
			hit, err := Affects(ecosystem, name, v, a)
			if err != nil {
				out.Basis.Error = err.Error()
				return out
			}
			if hit {
				clean = false
				break
			}
		}
		if clean {
			safe = append(safe, v)
		}
	}
	if len(safe) == 0 {
		return out
	}
	out.SmallestUpgrade = safe[0]
	if len(published) > 0 {
		out.Latest = safe[len(safe)-1]
	}
	if len(safe) > 10 {
		// The lowest nine and the latest: enough to choose a minimal or a
		// current upgrade.
		safe = append(safe[:9:9], safe[len(safe)-1])
	}
	out.Safe = safe
	return out
}
