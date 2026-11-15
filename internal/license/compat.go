package license

import (
	"strings"
)

// Outbound-licence compatibility (LIC-005, P2): can a dependency be
// combined into a project released under the project's own licence? This
// is a conservative policy aid for counsel, not legal advice. It answers
// allow, review or deny:
//
//   - deny: the licences are known to conflict (for example GPL code in an
//     MIT project, Apache-2.0 in a GPL-2.0-only project, non-commercial
//     terms in any open-source project);
//   - review: combination is possible with conditions (file-level or
//     linking obligations, the AGPL network clause, the combined work
//     moving to a later GPL version, unknown terms);
//   - allow: no known conflict.
//
// A dependency expression takes its most lenient option for OR and its
// strictest for AND. A project expression is checked against every
// licence it names: AND takes the strictest result; OR takes the result
// when its options agree and review when they do not.

// Compatibility is one outbound check.
type Compatibility struct {
	Effect     string   `json:"effect"`
	Project    string   `json:"project_license"`
	Dependency string   `json:"dependency_license"`
	Category   string   `json:"category"`
	Licenses   []string `json:"licenses"`
	Reason     string   `json:"reason"`
}

// OutboundApplies reports whether a project licence can be checked: it
// must parse and name only known open-source categories.
func OutboundApplies(c *Catalog, project string) bool {
	n, err := Parse(project)
	if err != nil || project == NoAssertion {
		return false
	}
	for _, leaf := range n.Leaves() {
		switch c.LeafCategory(leaf) {
		case Permissive, PublicDomain, WeakCopyleft, StrongCopyleft, NetworkCopyleft:
		default:
			return false
		}
	}
	return true
}

// Outbound checks a dependency licence against the project licence. An
// unparseable or NOASSERTION dependency is allowed here: the policy
// already reports it as unknown.
func Outbound(c *Catalog, project, dependency string) Compatibility {
	out := Compatibility{Effect: Allow, Project: project, Dependency: dependency, Licenses: []string{}}
	p, perr := Parse(project)
	d, derr := Parse(dependency)
	if perr != nil || derr != nil || dependency == NoAssertion || project == NoAssertion {
		return out
	}
	r := projectNode(c, p, d)
	r.Project, r.Dependency = project, dependency
	if r.Licenses == nil {
		r.Licenses = []string{}
	}
	return r
}

func projectNode(c *Catalog, p, d *Node) Compatibility {
	if p.Op == "" {
		return depNode(c, p, d)
	}
	left, right := projectNode(c, p.Left, d), projectNode(c, p.Right, d)
	if p.Op == "AND" {
		if rank(left.Effect) >= rank(right.Effect) {
			return left
		}
		return right
	}
	// OR: the project is offered under either licence.
	if left.Effect == right.Effect {
		return left
	}
	pick := left
	if rank(right.Effect) > rank(left.Effect) {
		pick = right
	}
	pick.Effect = Review
	pick.Reason = "Compatible with only some of the project's licence options: " + pick.Reason
	return pick
}

func depNode(c *Catalog, p, d *Node) Compatibility {
	if d.Op == "" {
		effect, reason := pair(c, p, d)
		return Compatibility{Effect: effect, Category: c.LeafCategory(d), Licenses: []string{d.ID}, Reason: reason}
	}
	left, right := depNode(c, p, d.Left), depNode(c, p, d.Right)
	pickLeft := rank(left.Effect) >= rank(right.Effect)
	if d.Op == "OR" {
		pickLeft = rank(left.Effect) <= rank(right.Effect)
	}
	if pickLeft {
		return left
	}
	return right
}

// family returns a licence id without its version suffix ("GPL-2.0"),
// and whether it allows later versions.
func family(id string) (string, bool) {
	later := strings.HasSuffix(id, "+") || strings.HasSuffix(id, "-or-later")
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(id, "+"), "-or-later"), "-only")
	return base, later
}

func gplVersion(base string) (string, string) {
	for _, f := range []string{"AGPL", "LGPL", "GPL"} {
		if v, ok := strings.CutPrefix(base, f+"-"); ok {
			return f, v
		}
	}
	return "", ""
}

// gplIncompatible lists weak-copyleft families the FSF lists as
// incompatible with the GPL.
var gplIncompatible = map[string]bool{"EPL-1.0": true, "CDDL-1.0": true, "CDDL-1.1": true, "MPL-1.1": true, "MPL-1.0": true, "CPL-1.0": true, "EUPL-1.1": true}

func pair(c *Catalog, p, d *Node) (string, string) {
	pc, dc := c.LeafCategory(p), c.LeafCategory(d)
	pBase, pLater := family(p.ID)
	dBase, dLater := family(d.ID)
	pFam, pVer := gplVersion(pBase)
	dFam, dVer := gplVersion(dBase)
	if p.ID == d.ID {
		return Allow, "Same licence as the project."
	}
	switch dc {
	case Permissive, PublicDomain:
		if dBase == "Apache-2.0" && pVer == "2.0" && !pLater && (pFam == "GPL" || pFam == "LGPL") {
			return Deny, "Apache-2.0 is incompatible with " + p.ID + " (its patent and indemnity terms are further restrictions under GPL version 2)."
		}
		if dBase == "Apache-2.0" && pFam == "LGPL" && pVer == "2.1" && !pLater {
			return Deny, "Apache-2.0 is incompatible with LGPL-2.1-only."
		}
		return Allow, "Permissive licence; keep its notices."
	case NonCommercial, SourceAvailableRestricted:
		return Deny, d.ID + " restricts use or redistribution, so the combined work cannot be released under the project's open-source licence."
	case Proprietary, Unknown:
		return Review, "The dependency's terms are unknown or proprietary; counsel must confirm it can be redistributed under the project's licence."
	case WeakCopyleft:
		if pc == StrongCopyleft || pc == NetworkCopyleft {
			switch {
			case gplIncompatible[dBase]:
				return Deny, d.ID + " is incompatible with the GPL family."
			case dBase == "EPL-2.0":
				return Review, "EPL-2.0 is GPL-compatible only when the dependency names the GPL as a Secondary License."
			case dFam == "LGPL" && dVer == "3.0" && pVer == "2.0" && !pLater:
				return Deny, "LGPL-3.0 code cannot be combined into a GPL-2.0-only work."
			}
			return Allow, d.ID + " can be combined into a copyleft work."
		}
		return Review, d.ID + " keeps its own terms for its files: ship its source or allow relinking as it requires, and do not relicense it under " + p.ID + "."
	case StrongCopyleft:
		if pc != StrongCopyleft && pc != NetworkCopyleft {
			return Deny, d.ID + " requires the combined work to be distributed under " + d.ID + ", so " + p.ID + " cannot be its outbound licence."
		}
		if dFam == "" || pFam == "" {
			return Review, "Copyleft licences from different families; counsel must confirm compatibility."
		}
		switch {
		case dVer == pVer:
			return Allow, "Same GPL version."
		case dVer == "2.0" && !dLater:
			return Deny, d.ID + " cannot be combined into a version 3 work."
		case pVer == "2.0" && !pLater:
			return Deny, d.ID + " cannot be combined into a GPL-2.0-only work."
		case dVer == "2.0" && dLater:
			return Allow, d.ID + " can be used under version 3."
		}
		return Review, "The combined work is distributed under " + d.ID + " (the project's 'or later' terms allow it); confirm the project accepts that."
	case NetworkCopyleft:
		if pFam == "AGPL" && dFam == "AGPL" {
			return Allow, "Same AGPL family."
		}
		if pFam == "GPL" && pVer == "3.0" || pFam == "GPL" && pLater {
			return Review, "GPL-3.0 section 13 permits combining with " + d.ID + "; its network-use clause then applies to the combined work."
		}
		return Deny, d.ID + " requires the combined work, including network use, to be under " + d.ID + "."
	}
	return Review, "No compatibility rule for this pair."
}
