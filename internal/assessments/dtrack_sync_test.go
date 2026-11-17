package assessments

import (
	"reflect"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/dtrack"
)

func TestDTrackIdentity(t *testing.T) {
	git := func(ref string, pr bool) Target {
		target := Target{Type: "git", Repository: "org/app", Ref: ref}
		if pr {
			target.PullRequest = &PullRequest{}
		}
		return target
	}
	cases := []struct {
		name                              string
		assetType, locator, defaultBranch string
		target                            Target
		commit                            string
		pr, commitOnly                    bool
		want                              DTrackIdentity
		ok                                bool
	}{
		{"default branch is the latest version", "github_repo", "org/app", "main", git("main", false), "abc", false, false, DTrackIdentity{"github/org/app", "main", true}, true},
		{"another branch is not", "github_repo", "org/app", "main", git("release/1", false), "abc", false, false, DTrackIdentity{"github/org/app", "release/1", false}, true},
		{"the provider keeps same paths apart", "gitlab_repo", "org/app", "main", git("main", false), "abc", false, false, DTrackIdentity{"gitlab/org/app", "main", true}, true},
		{"no default branch known", "github_repo", "org/app", "", git("main", false), "abc", false, false, DTrackIdentity{"github/org/app", "main", false}, true},
		{"a bare commit is skipped", "github_repo", "org/app", "main", git("", false), "abc", false, false, DTrackIdentity{}, false},
		{"a bare commit when asked for", "github_repo", "org/app", "main", git("", false), "abc", false, true, DTrackIdentity{"github/org/app", "abc", false}, true},
		{"a pull request is skipped", "github_repo", "org/app", "main", git("main", true), "abc", false, false, DTrackIdentity{}, false},
		{"a pull request when asked for is never latest", "github_repo", "org/app", "main", git("main", true), "abc", true, false, DTrackIdentity{"github/org/app", "main", false}, true},
		{"an image falls back to its digest", "container_image", "ghcr.io/org/app", "", Target{Type: "image"}, "sha256:aa", false, false, DTrackIdentity{"image/ghcr.io/org/app", "sha256:aa", false}, true},
		{"an image tag", "container_image", "ghcr.io/org/app", "", Target{Type: "image", Ref: "1.2.3"}, "sha256:aa", false, false, DTrackIdentity{"image/ghcr.io/org/app", "1.2.3", false}, true},
	}
	for _, c := range cases {
		got, ok := dtrackIdentity(c.assetType, c.locator, c.defaultBranch, c.target, c.commit, c.pr, c.commitOnly)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizePURL(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/Lodash@4.17.20":                      "pkg:npm/lodash@4.17.20",
		"pkg:maven/org.x/y@1.0?type=jar&classifier=a": "pkg:maven/org.x/y@1.0",
		"pkg:golang/github.com/a/b@v1.2.3#sub/path":   "pkg:golang/github.com/a/b@v1.2.3",
		"  pkg:pypi/django@4.2  ":                     "pkg:pypi/django@4.2",
		"":                                            "",
	} {
		if got := normalizePURL(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func finding(component, purl, vulnerability, source string, severity string, ids ...string) dtrack.Finding {
	return dtrack.Finding{ComponentUUID: component, PURL: purl, VulnerabilityUUID: vulnerability, VulnID: ids[0], IDs: ids, Source: source, Severity: severity, Analyzer: source + "_ANALYZER"}
}

func TestClusterDTrackFindings(t *testing.T) {
	const lodash = "pkg:npm/lodash@4.17.20"
	in := []dtrack.Finding{
		// One vulnerability, three IDs, reported by two sources: one cluster.
		finding("c1", lodash+"?x=1", "v1", "NVD", "HIGH", "CVE-2021-23337"),
		finding("c1", lodash, "v2", "GITHUB", "critical", "GHSA-35JH-R3H4-6JHM", "cve-2021-23337"),
		// A different vulnerability on the same component stays separate.
		finding("c1", lodash, "v3", "OSV", "low", "CVE-2020-8203"),
		// The same ID on another component is another cluster.
		finding("c2", "pkg:npm/lodash@4.17.21", "v4", "NVD", "high", "CVE-2021-23337"),
		// A component without a package URL clusters by name.
		{ComponentUUID: "c3", ComponentName: "tool", ComponentVersion: "1", VulnerabilityUUID: "v5", VulnID: "SNYK-1", IDs: []string{"SNYK-1"}, Severity: "medium"},
	}
	clusters := clusterDTrackFindings(in)
	if len(clusters) != 4 {
		t.Fatalf("clusters %d: %+v", len(clusters), clusters)
	}
	first := clusters[0]
	if first.PURL != "pkg:npm/lodash@4.17.20" || len(first.Members) != 2 || first.Severity != "critical" || first.Canonical != "CVE-2021-23337" ||
		!reflect.DeepEqual(first.IDs, []string{"CVE-2021-23337", "GHSA-35JH-R3H4-6JHM"}) || !reflect.DeepEqual(first.Sources, []string{"GITHUB", "NVD"}) || len(first.Analyzers) != 2 {
		t.Fatalf("merged cluster %+v", first)
	}
	if clusters[1].Canonical != "CVE-2020-8203" || clusters[2].PURL != "pkg:npm/lodash@4.17.21" || clusters[3].Canonical != "SNYK-1" {
		t.Fatalf("separate clusters %+v", clusters)
	}
	// GHSA is preferred over other IDs when no CVE exists.
	if got := canonicalID([]string{"GHSA-AAAA", "OSV-1", "SNYK-1"}); got != "GHSA-AAAA" {
		t.Fatal(got)
	}
}

func TestDTrackStatusMappings(t *testing.T) {
	until := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	for status, want := range map[string]struct {
		state      string
		suppressed bool
		ok         bool
	}{
		"open":           {"NOT_SET", false, true},
		"triaged":        {"IN_TRIAGE", false, true},
		"in_progress":    {"IN_TRIAGE", false, true},
		"accepted":       {"EXPLOITABLE", false, true},
		"false_positive": {"FALSE_POSITIVE", true, true},
		"suppressed":     {"NOT_AFFECTED", true, true},
		"fixed":          {"", false, false},
	} {
		a, ok := dtrackStatusFor(status, &until)
		if ok != want.ok || a.State != want.state || a.Suppressed != want.suppressed {
			t.Errorf("%s: %+v %v", status, a, ok)
		}
	}
	if a, _ := dtrackStatusFor("accepted", &until); a.Response != "WILL_NOT_FIX" || a.Details == "" {
		t.Fatalf("accepted risk: %+v", a)
	}

	m := func(state string, suppressed bool) dtrack.Finding {
		return dtrack.Finding{AnalysisState: state, Suppressed: suppressed}
	}
	for name, c := range map[string]struct {
		members []dtrack.Finding
		want    string
	}{
		"nothing analysed":             {[]dtrack.Finding{m("NOT_SET", false)}, ""},
		"resolved is decided by scans": {[]dtrack.Finding{m("RESOLVED", false)}, ""},
		"false positive":               {[]dtrack.Finding{m("FALSE_POSITIVE", true)}, "false_positive"},
		"not affected":                 {[]dtrack.Finding{m("NOT_AFFECTED", true)}, "suppressed"},
		"suppressed without a state":   {[]dtrack.Finding{m("NOT_SET", true)}, "suppressed"},
		"exploitable":                  {[]dtrack.Finding{m("EXPLOITABLE", false)}, "triaged"},
		"in triage":                    {[]dtrack.Finding{m("IN_TRIAGE", false)}, "triaged"},
		"all members agree to hide":    {[]dtrack.Finding{m("FALSE_POSITIVE", true), m("FALSE_POSITIVE", true)}, "false_positive"},
		"one source analysed, one not": {[]dtrack.Finding{m("FALSE_POSITIVE", true), m("NOT_SET", false)}, "triaged"},
		"members disagree":             {[]dtrack.Finding{m("FALSE_POSITIVE", true), m("EXPLOITABLE", false)}, "triaged"},
		"different hiding decisions":   {[]dtrack.Finding{m("FALSE_POSITIVE", true), m("NOT_AFFECTED", true)}, "triaged"},
	} {
		if got := dtrackImportStatus(c.members); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}
