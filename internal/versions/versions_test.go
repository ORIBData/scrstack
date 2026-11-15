package versions

import "testing"

func adv(id, eco, name string, events ...Event) Advisory {
	return Advisory{ID: id, Affected: []Affected{{Ecosystem: eco, Name: name, Ranges: []Range{{Type: "ECOSYSTEM", Events: events}}}}}
}

func TestAffects(t *testing.T) {
	a := adv("GHSA-1", "npm", "lodash", Event{Introduced: "0"}, Event{Fixed: "4.17.21"})
	for v, want := range map[string]bool{"4.17.20": true, "4.17.21": false, "1.0.0": true, "5.0.0": false} {
		if got, err := Affects("npm", "lodash", v, a); err != nil || got != want {
			t.Errorf("lodash %s: %v %v", v, got, err)
		}
	}
	// Two introduced/fixed pairs and last_affected.
	b := adv("GHSA-2", "PyPI", "django", Event{Introduced: "3.2"}, Event{Fixed: "3.2.25"}, Event{Introduced: "4.0"}, Event{LastAffected: "4.2.10"})
	for v, want := range map[string]bool{"3.1": false, "3.2.24": true, "3.2.25": false, "4.1": true, "4.2.10": true, "4.2.11": false, "5.0": false} {
		if got, err := Affects("PyPI", "Django", v, b); err != nil || got != want {
			t.Errorf("django %s: %v %v", v, got, err)
		}
	}
	// Debian ordering, release-scoped ecosystem.
	d := adv("DEBIAN-CVE-1", "Debian:12", "openssl", Event{Introduced: "0"}, Event{Fixed: "3.0.15-1~deb12u1"})
	if got, _ := Affects("Debian:12", "openssl", "3.0.11-1~deb12u2", d); !got {
		t.Error("Debian version before fix not affected")
	}
	if got, _ := Affects("Debian:13", "openssl", "3.0.11-1~deb12u2", d); got {
		t.Error("another Debian release matched")
	}
	if got, _ := Affects("npm", "lodash", "4.17.20", Advisory{Withdrawn: true, Affected: a.Affected}); got {
		t.Error("withdrawn advisory affects")
	}
	explicit := Advisory{ID: "X", Affected: []Affected{{Ecosystem: "npm", Name: "x", Versions: []string{"1.0.1"}}}}
	if got, _ := Affects("npm", "x", "1.0.1", explicit); !got {
		t.Error("explicit versions list ignored")
	}
}

func TestSafeVersions(t *testing.T) {
	// The PRD case: 1.0 is affected by A (fixed 1.2); B affects 1.1 up to
	// 1.3 (fixed 1.4). 1.2 fixes A but B affects it, so the smallest safe
	// upgrade is 1.4.0, which only the full package advisory set reveals.
	a := adv("GHSA-A", "npm", "pkg", Event{Introduced: "0"}, Event{Fixed: "1.2.0"})
	b := adv("GHSA-B", "npm", "pkg", Event{Introduced: "1.1.0"}, Event{Fixed: "1.4.0"})
	onlyMatched := SafeVersions("npm", "pkg", "1.0.0", []Advisory{a}, nil, nil)
	if onlyMatched.SmallestUpgrade != "1.2.0" || onlyMatched.Basis.Mirror {
		t.Fatalf("matched-only: %+v", onlyMatched)
	}
	full := SafeVersions("npm", "pkg", "1.0.0", []Advisory{a}, &Package{Ecosystem: "npm", Name: "pkg", Advisories: []Advisory{a, b}, Complete: true}, nil)
	if full.SmallestUpgrade != "1.4.0" || len(full.Fixed) != 1 || full.Fixed[0] != "1.2.0" || !full.Basis.Mirror || full.Basis.Versions != "advisory_fixes" || full.Latest != "" {
		t.Fatalf("full index: %+v", full)
	}
	published := []string{"0.9.0", "1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0-beta.1", "1.5.0", "2.0.0"}
	registry := SafeVersions("npm", "pkg", "1.0.0", []Advisory{a}, &Package{Advisories: []Advisory{a, b}, Complete: true}, published)
	if registry.SmallestUpgrade != "1.4.0" || registry.Latest != "2.0.0" || len(registry.Safe) != 3 || registry.Safe[1] != "1.5.0" || registry.Basis.Versions != "registry" {
		t.Fatalf("registry list: %+v", registry)
	}
	none := SafeVersions("npm", "pkg", "1.0.0", []Advisory{adv("GHSA-C", "npm", "pkg", Event{Introduced: "0"})}, nil, published)
	if none.SmallestUpgrade != "" || len(none.Safe) != 0 {
		t.Fatalf("no fix: %+v", none)
	}
	many := []string{}
	for _, v := range []string{"1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7", "1.4.8", "1.4.9", "1.4.10", "3.0.0"} {
		many = append(many, v)
	}
	capped := SafeVersions("npm", "pkg", "1.0.0", []Advisory{a}, nil, many)
	if len(capped.Safe) != 10 || capped.Safe[9] != "3.0.0" || capped.Latest != "3.0.0" {
		t.Fatalf("cap: %+v", capped.Safe)
	}
	if !Prerelease("PyPI", "2.0rc1") || Prerelease("PyPI", "2.0.1") || !Prerelease("Maven", "2.0-SNAPSHOT") || !Prerelease("npm", "1.0.0-alpha.1") || Prerelease("Go", "v1.2.3+incompatible") {
		t.Fatal("pre-release detection")
	}
	if _, err := Compare("CocoaPods", "1.0", "2.0"); err != ErrUnsupported {
		t.Fatalf("unsupported ecosystem: %v", err)
	}
}
