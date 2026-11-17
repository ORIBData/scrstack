package semver

import "testing"

func TestParseAndCompare(t *testing.T) {
	ordered := []string{"0.0.1", "0.1.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"}
	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			a, okA := Parse(ordered[i])
			b, okB := Parse(ordered[j])
			if !okA || !okB {
				t.Fatalf("%s or %s did not parse", ordered[i], ordered[j])
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(a, b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	for in, want := range map[string]string{"v1.2.3": "1.2.3", "1.2": "1.2.0", "1": "1.0.0", "1.2.3+build.5": "1.2.3"} {
		a, ok := Parse(in)
		b, _ := Parse(want)
		if !ok || Compare(a, b) != 0 {
			t.Errorf("Parse(%q) should equal %s", in, want)
		}
	}
	for _, bad := range []string{"", "1.2.3.4", "a.b.c", "1..2", "01.2.3", "1.2.3-", "1.2.3-01", "1.2.3-a..b", "-1.0.0", "1.2.x"} {
		if _, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) was accepted", bad)
		}
	}
	// Build metadata does not change precedence.
	a, _ := Parse("1.0.0+a")
	b, _ := Parse("1.0.0+b")
	if Compare(a, b) != 0 {
		t.Error("build metadata must be ignored")
	}
}

func TestRange(t *testing.T) {
	for _, tc := range []struct {
		r       Range
		version string
		want    bool
	}{
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "1.0.0", true},
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "1.2.2", true},
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "1.2.3", false}, // fixed is exclusive
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "0.9.9", false},
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "1.2.3-rc.1", true}, // a prerelease of the fix is below it
		{Range{Introduced: "0", Fixed: "2.0.0"}, "0.0.1", true},
		{Range{Fixed: "2.0.0"}, "1.9.9", true},
		{Range{Introduced: "1.0.0", LastAffected: "1.4.0"}, "1.4.0", true}, // last_affected is inclusive
		{Range{Introduced: "1.0.0", LastAffected: "1.4.0"}, "1.4.1", false},
		{Range{Introduced: "2.0.0"}, "99.0.0", true}, // no upper end
		{Range{Introduced: "2.0.0"}, "1.9.9", false},
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "not-a-version", false},
		{Range{Introduced: "1.0.0", Fixed: "1.2.3"}, "v1.1.0", true},
	} {
		if got := tc.r.Contains(tc.version); got != tc.want {
			t.Errorf("%+v contains %q = %v, want %v", tc.r, tc.version, got, tc.want)
		}
	}
	for _, r := range []Range{{Introduced: "2.0.0", Fixed: "1.0.0"}, {Introduced: "1.0.0", Fixed: "1.0.0"}, {Fixed: "1.0.0", LastAffected: "1.0.0"}, {Introduced: "x"}, {Fixed: "y"}} {
		if r.Valid() {
			t.Errorf("%+v should be invalid", r)
		}
	}
	if !(Range{Introduced: "1.0.0", LastAffected: "1.0.0"}).Valid() {
		t.Error("a single affected version is a valid range")
	}
	for eco, want := range map[string]bool{"npm": true, "Go": true, "crates.io": true, "PyPI": false, "Maven": false, "Alpine:v3.19": false, "npm:registry": true} {
		if Supported(eco) != want {
			t.Errorf("Supported(%s) != %v", eco, want)
		}
	}
}
