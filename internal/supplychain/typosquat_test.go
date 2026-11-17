package supplychain

import "testing"

func TestLookalike(t *testing.T) {
	for _, tc := range []struct {
		ecosystem, name, want string
	}{
		{"npm", "crossenv", "cross-env"},   // dropped hyphen, a real attack
		{"npm", "loadsh", "lodash"},        // swapped letters
		{"npm", "mongose", "mongoose"},     // dropped letter
		{"npm", "expresss", "express"},     // doubled letter
		{"npm", "react-dom-", "react-dom"}, // a stray separator
		{"npm", "reactt", "react"},         // inserted letter
		{"npm", "lodash", ""},              // the popular package itself
		{"npm", "left-pad", ""},            // popular
		{"npm", "@scope/lodsh", ""},        // scoped names are not compared
		{"npm", "my-internal-lib", ""},     // nothing close
		{"npm", "abc", ""},                 // too short to compare
		{"PyPI", "reqeusts", "requests"},   // swapped
		{"PyPI", "Requests", ""},           // case folding: it is the package
		{"PyPI", "python_dateutil", ""},    // separators fold: it is the package
		{"PyPI", "python-dateutils", "python-dateutil"},
		{"PyPI", "numpyy", "numpy"},
		{"Go", "github.com/x/lodsh", ""},     // other ecosystems are not covered
		{"npm:registry", "loadsh", "lodash"}, // ecosystem suffix is ignored
	} {
		got, ok := Lookalike(tc.ecosystem, tc.name)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("Lookalike(%s, %s) = %q, %v; want %q", tc.ecosystem, tc.name, got, ok, tc.want)
		}
	}
}

func TestPopularListsAreNormalisedAndDistinct(t *testing.T) {
	for name, list := range map[string][]string{"npm": popularNPM, "PyPI": popularPyPI} {
		seen := map[string]bool{}
		for _, n := range list {
			if n != normalizedForTest(name, n) {
				t.Errorf("%s: %q is not in normalised form", name, n)
			}
			if seen[n] {
				t.Errorf("%s: %q is listed twice", name, n)
			}
			seen[n] = true
		}
	}
}

func normalizedForTest(ecosystem, name string) string {
	n, _, _, _ := normalize(ecosystem, name)
	return n
}
