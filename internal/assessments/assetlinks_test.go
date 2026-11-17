package assessments

import "testing"

func TestParseSourceLabel(t *testing.T) {
	for _, tc := range []struct {
		label, provider, path string
		ok                    bool
	}{
		{"https://github.com/acme/api", "github", "acme/api", true},
		{"https://github.com/acme/api.git", "github", "acme/api", true},
		{"https://github.com/acme/api/", "github", "acme/api", true},
		{"http://www.github.com/acme/api", "github", "acme/api", true},
		{"git@github.com:acme/api.git", "github", "acme/api", true},
		{"ssh://git@github.com/acme/api.git", "github", "acme/api", true},
		{"https://gitlab.com/acme/platform/api", "gitlab", "acme/platform/api", true},
		{"https://gitlab.example.com/team/svc.git", "gitlab", "team/svc", true},
		{"https://git.example.com/team/svc", "", "team/svc", true},
		{"https://github.com/acme/api/tree/main", "", "", false}, // a path into the repository
		{"https://github.com/acme", "", "", false},
		{"https://github.com/acme/api?x=1", "", "", false},
		{"https://github.com/acme/api#readme", "", "", false},
		{"https://user:pw@github.com/acme/api", "", "", false},
		{"ftp://github.com/acme/api", "", "", false},
		{"https://github.com/ac me/api", "", "", false},
		{"https://github.com/../etc", "", "", false},
		{"", "", "", false},
		{"not a url", "", "", false},
	} {
		provider, path, ok := ParseSourceLabel(tc.label)
		if ok != tc.ok || provider != tc.provider || path != tc.path {
			t.Errorf("ParseSourceLabel(%q) = %q, %q, %v; want %q, %q, %v", tc.label, provider, path, ok, tc.provider, tc.path, tc.ok)
		}
	}
}
