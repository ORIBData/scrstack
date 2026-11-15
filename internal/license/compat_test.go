package license

import "testing"

func TestOutbound(t *testing.T) {
	c := DefaultCatalog()
	for _, tc := range []struct{ project, dep, want string }{
		{"MIT", "BSD-3-Clause", Allow},
		{"MIT", "GPL-3.0-only", Deny},
		{"Apache-2.0", "AGPL-3.0-only", Deny},
		{"MIT", "LGPL-2.1-only", Review},
		{"MIT", "MPL-2.0", Review},
		{"MIT", "GPL-2.0-only WITH Classpath-exception-2.0", Review},
		{"GPL-2.0-only", "Apache-2.0", Deny},
		{"GPL-2.0-or-later", "Apache-2.0", Allow},
		{"GPL-3.0-only", "Apache-2.0", Allow},
		{"GPL-3.0-only", "GPL-2.0-only", Deny},
		{"GPL-2.0-only", "GPL-3.0-only", Deny},
		{"GPL-3.0-only", "GPL-2.0-or-later", Allow},
		{"GPL-2.0-or-later", "GPL-3.0-only", Review},
		{"GPL-3.0-only", "AGPL-3.0-only", Review},
		{"AGPL-3.0-only", "GPL-3.0-only", Allow},
		{"GPL-3.0-only", "EPL-1.0", Deny},
		{"GPL-3.0-only", "EPL-2.0", Review},
		{"GPL-3.0-only", "LGPL-2.1-or-later", Allow},
		{"GPL-2.0-only", "LGPL-3.0-only", Deny},
		{"MIT", "CC-BY-NC-4.0", Deny},
		{"MIT", "LicenseRef-scrs-proprietary", Review},
		{"MIT", "NOASSERTION", Allow},
		// Dependency OR: the most lenient option; AND: the strictest.
		{"MIT", "GPL-3.0-only OR MIT", Allow},
		{"MIT", "GPL-3.0-only AND MIT", Deny},
		// Project OR: options disagree, so review.
		{"MIT OR GPL-3.0-only", "GPL-3.0-only", Review},
		{"MIT OR Apache-2.0", "GPL-3.0-only", Deny},
	} {
		got := Outbound(c, tc.project, tc.dep)
		if got.Effect != tc.want || got.Reason == "" && tc.want != Allow {
			t.Errorf("%s <- %s: %s (%s), want %s", tc.project, tc.dep, got.Effect, got.Reason, tc.want)
		}
	}
	for project, want := range map[string]bool{"MIT": true, "GPL-3.0-only": true, "MIT OR Apache-2.0": true, "NOASSERTION": false, "LicenseRef-scrs-proprietary": false, "not an expression ((": false, "BUSL-1.1": false} {
		if OutboundApplies(c, project) != want {
			t.Errorf("applies %q", project)
		}
	}
}
