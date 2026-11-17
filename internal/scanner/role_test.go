package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The remediation sandbox (REM-002) is the scanner image in a role that
// answers only /remediate (and /healthz) with its own token; the scan role
// no longer answers /remediate at all.
func TestScannerRolesNarrowWhatIsServed(t *testing.T) {
	token := strings.Repeat("r", 40)
	call := func(role, method, path, auth string) int {
		h := (Engine{Role: role}).Handler(token)
		r := httptest.NewRequest(method, path, strings.NewReader("archive"))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for role, want := range map[string]map[string]int{
		// path -> status for an unauthenticated POST: 401 means the route exists, 404 that it does not.
		"":              {"/scan": 401, "/remediate": 401, "/scan-image": 401},
		RoleAll:         {"/scan": 401, "/remediate": 401, "/scan-image": 401},
		RoleScan:        {"/scan": 401, "/remediate": 404, "/scan-image": 401},
		RoleRemediation: {"/scan": 404, "/remediate": 401, "/scan-image": 404, "/feeds": 404},
	} {
		for path, status := range want {
			method := http.MethodPost
			if path == "/feeds" {
				method = http.MethodGet
			}
			if got := call(role, method, path, ""); got != status {
				t.Errorf("role %q %s %s: %d, want %d", role, method, path, got, status)
			}
		}
	}
	// A wrong token never reaches the work, even on the route the role serves.
	if got := call(RoleRemediation, http.MethodPost, "/remediate", "wrong"); got != 401 {
		t.Errorf("wrong token on /remediate: %d", got)
	}
	// The health route answers in every role (a missing feed is a 503, not a 404).
	for _, role := range []string{"", RoleScan, RoleRemediation} {
		if got := call(role, http.MethodGet, "/healthz", ""); got == 404 {
			t.Errorf("role %q does not answer /healthz", role)
		}
	}
	for role, ok := range map[string]bool{"": true, "all": true, "scan": true, "remediation": true, "Remediation": false, "x": false} {
		if ValidRole(role) != ok {
			t.Errorf("ValidRole(%q) != %v", role, ok)
		}
	}
}
