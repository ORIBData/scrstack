package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPTrustBoundary(t *testing.T) {
	s := Security{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32")}}
	for _, c := range []struct{ peer, header, want string }{
		{"192.0.2.1", "198.51.100.1", "192.0.2.1"},
		{"10.1.2.3", "198.51.100.1, 192.0.2.1", "192.0.2.1"},
		{"10.1.2.3", "192.0.2.1", "192.0.2.1"},
		{"10.1.2.3", "invalid", "invalid IP"},
	} {
		if got := s.clientIP(netip.MustParseAddr(c.peer), c.header).String(); got != c.want {
			t.Errorf("peer %s: got %s want %s", c.peer, got, c.want)
		}
	}
}
func TestCORSRejectsUnlistedPreflight(t *testing.T) {
	s := Security{Origins: []string{"https://allowed.example"}}
	h := s.cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, origin := range []string{"https://allowed.example", "https://evil.example"} {
		r := httptest.NewRequest("OPTIONS", BasePath+"/tokens", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 403
		if origin == "https://allowed.example" {
			want = 204
		}
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
	}
}
