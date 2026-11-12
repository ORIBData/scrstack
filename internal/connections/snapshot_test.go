package connections

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type snapshotTransport func(*http.Request) (*http.Response, error)

func (f snapshotTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSnapshotRedirectBoundaryAndImmutableResolution(t *testing.T) {
	sha := strings.Repeat("a", 40)
	c := Connection{Provider: "github", Enabled: true, Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: Scope{Include: []string{"org/*"}}}
	for _, location := range []string{"https://codeload.github.com/org/repo/legacy.tar.gz/" + sha, "https://evil.example/archive", "http://codeload.github.com/archive", "https://codeload.github.com.evil.example/archive"} {
		t.Run(location, func(t *testing.T) {
			downloaded := false
			a := NewNativeAdapters()
			a.Client = &http.Client{Transport: snapshotTransport(func(r *http.Request) (*http.Response, error) {
				response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"sha":"` + sha + `"}`)), Request: r}
				if r.URL.Host == "api.github.com" {
					if r.Header.Get("Authorization") != "Bearer synthetic" {
						t.Fatal("missing API token")
					}
					if strings.Contains(r.URL.Path, "/tarball/") {
						response.StatusCode = 302
						response.Header.Set("Location", location)
					}
				} else {
					downloaded = true
					if r.URL.Host != "codeload.github.com" || r.Header.Get("Authorization") != "" {
						t.Fatal("credential/origin boundary violated")
					}
					response.Body = io.NopCloser(strings.NewReader("archive"))
				}
				return response, nil
			})}
			data, resolved, _, err := a.GitHubSnapshot(context.Background(), c, json.RawMessage(`{"token":"synthetic"}`), "org/repo", "main", sha)
			if strings.HasPrefix(location, "https://codeload.github.com/") {
				if err != nil || resolved != sha || string(data) != "archive" || !downloaded {
					t.Fatal("snapshot failed", err)
				}
			} else if err == nil || downloaded {
				t.Fatal("unsafe redirect accepted")
			}
		})
	}
}
