package dtrack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestClient(t *testing.T) {
	var got map[string]any
	status := 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/version":
			if r.Header.Get("X-Api-Key") != "" {
				t.Error("key sent to the unauthenticated version endpoint")
			}
			_, _ = w.Write([]byte(`{"version":"4.13.2"}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/event/token/"):
			if r.Header.Get("X-Api-Key") != "odt_key_0123456789" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"processing":false}`))
		case r.URL.Path == "/api/v1/bom" && r.Method == http.MethodPut:
			if r.Header.Get("X-Api-Key") != "odt_key_0123456789" {
				w.WriteHeader(403)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"token":"5e2f0b4a-7f5e-4b55-9d0e-1c1f3a3c1b2a"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	private := map[string]bool{"127.0.0.1": true}
	c := Client{BaseURL: server.URL, APIKey: "odt_key_0123456789", HTTP: NewHTTPClient(private)}
	ctx := context.Background()
	if v, err := c.Check(ctx); err != nil || v != "4.13.2" {
		t.Fatal(v, err)
	}
	parent := uuid.New()
	token, err := c.Upload(ctx, Upload{ProjectName: "org/app", ProjectVersion: "main", Parent: &parent, BOM: []byte(`{"bomFormat":"CycloneDX"}`)})
	if err != nil || token == "" {
		t.Fatal(token, err)
	}
	bom, _ := base64.StdEncoding.DecodeString(got["bom"].(string))
	if got["projectName"] != "org/app" || got["projectVersion"] != "main" || got["autoCreate"] != true || got["parentUUID"] != parent.String() || string(bom) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("upload body %+v", got)
	}
	status = 503
	if _, err := c.Upload(ctx, Upload{ProjectName: "a", ProjectVersion: "b", BOM: []byte("{}")}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("5xx must be transient", err)
	}
	bad := Client{BaseURL: server.URL, APIKey: "wrong-key-0123456789", HTTP: c.HTTP}
	if _, err := bad.Check(ctx); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "BOM_UPLOAD") {
		t.Fatal("bad key must be rejected", err)
	}
	if _, err := c.Upload(ctx, Upload{ProjectName: "a", ProjectVersion: "b"}); !errors.Is(err, ErrRejected) {
		t.Fatal("empty BOM", err)
	}
	// Without the private-host allowance the guard refuses loopback.
	guarded := Client{BaseURL: server.URL, HTTP: NewHTTPClient(nil)}
	if _, err := guarded.Check(ctx); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "SCRS_DTRACK_PRIVATE_HOSTS") {
		t.Fatal("loopback reached", err)
	}
}

func TestValidURL(t *testing.T) {
	private := map[string]bool{"dtrack.internal": true}
	for raw, want := range map[string]bool{
		"https://dtrack.example.com":         true,
		"https://dtrack.example.com/sub":     true,
		"http://dtrack.internal:8081":        true,
		"http://dtrack.example.com":          false,
		"https://user:pw@dtrack.example.com": false,
		"https://dtrack.example.com/?a=1":    false,
		"ftp://dtrack.example.com":           false,
		"":                                   false,
	} {
		if ValidURL(raw, private) != want {
			t.Errorf("%q", raw)
		}
	}
}
