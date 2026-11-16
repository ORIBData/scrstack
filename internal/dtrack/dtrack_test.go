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
		case r.URL.Path == "/api/v1/team/self":
			// Like the real server: 401 for an unknown key, the team's
			// permissions for a known one.
			switch r.Header.Get("X-Api-Key") {
			case "odt_key_0123456789":
				_, _ = w.Write([]byte(`{"name":"scrs","permissions":[{"name":"BOM_UPLOAD"},{"name":"PROJECT_CREATION_UPLOAD"},{"name":"VIEW_PORTFOLIO"}]}`))
			case "odt_key_upload_only":
				_, _ = w.Write([]byte(`{"name":"scrs","permissions":[{"name":"BOM_UPLOAD"}]}`))
			case "odt_key_no_team":
				w.WriteHeader(404)
			default:
				w.WriteHeader(401)
			}
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
	if r, err := c.Check(ctx); err != nil || r.Version != "4.13.2" || len(r.Permissions) != 3 || len(r.Missing) != 0 {
		t.Fatal(r, err)
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
	if _, err := bad.Check(ctx); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not valid") {
		t.Fatal("bad key must be rejected", err)
	}
	// A valid key whose team lacks a permission fails the check and names it;
	// before, any valid key passed because the probe only authenticated.
	limited := Client{BaseURL: server.URL, APIKey: "odt_key_upload_only", HTTP: c.HTTP}
	r, err := limited.Check(ctx)
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "PROJECT_CREATION_UPLOAD") || len(r.Missing) != 1 || r.Missing[0] != "PROJECT_CREATION_UPLOAD" || r.Version != "4.13.2" {
		t.Fatal("missing permission", r, err)
	}
	orphan := Client{BaseURL: server.URL, APIKey: "odt_key_no_team", HTTP: c.HTTP}
	if _, err := orphan.Check(ctx); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "team API key") {
		t.Fatal("key without a team", err)
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

func TestProcessingAndProject(t *testing.T) {
	token := "5e2f0b4a-7f5e-4b55-9d0e-1c1f3a3c1b2a"
	processing := true
	imported := int64(1763290000000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "odt_key_0123456789" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/event/token/"+token:
			_, _ = w.Write([]byte(`{"processing":` + map[bool]string{true: "true", false: "false"}[processing] + `}`))
		case r.URL.Path == "/api/v1/project/lookup":
			q := r.URL.Query()
			switch q.Get("name") {
			case "org/app":
				if q.Get("version") != "feature/x y" {
					t.Errorf("lookup query %v", q)
				}
				_, _ = w.Write([]byte(`{"uuid":"11111111-1111-1111-1111-111111111111","lastBomImport":` + "1763290000000" + `}`))
			case "org/never":
				_, _ = w.Write([]byte(`{"uuid":"22222222-2222-2222-2222-222222222222"}`))
			case "org/denied":
				w.WriteHeader(403)
			default:
				w.WriteHeader(404)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := Client{BaseURL: server.URL, APIKey: "odt_key_0123456789", HTTP: NewHTTPClient(map[string]bool{"127.0.0.1": true})}
	ctx := context.Background()

	if p, err := c.Processing(ctx, token); err != nil || !p {
		t.Fatal("still processing", p, err)
	}
	processing = false
	if p, err := c.Processing(ctx, token); err != nil || p {
		t.Fatal("finished", p, err)
	}
	if _, err := c.Processing(ctx, "../../etc"); !errors.Is(err, ErrRejected) {
		t.Fatal("a non-UUID token must never reach the URL", err)
	}
	bad := Client{BaseURL: server.URL, APIKey: "wrong-key-0123456789", HTTP: c.HTTP}
	if _, err := bad.Processing(ctx, token); !errors.Is(err, ErrRejected) {
		t.Fatal("bad key", err)
	}

	p, err := c.Project(ctx, "org/app", "feature/x y")
	if err != nil || p.UUID == "" || p.LastBOMImport.UnixMilli() != imported {
		t.Fatal(p, err)
	}
	if p, err := c.Project(ctx, "org/never", "1"); err != nil || !p.LastBOMImport.IsZero() {
		t.Fatal("a project never imported has no import time", p, err)
	}
	if _, err := c.Project(ctx, "org/denied", "1"); !errors.Is(err, ErrForbidden) || !errors.Is(err, ErrRejected) {
		t.Fatal("403", err)
	}
	if _, err := c.Project(ctx, "org/missing", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("404", err)
	}
}
