package connections

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestNewProviderValidation(t *testing.T) {
	for _, tc := range []struct {
		provider, config, credential string
		ok                           bool
	}{
		{"gitlab", `{"group":"team/platform"}`, `{"token":"glpat"}`, true},
		{"gitlab", `{"group":"team","base_url":"https://git.example.com/gitlab"}`, `{"token":"glpat"}`, true},
		{"gitlab", `{"group":"team","base_url":"http://git.example.com"}`, `{"token":"glpat"}`, false},
		{"gitlab", `{"group":"team","base_url":"https://user:pw@git.example.com"}`, `{"token":"glpat"}`, false},
		{"gitlab", `{"group":"../x"}`, `{"token":"glpat"}`, false},
		{"gitlab", `{"group":"team"}`, `{"token":"glpat","extra":1}`, false},
		{"harbor", `{"url":"https://harbor.example.com","project":"apps","username":"robot$scrs"}`, `{"token":"x"}`, true},
		{"harbor", `{"url":"https://harbor.example.com","project":"apps"}`, `{"token":"x"}`, false},
		{"oci", `{"registry":"ghcr.io","username":"bot","repositories":["acme/api"]}`, `{"token":"x"}`, true},
		{"oci", `{"registry":"registry.internal:5000"}`, `{}`, true},
		{"oci", `{"registry":"ghcr.io","username":"bot"}`, `{}`, false},
		{"oci", `{"registry":"ghcr.io","repositories":["Acme/API"]}`, `{}`, false},
		{"oci", `{"registry":"https://ghcr.io"}`, `{}`, false},
	} {
		err := ValidateInput(Connection{Name: "c", Provider: tc.provider, Config: json.RawMessage(tc.config)}, json.RawMessage(tc.credential))
		if (err == nil) != tc.ok {
			t.Errorf("%s %s %s: err=%v", tc.provider, tc.config, tc.credential, err)
		}
	}
}

// GitLab adapter against a mock API: subgroup discovery, HEAD resolution
// through the default branch, commit pinning and archive download.
func TestGitLabListAndSnapshot(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer glpat" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/api/v4/groups/team/projects" && r.URL.Query().Get("include_subgroups") == "true":
			_, _ = w.Write([]byte(`[{"path_with_namespace":"team/platform/api","default_branch":"main","visibility":"private"},{"path_with_namespace":"other/leak","default_branch":"main"}]`))
		case r.URL.EscapedPath() == "/api/v4/projects/team%2Fplatform%2Fapi":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case r.URL.EscapedPath() == "/api/v4/projects/team%2Fplatform%2Fapi/repository/commits/main":
			_, _ = w.Write([]byte(`{"id":"` + sha + `"}`))
		case r.URL.EscapedPath() == "/api/v4/projects/team%2Fplatform%2Fapi/repository/archive.tar.gz" && r.URL.Query().Get("sha") == sha:
			_, _ = w.Write([]byte("archive-bytes"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	a := NativeAdapters{Client: server.Client()}
	c := Connection{Provider: "gitlab", Enabled: true, Config: json.RawMessage(`{"group":"team","base_url":"` + server.URL + `"}`), Scope: Scope{Include: []string{"team/**"}}}
	secret := json.RawMessage(`{"token":"glpat"}`)
	resources, err := a.List(context.Background(), c, secret)
	if err != nil || len(resources) != 1 || resources[0].Type != "gitlab_repo" || resources[0].Locator != "team/platform/api" {
		t.Fatal("GitLab discovery", resources, err)
	}
	data, commit, moved, err := a.Snapshot(context.Background(), c, secret, "team/platform/api", "HEAD", "")
	if err != nil || string(data) != "archive-bytes" || commit != sha || moved {
		t.Fatal("GitLab snapshot", string(data), commit, moved, err)
	}
	if _, _, _, err := a.Snapshot(context.Background(), c, secret, "team/platform/api", "main", strings.Repeat("cd", 20)); err == nil {
		t.Fatal("commit mismatch accepted")
	}
	if _, _, _, err := a.Snapshot(context.Background(), c, secret, "other/leak", "main", ""); err == nil {
		t.Fatal("repository outside the group fetched")
	}
}

func TestHarborList(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "robot$scrs" || pass != "secret" || r.URL.Path != "/api/v2.0/projects/apps/repositories" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`[{"name":"apps/web"},{"name":"apps/worker"},{"name":"other/x"}]`))
	}))
	defer server.Close()
	a := NativeAdapters{Client: server.Client()}
	c := Connection{Provider: "harbor", Config: json.RawMessage(`{"url":"` + server.URL + `","project":"apps","username":"robot$scrs"}`)}
	resources, err := a.List(context.Background(), c, json.RawMessage(`{"token":"secret"}`))
	host := strings.TrimPrefix(server.URL, "https://")
	if err != nil || len(resources) != 2 || resources[0].Locator != host+"/apps/web" {
		t.Fatal("Harbor discovery", resources, err)
	}
}

// Generic OCI: catalog discovery and a digest-pinned pull from a real
// (in-memory) distribution registry.
func TestOCICatalogAndPull(t *testing.T) {
	server := httptest.NewServer(registry.New())
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	image, err := random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"acme/api", "other/tool"} {
		ref, _ := name.ParseReference(host + "/" + repo + ":1.0")
		if err := remote.Write(ref, image); err != nil {
			t.Fatal(err)
		}
	}
	a := NativeAdapters{Client: server.Client()}
	c := Connection{Provider: "oci", Enabled: true, Config: json.RawMessage(`{"registry":"` + host + `","namespace":"acme"}`), Scope: Scope{Include: []string{host + "/acme/*"}}}
	resources, err := a.List(context.Background(), c, json.RawMessage(`{}`))
	if err != nil || len(resources) != 1 || resources[0].Locator != host+"/acme/api" {
		t.Fatal("OCI catalog discovery", resources, err)
	}
	digest, _ := image.Digest()
	var archive bytes.Buffer
	got, err := a.ImageArchive(context.Background(), c, json.RawMessage(`{}`), host+"/acme/api", "", digest.String(), "linux/amd64", 1<<20, &archive)
	if err != nil || got != digest.String() || archive.Len() == 0 {
		t.Fatal("OCI pull", got, err)
	}
	if _, err := a.ImageArchive(context.Background(), c, json.RawMessage(`{}`), "docker.io/acme/api", "1.0", "", "linux/amd64", 1<<20, &bytes.Buffer{}); err == nil {
		t.Fatal("image from another registry pulled with this connection")
	}
}
