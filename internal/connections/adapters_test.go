package connections

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScopeAllSelectedAndExclusion(t *testing.T) {
	s := Scope{Include: []string{"org/*"}, Exclude: []string{"org/private-*"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for locator, want := range map[string]bool{"org/api": true, "org/private-payroll": false, "other/api": false} {
		if got := s.Matches(locator); got != want {
			t.Errorf("scope match %q = %v, want %v", locator, got, want)
		}
	}
	if (Scope{}).Matches("org/api") {
		t.Fatal("empty scope must fail closed")
	}
}

func TestGitHubScopeMatchesCaseInsensitiveRepositoryNames(t *testing.T) {
	s := Scope{Include: []string{"CreditChek/API"}}
	if !s.matchesResource(Resource{Type: "github_repo", Locator: "creditchek/api"}) {
		t.Fatal("GitHub repository naming must be case insensitive")
	}
	if s.matchesResource(Resource{Type: "container_image", Locator: "creditchek/api"}) {
		t.Fatal("registry matching must preserve its own case semantics")
	}
}

func TestGitHubAdapterListsOnlyConfiguredOrganization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42/access_tokens":
			if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
				t.Errorf("bad GitHub token request")
			}
			_, _ = w.Write([]byte(`{"token":"installation-token"}`))
		case "/installation/repositories":
			if r.Header.Get("Authorization") != "Bearer installation-token" {
				t.Errorf("installation token not used")
			}
			_, _ = w.Write([]byte(`{"repositories":[{"full_name":"org/api","private":true},{"full_name":"other/api","private":false}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	config, _ := json.Marshal(map[string]any{"organization": "org", "app_id": "123", "installation_id": 42})
	secret, _ := json.Marshal(map[string]string{"private_key_pem": private})
	a := NewNativeAdapters()
	a.GitHubAPI = server.URL
	resources, err := a.List(context.Background(), Connection{Provider: "github", Config: config}, secret)
	if err != nil || len(resources) != 1 || resources[0].Locator != "org/api" {
		t.Fatalf("GitHub resources: %#v, %v", resources, err)
	}
}

func TestGitHubUserTokenModesListAuthorizedOrganizationRepos(t *testing.T) {
	for _, authType := range []string{"fine_grained_pat", "oauth_app_token"} {
		t.Run(authType, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/user/repos" || r.Header.Get("Authorization") != "Bearer issued-token" || r.URL.Query().Get("visibility") != "all" || r.Header.Get("X-GitHub-Api-Version") == "" {
					t.Errorf("unexpected GitHub request: %s %s", r.Method, r.URL.String())
				}
				_, _ = w.Write([]byte(`[{"full_name":"org/private","private":true,"owner":{"login":"org"}},{"full_name":"personal/repo","owner":{"login":"personal"}},{"full_name":"org/forged","owner":{"login":"other"}}]`))
			}))
			defer server.Close()
			config, _ := json.Marshal(map[string]string{"organization": "org", "auth_type": authType})
			a := NewNativeAdapters()
			a.GitHubAPI = server.URL
			resources, err := a.List(context.Background(), Connection{Provider: "github", Config: config}, json.RawMessage(`{"token":"issued-token"}`))
			if err != nil || len(resources) != 1 || resources[0].Locator != "org/private" {
				t.Fatalf("GitHub resources: %#v, %v", resources, err)
			}
		})
	}
}

func TestGitHubUserTokenDoesNotTreatDeniedAccessAsEmptyInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"policy denied secret-token"}`))
	}))
	defer server.Close()
	a := NewNativeAdapters()
	a.GitHubAPI = server.URL
	_, err := a.List(context.Background(), Connection{Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"oauth_app_token"}`)}, json.RawMessage(`{"token":"secret-token"}`))
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("denied access error: %v", err)
	}
}

func TestDockerHubAdapterExchangesTokenAndListsNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/auth/token":
			_, _ = w.Write([]byte(`{"access_token":"hub-token"}`))
		case "/v2/namespaces/org/repositories":
			if r.Header.Get("Authorization") != "Bearer hub-token" {
				t.Errorf("Docker Hub bearer token not used")
			}
			_, _ = w.Write([]byte(`{"results":[{"namespace":"org","name":"api","is_private":true}],"next":null}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	config, _ := json.Marshal(map[string]string{"namespace": "org", "identifier": "org"})
	secret, _ := json.Marshal(map[string]string{"token": "test-oat"})
	a := NewNativeAdapters()
	a.DockerAPI = server.URL
	resources, err := a.List(context.Background(), Connection{Provider: "dockerhub", Config: config}, secret)
	if err != nil || len(resources) != 1 || resources[0].Locator != "docker.io/org/api" {
		t.Fatalf("Docker Hub resources: %#v, %v", resources, err)
	}
}

func TestGARRejectsUntrustedCredentialURL(t *testing.T) {
	config := json.RawMessage(`{"project":"p","location":"us-east1"}`)
	secret := json.RawMessage(`{"service_account_json":{"type":"service_account","token_uri":"http://127.0.0.1/token"}}`)
	_, err := NewNativeAdapters().List(context.Background(), Connection{Provider: "gar", Config: config}, secret)
	if err == nil || !strings.Contains(err.Error(), "official token URI") {
		t.Fatalf("unsafe GAR credential accepted: %v", err)
	}
}
