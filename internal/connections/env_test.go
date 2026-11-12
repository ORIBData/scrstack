package connections

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGitHubFromEnvTokenModesKeepSecretOutOfConfig(t *testing.T) {
	for _, mode := range []string{"fine_grained_pat", "oauth_app_token"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SCRS_GITHUB_ORGANIZATION", "example-org")
			t.Setenv("SCRS_GITHUB_AUTH_TYPE", mode)
			t.Setenv("SCRS_GITHUB_TOKEN", "sensitive-issued-token")
			t.Setenv("SCRS_GITHUB_REPOSITORY_MODE", "selected")
			t.Setenv("SCRS_GITHUB_REPOSITORY_INCLUDE", "example-org/api")
			c, credential, err := githubFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(c.Config), "sensitive-issued-token") || !strings.Contains(string(credential), "sensitive-issued-token") {
				t.Fatal("token must be separate from JSONB config")
			}
			var config map[string]string
			if json.Unmarshal(c.Config, &config) != nil || config["auth_type"] != mode || len(c.Scope.Include) != 1 || c.Scope.Include[0] != "example-org/api" {
				t.Fatalf("bad token mode configuration: %s, %#v", c.Config, c.Scope)
			}
		})
	}
}

func TestGitHubFromEnvRejectsMissingToken(t *testing.T) {
	t.Setenv("SCRS_GITHUB_ORGANIZATION", "example-org")
	t.Setenv("SCRS_GITHUB_AUTH_TYPE", "oauth_app_token")
	t.Setenv("SCRS_GITHUB_TOKEN", "")
	_, _, err := githubFromEnv()
	if err == nil || !strings.Contains(err.Error(), "SCRS_GITHUB_TOKEN") {
		t.Fatalf("missing token accepted: %v", err)
	}
}
