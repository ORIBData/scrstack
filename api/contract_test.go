package api

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestOpenAPIUsesSCRSModulePaths(t *testing.T) {
	var contract struct {
		OpenAPI string `yaml:"openapi"`
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPI, &contract); err != nil {
		t.Fatalf("invalid OpenAPI YAML: %v", err)
	}
	if contract.OpenAPI != "3.1.0" || len(contract.Servers) != 1 || contract.Servers[0].URL != "/scrs/v1" {
		t.Fatalf("unexpected OpenAPI version or server: %#v", contract)
	}
	for path := range contract.Paths {
		if !strings.HasPrefix(path, "/system/") && !strings.HasPrefix(path, "/docs") && !strings.HasPrefix(path, "/connections") && !strings.HasPrefix(path, "/assets") && !strings.HasPrefix(path, "/tokens") && !strings.HasPrefix(path, "/assessments") && !strings.HasPrefix(path, "/register") && !strings.HasPrefix(path, "/remediation") && !strings.HasPrefix(path, "/feeds/") && !strings.HasPrefix(path, "/webhooks/") && !strings.HasPrefix(path, "/settings/") && !strings.HasPrefix(path, "/ingest/") && !strings.HasPrefix(path, "/owners") && !strings.HasPrefix(path, "/maintenance/") && !strings.HasPrefix(path, "/events/") && path != "/webhooks" {
			t.Errorf("path %q does not use a module", path)
		}
	}
}
