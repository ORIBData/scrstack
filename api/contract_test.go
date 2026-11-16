package api

import (
	"regexp"
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
		if !strings.HasPrefix(path, "/system/") && !strings.HasPrefix(path, "/docs") && !strings.HasPrefix(path, "/connections") && !strings.HasPrefix(path, "/assets") && !strings.HasPrefix(path, "/tokens") && !strings.HasPrefix(path, "/assessments") && !strings.HasPrefix(path, "/register") && !strings.HasPrefix(path, "/remediation") && !strings.HasPrefix(path, "/feeds/") && !strings.HasPrefix(path, "/intel/") && !strings.HasPrefix(path, "/webhooks/") && !strings.HasPrefix(path, "/settings/") && !strings.HasPrefix(path, "/ingest/") && !strings.HasPrefix(path, "/owners") && !strings.HasPrefix(path, "/maintenance/") && !strings.HasPrefix(path, "/events/") && !strings.HasPrefix(path, "/qa/") && !strings.HasPrefix(path, "/llm/") && !strings.HasPrefix(path, "/schemas/") && !strings.HasPrefix(path, "/policies/") && !strings.HasPrefix(path, "/licenses/") && !strings.HasPrefix(path, "/reports") && !strings.HasPrefix(path, "/frameworks/") && !strings.HasPrefix(path, "/sboms/") && !strings.HasPrefix(path, "/sast/") && !strings.HasPrefix(path, "/reachability/") && !strings.HasPrefix(path, "/integrations/") && path != "/events" && path != "/audit" && path != "/webhooks" {
			t.Errorf("path %q does not use a module", path)
		}
	}
}

// Every operation states how it is authenticated in its `security`
// requirement, and the scope sentence in its description agrees with it, so a
// developer reading either gets the same answer. The router itself is checked
// against these scopes by TestPostgresContractScopesMatchRouter.
func TestOpenAPIOperationsDeclareScopes(t *testing.T) {
	var contract struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPI, &contract); err != nil {
		t.Fatal(err)
	}
	valid := map[string]bool{"read": true, "write": true, "trigger": true, "ingest:relay": true, "admin": true}
	sentence := regexp.MustCompile("[Ss]copes? ((?:`[^`]+`(?:,? (?:or |and )?)?)+)")
	operations := 0
	for path, item := range contract.Paths {
		for method, raw := range item {
			op, ok := raw.(map[string]any)
			if !ok || !strings.Contains(" get post put patch delete ", " "+method+" ") {
				continue
			}
			operations++
			name := strings.ToUpper(method) + " " + path
			requirements, declared := op["security"].([]any)
			if !declared {
				t.Errorf("%s has no security requirement (use [] for public routes)", name)
				continue
			}
			listed, anonymous := map[string]bool{}, false
			for _, r := range requirements {
				entry, _ := r.(map[string]any)
				anonymous = anonymous || len(entry) == 0
				for _, scopes := range entry {
					for _, s := range scopes.([]any) {
						if !valid[s.(string)] {
							t.Errorf("%s lists unknown scope %v", name, s)
						}
						listed[s.(string)] = true
					}
				}
			}
			if len(requirements) > 0 && !anonymous && len(listed) == 0 {
				t.Errorf("%s needs a token but lists no scope", name)
			}
			description, _ := op["description"].(string)
			if match := sentence.FindStringSubmatch(description); match != nil && len(requirements) > 0 {
				stated := map[string]bool{}
				for _, token := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(match[1], -1) {
					if valid[token[1]] {
						stated[token[1]] = true
					}
				}
				if len(stated) > 0 && len(stated) != len(listed) {
					t.Errorf("%s: description says %v but security lists %v", name, stated, listed)
				}
				for s := range stated {
					if !listed[s] {
						t.Errorf("%s: description names scope %s missing from security", name, s)
					}
				}
			}
		}
	}
	if operations < 150 {
		t.Fatalf("only %d operations parsed", operations)
	}
}
