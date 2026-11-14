package httpapi

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/api"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"
)

// adminTokens authenticates every bearer token as admin, so routing is
// exercised without a database. With no Redis, protected routes stop at the
// rate limiter (503) after the router matched them.
type adminTokens struct{}

func (adminTokens) Authenticate(context.Context, string, netip.Addr) (connections.Token, error) {
	return connections.Token{ID: uuid.New(), Name: "contract", Scopes: []string{"admin"}}, nil
}
func (adminTokens) CreateToken(context.Context, connections.Token, uuid.UUID) (connections.Token, string, error) {
	return connections.Token{}, "", nil
}
func (adminTokens) Tokens(context.Context, uuid.UUID, int) ([]connections.Token, error) {
	return nil, nil
}
func (adminTokens) RevokeToken(context.Context, uuid.UUID, uuid.UUID) error { return nil }

type operation struct {
	OperationID string         `yaml:"operationId"`
	Summary     string         `yaml:"summary"`
	Description string         `yaml:"description"`
	Tags        []string       `yaml:"tags"`
	Responses   map[string]any `yaml:"responses"`
}

func loadContract(t *testing.T) (map[string]map[string]operation, map[string]bool) {
	t.Helper()
	var doc struct {
		Tags []struct {
			Name string `yaml:"name"`
		} `yaml:"tags"`
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, tag := range doc.Tags {
		tags[tag.Name] = true
	}
	ops := map[string]map[string]operation{}
	for path, item := range doc.Paths {
		ops[path] = map[string]operation{}
		for method, node := range item {
			if method == "parameters" {
				continue
			}
			var op operation
			if err := node.Decode(&op); err != nil {
				t.Fatal(path, method, err)
			}
			ops[path][method] = op
		}
	}
	return ops, tags
}

// Every documented operation is complete enough for client generation and
// a frontend reader: unique operationId, one known tag, a short summary and
// a description.
func TestContractDocumentsEveryOperation(t *testing.T) {
	ops, tags := loadContract(t)
	ids := map[string]bool{}
	count := 0
	for path, methods := range ops {
		for method, op := range methods {
			count++
			where := strings.ToUpper(method) + " " + path
			switch {
			case op.OperationID == "" || ids[op.OperationID]:
				t.Errorf("%s: missing or duplicate operationId %q", where, op.OperationID)
			case len(op.Tags) != 1 || !tags[op.Tags[0]]:
				t.Errorf("%s: needs exactly one declared tag, got %v", where, op.Tags)
			case op.Summary == "" || len(op.Summary) > 60:
				t.Errorf("%s: summary must be 1-60 characters", where)
			case len(strings.TrimSpace(op.Description)) < 20:
				t.Errorf("%s: description missing", where)
			case len(op.Responses) == 0:
				t.Errorf("%s: no responses", where)
			}
			ids[op.OperationID] = true
		}
	}
	if count < 70 {
		t.Fatalf("only %d operations documented", count)
	}
}

// Every documented operation reaches a handler, and every route registered in
// the router source is documented.
func TestContractMatchesRouter(t *testing.T) {
	ops, _ := loadContract(t)
	handler := HandlerWithSecurity(nil, &connections.Store{}, Security{Store: adminTokens{}, Assessments: &assessments.Store{}, Notify: &notify.Store{}})
	placeholder := regexp.MustCompile(`\{[a-z_]+\}`)
	for path, methods := range ops {
		for method := range methods {
			concrete := placeholder.ReplaceAllStringFunc(path, func(p string) string {
				if p == "{provider}" {
					return "harbor"
				}
				return uuid.NewString()
			})
			r := httptest.NewRequest(strings.ToUpper(method), BasePath+concrete, strings.NewReader("{}"))
			r.Header.Set("Authorization", "Bearer contract-token-contract-token-1234")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			body := w.Body.String()
			if body == "404 page not found\n" || strings.HasPrefix(body, "Method Not Allowed") || (w.Code == 405 && strings.Contains(body, "method not allowed")) {
				t.Errorf("%s %s is documented but not routed (%d %q)", strings.ToUpper(method), path, w.Code, body)
			}
		}
	}
	// Source scan: method-qualified routes in the router must be documented.
	source, err := os.ReadFile("auth.go")
	if err != nil {
		t.Fatal(err)
	}
	route := regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) "\+BasePath\+"([^"]+)"`)
	for _, m := range route.FindAllStringSubmatch(string(source), -1) {
		method, path := strings.ToLower(m[1]), m[2]
		if strings.HasSuffix(path, "/") {
			continue // composed in a loop; covered by the forward check
		}
		if _, ok := ops[path][method]; !ok {
			t.Errorf("router registers %s %s but the contract does not document it", m[1], path)
		}
	}
}
