package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/api"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.yaml.in/yaml/v3"
)

// The scopes published in api/openapi.yaml are what the router enforces:
// for every operation, a token of each scope is refused (403) exactly when the
// contract does not list that scope (admin always passes). Operations that
// take a webhook signature or connection secret instead of a token are skipped.
func TestPostgresContractScopesMatchRouter(t *testing.T) {
	databaseURL, redisURL := os.Getenv("SCRS_TEST_DATABASE_URL"), os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, databaseURL)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.SyncBootstrap(ctx, strings.Repeat("a", 40)); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	events, err := notify.Open(ctx, databaseURL, schema, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	artifacts := memoryArtifacts{}
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Artifacts: artifacts, Notify: events, Live: &notify.Hub{MaxStreams: 10, PerToken: 2}, RelayEnabled: true, Status: NewPlatformStatus(nil, jobs, nil, nil)})

	var contract struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &contract); err != nil {
		t.Fatal(err)
	}
	type operation struct {
		method, path string
		allowed      map[string]bool
		params       map[string]string
	}
	var ops []operation
	for path, item := range contract.Paths {
		params := pathParameters(item["parameters"])
		for method, raw := range item {
			if !strings.Contains(" get post put patch delete ", " "+method+" ") {
				continue
			}
			op, _ := raw.(map[string]any)
			for k, v := range pathParameters(op["parameters"]) {
				params[k] = v
			}
			requirements, declared := op["security"].([]any)
			if !declared {
				requirements, declared = []any{map[string]any{"bearerAuth": []any{}}}, false
				t.Errorf("%s %s has no security requirement", strings.ToUpper(method), path)
			}
			allowed, skip := map[string]bool{}, len(requirements) == 0
			for _, r := range requirements {
				entry, _ := r.(map[string]any)
				if len(entry) == 0 { // anonymous alternative: signature or secret authenticated
					skip = true
				}
				for _, scopes := range entry {
					for _, s := range scopes.([]any) {
						allowed[s.(string)] = true
					}
				}
			}
			if !skip && declared && len(allowed) == 0 {
				t.Errorf("%s %s requires a token but lists no scope", strings.ToUpper(method), path)
			}
			if !skip {
				ops = append(ops, operation{strings.ToUpper(method), path, allowed, params})
			}
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].path+ops[i].method < ops[j].path+ops[j].method })
	if len(ops) < 150 {
		t.Fatalf("only %d token operations found", len(ops))
	}

	// These handlers load the assessment before checking the caller (ownership
	// for trigger tokens, admin for source archives), so an unknown id answers
	// 404 to a token that is refused on a real one.
	afterLookup := map[string]bool{"GET /assessments/{id}/snapshot": true, "DELETE /assessments/{id}": true}
	scopes := []string{"read", "write", "trigger", "ingest:relay", "admin"}
	var tokens map[string]string
	issue := func() {
		tokens = map[string]string{}
		for _, scope := range scopes {
			_, secret, err := store.CreateToken(ctx, connections.Token{Name: "matrix-" + uuid.NewString()[:8], Scopes: []string{scope}}, uuid.Nil)
			if err != nil {
				t.Fatal(err)
			}
			tokens[scope] = secret
		}
	}
	var mismatches []string
	for i, op := range ops {
		if i%20 == 0 { // 120 requests per token per minute: rotate before the limit
			issue()
		}
		target := op.path
		for name, value := range op.params {
			target = strings.ReplaceAll(target, "{"+name+"}", value)
		}
		for strings.Contains(target, "{") {
			start := strings.Index(target, "{")
			end := strings.Index(target[start:], "}") + start
			target = target[:start] + "x" + target[end+1:]
		}
		for _, scope := range scopes {
			permitted := scope == "admin" || op.allowed[scope]
			if permitted && op.method == "GET" && op.path == "/events" {
				continue // a permitted stream would stay open
			}
			r := httptest.NewRequest(op.method, BasePath+target, strings.NewReader("{}"))
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("Authorization", "Bearer "+tokens[scope])
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			late := afterLookup[op.method+" "+op.path]
			if late && permitted {
				continue
			}
			if refused := w.Code == http.StatusForbidden || (late && w.Code == http.StatusNotFound); refused == permitted {
				mismatches = append(mismatches, fmt.Sprintf("%s %s with %s: status %d, contract lists %v", op.method, op.path, scope, w.Code, sortedKeys(op.allowed)))
			}
			if w.Code == http.StatusUnauthorized || w.Code == http.StatusTooManyRequests {
				mismatches = append(mismatches, fmt.Sprintf("%s %s with %s: unexpected %d", op.method, op.path, scope, w.Code))
			}
		}
	}
	for _, m := range mismatches {
		t.Error(m)
	}
}

func pathParameters(raw any) map[string]string {
	out := map[string]string{}
	list, _ := raw.([]any)
	for _, item := range list {
		p, _ := item.(map[string]any)
		if ref, ok := p["$ref"].(string); ok && strings.HasSuffix(ref, "/Id") {
			out["id"] = uuid.NewString()
			continue
		}
		if p["in"] != "path" {
			continue
		}
		name, _ := p["name"].(string)
		schema, _ := p["schema"].(map[string]any)
		if values, ok := schema["enum"].([]any); ok && len(values) > 0 {
			out[name] = fmt.Sprint(values[0])
		} else if schema["format"] == "uuid" {
			out[name] = uuid.NewString()
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
