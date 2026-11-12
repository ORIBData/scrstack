package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func TestPostgresManagedSecurityAndLifecycle(t *testing.T) {
	databaseURL := os.Getenv("SCRS_TEST_DATABASE_URL")
	redisURL := os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	store, err := connections.Open(ctx, databaseURL, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := strings.Repeat("x", 40)
	if _, err := store.SyncBootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(opts)
	defer client.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: client})
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	mustStatus := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body)
		}
	}
	mustStatus(request("GET", "/docs", "", ""), 401)
	mustStatus(request("GET", "/docs", admin, ""), 200)
	w := request("POST", "/tokens", admin, `{"name":"reader","scopes":["read"],"ip_allow_list":["192.0.2.0/24"]}`)
	mustStatus(w, 201)
	var issued struct {
		Token    string            `json:"token"`
		Metadata connections.Token `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	mustStatus(request("GET", "/assets", issued.Token, ""), 200)
	if _, err := store.Authenticate(ctx, issued.Token, netip.MustParseAddr("198.51.100.1")); !errors.Is(err, connections.ErrUnauthorized) {
		t.Fatal("IP allow-list bypass", err)
	}
	mustStatus(request("GET", "/assets", issued.Token+"tampered", ""), 401)
	past := time.Now().Add(-time.Minute)
	if _, _, err := store.CreateToken(ctx, connections.Token{Name: "expired", Scopes: []string{"read"}, ExpiresAt: &past}, issued.Metadata.ID); !errors.Is(err, connections.ErrTokenInput) {
		t.Fatal("past expiry accepted", err)
	}
	expiryToken, expirySecret, err := store.CreateToken(ctx, connections.Token{Name: "expiry-check", Scopes: []string{"read"}}, issued.Metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".api_tokens SET expires_at=now()-interval '1 second' WHERE id=$1", expiryToken.ID); err != nil {
		t.Fatal(err)
	}
	mustStatus(request("GET", "/assets", expirySecret, ""), 401)

	mustStatus(request("GET", "/connections", issued.Token, ""), 403)
	mustStatus(request("POST", "/tokens", issued.Token, `{"name":"evil","scopes":["admin"]}`), 403)
	w = request("GET", "/tokens", admin, "")
	mustStatus(w, 200)
	if strings.Contains(w.Body.String(), issued.Token) {
		t.Fatal("list leaked token")
	}
	mustStatus(request("DELETE", "/tokens/"+issued.Metadata.ID.String(), admin, ""), 204)
	mustStatus(request("GET", "/assets", issued.Token, ""), 401)
	// Rate-limit storage failure must not admit authenticated requests.
	unavailable := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond, MaxRetries: -1})
	defer unavailable.Close()
	offlineHandler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: unavailable})
	offlineRequest := httptest.NewRequest("GET", BasePath+"/assets", nil)
	offlineRequest.Header.Set("Authorization", "Bearer "+admin)
	offlineResponse := httptest.NewRecorder()
	offlineHandler.ServeHTTP(offlineResponse, offlineRequest)
	mustStatus(offlineResponse, 503)
	// Explicit bootstrap rotation invalidates the old token without a process-local cache.
	replacement := strings.Repeat("y", 40)
	if _, err := store.SyncBootstrap(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	mustStatus(request("GET", "/assets", admin, ""), 401)
	admin = replacement
	w = request("POST", "/connections", admin, `{"provider":"github","name":"test","config":{"organization":"org","auth_type":"fine_grained_pat"},"scope":{"include":["org/*"]},"credential":{"token":"synthetic"}}`)
	mustStatus(w, 201)
	var c connections.Connection
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Discover(ctx, "test", fixtureInventory{}); err != nil {
		t.Fatal(err)
	}
	mustStatus(request("PATCH", "/connections/"+c.ID.String(), admin, `{"enabled":false}`), 200)
	stored, _, err := store.Get(ctx, "test")
	if err != nil || stored.Enabled {
		t.Fatal("disable did not persist", err)
	}
	mustStatus(request("POST", "/connections/"+c.ID.String()+":rotate-credential", admin, `{"credential":{"token":"rotated"}}`), 200)
	_, secret, err := store.Get(ctx, "test")
	if err != nil || !strings.Contains(string(secret), "rotated") {
		t.Fatal("rotation did not persist", err)
	}
	mustStatus(request("PATCH", "/connections/"+c.ID.String(), admin, `{"config":{"token":"leak"}}`), 400)
	mustStatus(request("DELETE", "/connections/"+c.ID.String(), admin, ""), 200)
	// Restore an actual PostgreSQL custom-format backup into a separate disposable
	// database, then verify encrypted credentials, revocation and retained inventory.
	if container := os.Getenv("SCRS_TEST_PG_CONTAINER"); container != "" {
		docker := os.Getenv("DOCKER")
		if docker == "" {
			docker = "docker"
		}
		dump, err := exec.CommandContext(ctx, docker, "exec", container, "pg_dump", "-U", "postgres", "-Fc", "--schema", schema, "postgres").Output()
		if err != nil {
			t.Fatal("backup failed", err)
		}
		restoreDB := "restore_" + uuid.NewString()[:8]
		if out, err := exec.CommandContext(ctx, docker, "exec", container, "createdb", "-U", "postgres", restoreDB).CombinedOutput(); err != nil {
			t.Fatalf("restore database: %s %v", out, err)
		}
		defer func() { _, _ = pool.Exec(context.Background(), "DROP DATABASE "+restoreDB) }()
		restore := exec.CommandContext(ctx, docker, "exec", "-i", container, "pg_restore", "-U", "postgres", "--exit-on-error", "--no-owner", "--no-privileges", "--dbname", restoreDB)
		restore.Stdin = bytes.NewReader(dump)
		if out, err := restore.CombinedOutput(); err != nil {
			t.Fatalf("restore: %s %v", out, err)
		}
		restoredURL, err := url.Parse(databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		restoredURL.Path = "/" + restoreDB
		restored, err := connections.Open(ctx, restoredURL.String(), schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		defer restored.Close()
		saved, credential, err := restored.Get(ctx, "test")
		if err != nil || saved.Enabled || !strings.Contains(string(credential), "rotated") {
			t.Fatal("restored credential/state mismatch", err)
		}
		if _, err := restored.Authenticate(ctx, issued.Token, netip.MustParseAddr("192.0.2.1")); !errors.Is(err, connections.ErrUnauthorized) {
			t.Fatal("restored revoked token accepted", err)
		}
		assets, err := restored.ListAssetsPage(ctx, 10, "", uuid.Nil)
		if err != nil || len(assets) != 1 || strings.Contains(string(assets[0].Flags), `"in_scope": true`) {
			t.Fatal("restored asset history/eligibility mismatch", err)
		}
	}
	// A fresh token receives exactly 120 requests per sliding minute.
	_, limited, err := store.CreateToken(ctx, connections.Token{Name: "limited", Scopes: []string{"read"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		mustStatus(request("GET", "/assets", limited, ""), 200)
	}
	mustStatus(request("GET", "/assets", limited, ""), 429)
}

type fixtureInventory struct{}

func (fixtureInventory) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return []connections.Resource{{Type: "github_repo", Locator: "org/api"}}, nil
}
