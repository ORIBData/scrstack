package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// The QA and LLM provider API through the real router and authorization:
// scopes, write-only secrets, revisions and the provider check.
func TestPostgresQAAndLLMProviderAPI(t *testing.T) {
	databaseURL, redisURL := os.Getenv("SCRS_TEST_DATABASE_URL"), os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, databaseURL)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	store, err := connections.Open(ctx, databaseURL, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := strings.Repeat("a", 40)
	if _, err := store.SyncBootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	gh := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := store.Put(ctx, gh, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Discover(ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}}); err != nil {
		t.Fatal(err)
	}
	var asset uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator='org/api'`).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-live-key" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":{"message":"bad key"}}`)
			return
		}
		fmt.Fprint(w, `{"model":"m-1","choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}}`)
	}))
	defer model.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, LLMPrivateHosts: map[string]bool{"127.0.0.1": true}})
	call := func(method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	must := func(w *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
		t.Helper()
		if w.Code != status {
			t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body)
		}
		return w
	}
	_, writer, _ := store.CreateToken(ctx, connections.Token{Name: "ci", Scopes: []string{"write"}}, uuid.Nil)
	_, reader, _ := store.CreateToken(ctx, connections.Token{Name: "ro", Scopes: []string{"read"}}, uuid.Nil)
	_, trigger, _ := store.CreateToken(ctx, connections.Token{Name: "n8n", Scopes: []string{"trigger"}}, uuid.Nil)

	// LLM providers: admin manages, read lists; keys never come back.
	if body := must(call("GET", "/llm/presets", reader, "", nil), 200).Body.String(); !strings.Contains(body, `"kind":"anthropic"`) || !strings.Contains(body, "generativelanguage.googleapis.com") {
		t.Fatal(body)
	}
	provider := fmt.Sprintf(`{"name":"local","kind":"openai_compatible","base_url":%q,"model":"m-1","max_tokens":2048,"api_key":"sk-live-key"}`, model.URL+"/v1")
	must(call("POST", "/llm/providers", writer, provider, nil), 403)
	created := must(call("POST", "/llm/providers", admin, provider, nil), 201)
	if strings.Contains(created.Body.String(), "sk-live-key") || created.Header().Get("ETag") != `"1"` {
		t.Fatal("key echoed or ETag missing", created.Body.String())
	}
	var p assessments.LLMProvider
	_ = json.Unmarshal(created.Body.Bytes(), &p)
	var sealedKey []byte
	_ = pool.QueryRow(ctx, `SELECT credential FROM `+schema+`.llm_providers WHERE id=$1`, p.ID).Scan(&sealedKey)
	if !p.HasKey || bytes.Contains(sealedKey, []byte("sk-live-key")) {
		t.Fatal("key stored in clear")
	}
	must(call("POST", "/llm/providers", admin, provider, nil), 409)
	must(call("POST", "/llm/providers", admin, `{"name":"nokey","kind":"openai","model":"gpt-5.1"}`, nil), 400)
	must(call("POST", "/llm/providers", admin, `{"name":"plain","kind":"openai","base_url":"http://api.openai.com/v1","model":"m","api_key":"k"}`, nil), 400)
	tested := must(call("POST", "/llm/providers/"+p.ID.String()+":test", admin, "", nil), 200).Body.String()
	if !strings.Contains(tested, `"reply":"OK"`) || !strings.Contains(tested, `"ok":true`) {
		t.Fatal(tested)
	}
	must(call("PATCH", "/llm/providers/"+p.ID.String(), admin, `{"model":"m-2"}`, nil), 428)
	must(call("PATCH", "/llm/providers/"+p.ID.String(), admin, `{"api_key":"wrong"}`, map[string]string{"If-Match": `"1"`}), 200)
	failedTest := must(call("POST", "/llm/providers/"+p.ID.String()+":test", admin, "", nil), 502).Body.String()
	if !strings.Contains(failedTest, "refused the API key") || !strings.Contains(failedTest, "bad key") {
		t.Fatal(failedTest)
	}
	must(call("PATCH", "/llm/providers/"+p.ID.String(), admin, `{"api_key":"sk-live-key"}`, map[string]string{"If-Match": `"1"`}), 409)
	if list := must(call("GET", "/llm/providers", reader, "", nil), 200).Body.String(); !strings.Contains(list, `"last_test_error":"model provider refused`) {
		t.Fatal(list)
	}

	// QA profile: admin writes; variables are sealed and write-only.
	base := "/assets/" + asset.String() + "/qa/profile"
	must(call("GET", base, reader, "", nil), 404)
	profile := fmt.Sprintf(`{"base_url":"https://api.staging.example.com","environment":"staging","refs":["main"],"variables":{"API_TOKEN":"profile-secret"},"auth":{"header":"Authorization","variable":"API_TOKEN","prefix":"Bearer "},"llm_provider_id":%q,"perf":{"features":["perf/load.feature"],"users":5,"duration_seconds":30,"p95_millis":500}}`, p.ID)
	must(call("PUT", base, writer, profile, nil), 403)
	saved := must(call("PUT", base, admin, profile, nil), 201)
	if saved.Header().Get("ETag") != `"1"` || strings.Contains(saved.Body.String(), "profile-secret") {
		t.Fatal(saved.Body.String())
	}
	var sealedVars []byte
	_ = pool.QueryRow(ctx, `SELECT variables FROM `+schema+`.qa_profiles WHERE asset_id=$1`, asset).Scan(&sealedVars)
	if len(sealedVars) == 0 || bytes.Contains(sealedVars, []byte("profile-secret")) {
		t.Fatal("variables stored in clear")
	}
	var got assessments.QAProfile
	_ = json.Unmarshal(must(call("GET", base, reader, "", nil), 200).Body.Bytes(), &got)
	if got.TestPath != "karate" || got.Threads != 1 || !got.AutoRun || len(got.VariableNames) != 1 || got.Perf == nil || got.Perf.Users != 5 {
		t.Fatalf("defaults %+v", got)
	}
	must(call("PUT", base, admin, profile, nil), 428)
	// Omitting variables keeps them; auth may still name API_TOKEN.
	keep := strings.Replace(profile, `"variables":{"API_TOKEN":"profile-secret"},`, "", 1)
	must(call("PUT", base, admin, keep, map[string]string{"If-Match": `"1"`}), 200)
	for _, bad := range []string{`{"base_url":"ftp://x"}`, `{"base_url":"https://x","test_path":"../etc"}`, `{"base_url":"https://x","tags":["smoke"]}`, `{"base_url":"https://x","auth":{"header":"Authorization","variable":"MISSING"}}`, `{"base_url":"https://x","variables":{"bad name":"v"}}`} {
		must(call("PUT", base, admin, bad, map[string]string{"If-Match": `"2"`}), 400)
	}
	notRepo := "/assets/" + uuid.NewString() + "/qa/profile"
	must(call("PUT", notRepo, admin, `{"base_url":"https://x"}`, nil), 404)

	// Runs and generations need a successful assessment.
	runs := "/assets/" + asset.String() + "/qa/runs"
	must(call("POST", runs, reader, `{}`, nil), 403)
	if body := must(call("POST", runs, trigger, `{}`, nil), 409).Body.String(); !strings.Contains(body, "run one first") {
		t.Fatal(body)
	}
	must(call("POST", runs, writer, `{"include_drafts":true}`, nil), 403)
	must(call("POST", runs, writer, `{"kind":"stress"}`, nil), 400)
	must(call("POST", "/assets/"+asset.String()+"/qa/generations", writer, `{"kind":"unit"}`, nil), 409)
	must(call("POST", "/assets/"+asset.String()+"/qa/generations", writer, `{"kind":"api","max_operations":500}`, nil), 400)
	must(call("GET", runs, reader, "", nil), 200)
	must(call("GET", "/assets/"+asset.String()+"/qa/coverage", reader, "", nil), 200)
	must(call("GET", "/assets/"+asset.String()+"/qa/suites?kind=api", reader, "", nil), 200)
	must(call("GET", "/assets/"+asset.String()+"/qa/generations", reader, "", nil), 200)
	must(call("GET", "/assessments/"+uuid.NewString()+"/qa", trigger, "", nil), 200)
	if body := must(call("GET", "/qa/runner", reader, "", nil), 200).Body.String(); !strings.Contains(body, `"configured":false`) {
		t.Fatal(body)
	}
	must(call("GET", "/qa/runs/"+uuid.NewString(), reader, "", nil), 404)
	must(call("POST", "/qa/runs/"+uuid.NewString()+":cancel", reader, "", nil), 403)
	must(call("POST", "/qa/runs/"+uuid.NewString()+":cancel", trigger, "", nil), 404)
	must(call("POST", "/qa/suites/"+uuid.NewString()+":approve", writer, `{}`, nil), 403)
	must(call("GET", "/qa/generations/"+uuid.NewString()+"/files", reader, "", nil), 404)

	// Deleting the provider detaches it from the profile.
	must(call("DELETE", "/llm/providers/"+p.ID.String(), admin, "", nil), 204)
	_ = json.Unmarshal(must(call("GET", base, reader, "", nil), 200).Body.Bytes(), &got)
	if got.LLMProviderID != nil {
		t.Fatal("deleted provider still referenced")
	}
	must(call("DELETE", base, writer, "", nil), 403)
	must(call("DELETE", base, admin, "", nil), 204)
	must(call("DELETE", base, admin, "", nil), 404)
}
