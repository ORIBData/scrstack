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
	// Where a provider runs decides what it may be sent: this one's host is in
	// SCRS_LLM_PRIVATE_HOSTS, so it is local; a public endpoint is hosted.
	if p.Locality != "local" {
		t.Fatalf("locality of a self-hosted provider: %q", p.Locality)
	}
	hostedCreated := must(call("POST", "/llm/providers", admin, `{"name":"cloud","kind":"openai_compatible","base_url":"https://api.example.com/v1","model":"m-2","api_key":"sk-cloud-key"}`, nil), 201)
	var hostedProvider assessments.LLMProvider
	_ = json.Unmarshal(hostedCreated.Body.Bytes(), &hostedProvider)
	if hostedProvider.Locality != "hosted" || !strings.Contains(must(call("GET", "/llm/providers", reader, "", nil), 200).Body.String(), `"locality":"hosted"`) {
		t.Fatalf("locality of a hosted provider: %q", hostedProvider.Locality)
	}

	// Source code to a hosted provider is opt-in twice: the platform switch
	// (SCRS_LLM_ALLOW_SOURCE_TO_HOSTED) and an acknowledgement of that provider.
	must(call("POST", "/llm/providers/"+hostedProvider.ID.String()+":allow-source", admin, `{"note":"Zero-retention agreement signed 2026"}`, nil), 409) // switch off
	openHandler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, LLMPrivateHosts: map[string]bool{"127.0.0.1": true}, LLMAllowSource: true})
	callOpen := func(method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		openHandler.ServeHTTP(w, r)
		return w
	}
	allow := "/llm/providers/" + hostedProvider.ID.String() + ":allow-source"
	must(callOpen("POST", allow, writer, `{"note":"Zero-retention agreement signed 2026"}`, nil), 403)
	must(callOpen("POST", allow, admin, `{}`, nil), 400)                                                                   // a note is the audit trail
	must(callOpen("POST", "/llm/providers/"+p.ID.String()+":allow-source", admin, `{"note":"not needed here"}`, nil), 409) // self-hosted needs none
	acked := must(callOpen("POST", allow, admin, `{"note":"Zero-retention agreement signed 2026"}`, nil), 200)
	var ackedProvider assessments.LLMProvider
	_ = json.Unmarshal(acked.Body.Bytes(), &ackedProvider)
	if !ackedProvider.SourceAllowed || ackedProvider.Locality != "hosted" || ackedProvider.SourceAckAt == nil || ackedProvider.SourceAckNote == "" {
		t.Fatalf("acknowledged provider: %+v", ackedProvider)
	}
	// The same acknowledgement means nothing while the platform switch is off.
	if body := must(call("GET", "/llm/providers/"+hostedProvider.ID.String(), reader, "", nil), 200).Body.String(); !strings.Contains(body, `"source_allowed":false`) {
		t.Fatal("source must not be allowed while the platform switch is off:", body)
	}
	// Pointing the provider elsewhere withdraws the acknowledgement.
	moved := must(callOpen("PATCH", "/llm/providers/"+hostedProvider.ID.String(), admin, `{"base_url":"https://other.example.com/v1"}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, ackedProvider.Revision)}), 200)
	if !strings.Contains(moved.Body.String(), `"source_allowed":false`) || !strings.Contains(moved.Body.String(), `"source_ack_at":null`) {
		t.Fatal("a changed endpoint must clear the acknowledgement:", moved.Body.String())
	}
	must(callOpen("POST", allow, admin, `{"note":"Zero-retention agreement signed 2026"}`, nil), 200)
	revoked := must(callOpen("POST", "/llm/providers/"+hostedProvider.ID.String()+":revoke-source", admin, ``, nil), 200)
	if !strings.Contains(revoked.Body.String(), `"source_allowed":false`) {
		t.Fatal(revoked.Body.String())
	}
	var audited int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action IN ('llm_provider.source_allowed','llm_provider.source_revoked')`).Scan(&audited)
	if audited != 3 {
		t.Fatalf("acknowledgements must be audited, got %d", audited)
	}

	// A provider declared in the environment is managed there.
	managed, action, err := jobs.BootstrapLLMProvider(ctx, assessments.LLMProvider{Name: "from-env", Kind: "openai_compatible", BaseURL: "https://api.example.com/v1", Model: "m-env", MaxTokens: 4096}, false,
		func(id uuid.UUID) ([]byte, error) { return []byte{}, nil }, func(uuid.UUID, []byte) bool { return true })
	if err != nil || action != "created" || !managed.Managed {
		t.Fatal(managed, action, err)
	}
	must(call("DELETE", "/llm/providers/"+managed.ID.String(), admin, "", nil), 409)
	must(call("PATCH", "/llm/providers/"+managed.ID.String(), admin, `{"model":"other"}`, map[string]string{"If-Match": `"1"`}), 409)
	must(call("PATCH", "/llm/providers/"+managed.ID.String(), admin, `{"enabled":false}`, map[string]string{"If-Match": `"1"`}), 200) // an administrator can still switch it off

	// AI code review: with the platform switch off, source goes only to a self-hosted provider.
	reviews := "/assets/" + asset.String() + "/ai-reviews"
	must(call("POST", reviews, reader, `{}`, nil), 403)
	must(call("POST", reviews, writer, `{}`, nil), 400) // provider_id is required
	must(call("POST", reviews, writer, `{"provider_id":"`+hostedProvider.ID.String()+`"}`, nil), 409)
	if body := call("POST", reviews, trigger, `{"provider_id":"`+hostedProvider.ID.String()+`"}`, nil).Body.String(); !strings.Contains(body, "may not receive source code") {
		t.Fatal("the refusal should say why:", body)
	}
	must(call("POST", reviews, writer, `{"provider_id":"`+uuid.NewString()+`"}`, nil), 409)
	must(call("POST", reviews, writer, `{"provider_id":"`+p.ID.String()+`","max_files":99}`, nil), 400)
	must(call("POST", reviews, writer, `{"provider_id":"`+p.ID.String()+`"}`, nil), 409) // local, but the asset has no successful assessment yet
	must(call("POST", reviews, writer, `{"provider_id":"`+p.ID.String()+`","unknown":1}`, nil), 400)
	if body := must(call("GET", reviews, reader, "", nil), 200).Body.String(); !strings.Contains(body, `"items":[]`) {
		t.Fatal(body)
	}
	must(call("GET", "/ai-reviews/"+uuid.NewString(), reader, "", nil), 404)
	must(call("GET", "/ai-reviews/not-a-uuid", reader, "", nil), 404)
	must(call("GET", "/ai-reviews/"+uuid.NewString(), "", "", nil), 401)

	// AI advisories and summaries: any provider, findings and advisory text only.
	summaries := "/assessments/" + uuid.NewString() + "/summaries"
	must(call("POST", summaries, reader, `{}`, nil), 403)
	must(call("POST", summaries, writer, `{}`, nil), 400) // provider_id is required
	must(call("POST", summaries, trigger, `{"provider_id":"`+uuid.NewString()+`"}`, nil), 409)
	must(call("POST", summaries, writer, `{"provider_id":"`+p.ID.String()+`","max_advisories":99}`, nil), 400)
	must(call("POST", summaries, writer, `{"provider_id":"`+p.ID.String()+`"}`, nil), 404) // no such assessment
	must(call("POST", summaries, writer, `{"provider_id":"`+hostedProvider.ID.String()+`","bogus":1}`, nil), 400)
	if body := must(call("GET", summaries, reader, "", nil), 200).Body.String(); !strings.Contains(body, `"items":[]`) {
		t.Fatal(body)
	}
	must(call("GET", "/summary-jobs/"+uuid.NewString(), reader, "", nil), 404)
	must(call("GET", "/summary-jobs/nope", reader, "", nil), 404)

	// The chronicle is empty until something is written, and its filters are checked.
	chronicle := "/assets/" + asset.String() + "/chronicle"
	if body := must(call("GET", chronicle, reader, "", nil), 200).Body.String(); !strings.Contains(body, `"items":[]`) {
		t.Fatal(body)
	}
	must(call("GET", chronicle+"?kind=advisory,assessment_summary&include_superseded=true&limit=5", reader, "", nil), 200)
	must(call("GET", chronicle+"?finding_id=nope", reader, "", nil), 400)
	must(call("GET", chronicle+"?assessment_id=nope", reader, "", nil), 400)
	must(call("GET", chronicle+"?since=yesterday", reader, "", nil), 400)
	must(call("GET", chronicle+"?limit=0", reader, "", nil), 400)
	must(call("GET", chronicle+"?limit=500", reader, "", nil), 400)
	must(call("GET", chronicle, "", "", nil), 401)

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
	// Lint settings and AI triage are part of the profile.
	withLint := strings.Replace(keep, `"perf":`, fmt.Sprintf(`"lint":{"tools":["ruff"]},"ai_triage":true,"perf":`), 1)
	for _, bad := range []string{strings.Replace(keep, `"perf":`, `"lint":{"tools":["rm"]},"perf":`, 1), strings.Replace(keep, `"perf":`, `"lint":{"tools":[]},"perf":`, 1), strings.Replace(strings.Replace(keep, fmt.Sprintf(`"llm_provider_id":%q,`, p.ID), "", 1), `"perf":`, `"ai_triage":true,"perf":`, 1)} {
		must(call("PUT", base, admin, bad, map[string]string{"If-Match": `"2"`}), 400)
	}
	must(call("PUT", base, admin, withLint, map[string]string{"If-Match": `"2"`}), 200)
	_ = json.Unmarshal(must(call("GET", base, reader, "", nil), 200).Body.Bytes(), &got)
	if got.Lint == nil || len(got.Lint.Tools) != 1 || got.Lint.Tools[0] != "ruff" || !got.AITriage {
		t.Fatalf("lint settings %+v", got)
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
	// A lint run is a known kind: it is refused only for want of an assessment.
	if body := must(call("POST", runs, writer, `{"kind":"lint"}`, nil), 409).Body.String(); !strings.Contains(body, "run one first") {
		t.Fatal(body)
	}
	must(call("POST", "/assets/"+asset.String()+"/qa/generations", writer, `{"kind":"unit"}`, nil), 409)
	must(call("POST", "/assets/"+asset.String()+"/qa/generations", writer, `{"kind":"api","max_operations":500}`, nil), 400)
	must(call("GET", runs, reader, "", nil), 200)
	must(call("GET", "/assets/"+asset.String()+"/qa/coverage", reader, "", nil), 200)
	must(call("GET", "/assets/"+asset.String()+"/qa/suites?kind=api", reader, "", nil), 200)
	must(call("GET", "/assets/"+asset.String()+"/qa/generations", reader, "", nil), 200)
	must(call("GET", "/assessments/"+uuid.NewString()+"/qa", trigger, "", nil), 200)

	// A qa token starts and reads QA and reaches nothing else. The default
	// gate still wants an assessment; gate none (admin only) does not.
	_, qaToken, err := store.CreateToken(ctx, connections.Token{Name: "qa-pipeline", Scopes: []string{"qa"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateToken(ctx, connections.Token{Name: "bad", Scopes: []string{"quality"}}, uuid.Nil); err == nil {
		t.Fatal("an unknown scope was accepted")
	}
	must(call("GET", base, qaToken, "", nil), 200)
	must(call("GET", runs, qaToken, "", nil), 200)
	must(call("GET", "/qa/runner", qaToken, "", nil), 200)
	if body := must(call("POST", runs, qaToken, `{"kind":"full"}`, nil), 409).Body.String(); !strings.Contains(body, "run one first") {
		t.Fatal(body)
	}
	must(call("PUT", base, qaToken, withLint, map[string]string{"If-Match": `"3"`}), 403)
	must(call("POST", "/assessments", qaToken, `{"target":{"type":"git","repository":"org/repo","ref":"main"}}`, nil), 403)
	must(call("GET", "/assessments", qaToken, "", nil), 403)
	must(call("GET", "/assets", qaToken, "", nil), 403)
	must(call("POST", "/qa/runs/"+uuid.NewString()+"/triage", qaToken, `{}`, nil), 403)
	must(call("POST", "/assets/"+asset.String()+"/qa/generations", qaToken, `{"kind":"unit"}`, nil), 403)
	must(call("POST", "/assets/"+asset.String()+"/ai-reviews", qaToken, `{}`, nil), 403)
	ungated := strings.Replace(withLint, "{", `{"gate":"none",`, 1)
	must(call("PUT", base, writer, ungated, map[string]string{"If-Match": `"3"`}), 403)
	must(call("PUT", base, admin, strings.Replace(withLint, "{", `{"gate":"sometimes",`, 1), map[string]string{"If-Match": `"3"`}), 400)
	if body := must(call("PUT", base, admin, ungated, map[string]string{"If-Match": `"3"`}), 200).Body.String(); !strings.Contains(body, `"gate":"none"`) {
		t.Fatal(body)
	}
	must(call("POST", runs, qaToken, `{"kind":"lint","ref":"feature/x"}`, nil), 400) // outside the profile's refs
	full := must(call("POST", runs, qaToken, `{"kind":"full","ref":"main"}`, nil), 202)
	var started struct {
		Runs []struct {
			ID          string `json:"id"`
			Kind        string `json:"kind"`
			Ref         string `json:"ref"`
			RequestedBy string `json:"requested_by"`
		} `json:"runs"`
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(full.Body.Bytes(), &started); err != nil || len(started.Runs) != 3 || started.Runs[0].Kind != "functional" || started.Runs[2].Kind != "lint" || started.JobID == "" || started.Runs[0].ID != started.JobID || started.Runs[0].Ref != "main" || started.Runs[0].RequestedBy != "qa-pipeline" || !strings.HasSuffix(full.Header().Get("Location"), started.JobID) {
		t.Fatal(full.Body, err)
	}
	one := must(call("POST", runs, qaToken, `{"kind":"lint"}`, nil), 202).Body.String()
	if !strings.Contains(one, `"assessment_id":null`) || !strings.Contains(one, `"job_id"`) || strings.Contains(one, `"runs"`) {
		t.Fatal(one)
	}
	must(call("POST", "/qa/runs/"+started.JobID+":cancel", qaToken, "", nil), 200)
	must(call("GET", "/qa/runs/"+started.JobID, qaToken, "", nil), 200)
	if body := must(call("GET", "/qa/runner", reader, "", nil), 200).Body.String(); !strings.Contains(body, `"configured":false`) {
		t.Fatal(body)
	}
	must(call("GET", "/qa/runs/"+uuid.NewString(), reader, "", nil), 404)
	must(call("POST", "/qa/runs/"+uuid.NewString()+":cancel", reader, "", nil), 403)
	must(call("POST", "/qa/runs/"+uuid.NewString()+":cancel", trigger, "", nil), 404)
	must(call("POST", "/qa/runs/"+uuid.NewString()+"/triage", reader, `{}`, nil), 403)
	must(call("POST", "/qa/runs/"+uuid.NewString()+"/triage", writer, `{}`, nil), 404)
	must(call("POST", "/qa/runs/"+uuid.NewString()+"/triage", writer, `{"provider_id":"not-a-uuid"}`, nil), 400)
	must(call("GET", "/qa/runs/"+uuid.NewString()+"/triage", reader, "", nil), 404)
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
