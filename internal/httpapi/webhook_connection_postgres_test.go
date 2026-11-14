package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Inbound webhooks per connection (GitHub, GitLab, Harbor, Docker Hub) and
// connection-scoped outbound subscriptions, through the real router.
func TestPostgresConnectionWebhooksAndScopedSubscriptions(t *testing.T) {
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
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := strings.Repeat("a", 40)
	if _, err := store.SyncBootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	ids := map[string]uuid.UUID{}
	for _, c := range []struct {
		conn      connections.Connection
		inventory staticInventory
	}{
		{connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}, staticInventory{{Type: "github_repo", Locator: "org/api"}}},
		{connections.Connection{Name: "gh2", Provider: "github", Config: json.RawMessage(`{"organization":"other","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"other/*"}}}, staticInventory{{Type: "github_repo", Locator: "other/web"}}},
		{connections.Connection{Name: "gl", Provider: "gitlab", Config: json.RawMessage(`{"group":"team","base_url":"https://gitlab.example.com"}`), Scope: connections.Scope{Include: []string{"team/**"}}}, staticInventory{{Type: "gitlab_repo", Locator: "team/app"}}},
		{connections.Connection{Name: "hb", Provider: "harbor", Config: json.RawMessage(`{"url":"https://harbor.example.com","project":"apps","username":"robot$scrs"}`), Scope: connections.Scope{Include: []string{"harbor.example.com/apps/*"}}}, staticInventory{{Type: "container_image", Locator: "harbor.example.com/apps/web"}}},
		{connections.Connection{Name: "dh", Provider: "dockerhub", Config: json.RawMessage(`{"namespace":"acme","identifier":"bot"}`), Scope: connections.Scope{Include: []string{"docker.io/acme/*"}}}, staticInventory{{Type: "container_image", Locator: "docker.io/acme/api"}}},
	} {
		if _, err := store.Put(ctx, c.conn, json.RawMessage(`{"token":"t"}`), false); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Discover(ctx, c.conn.Name, c.inventory); err != nil {
			t.Fatal(err)
		}
		got, _ := store.PublicByName(ctx, c.conn.Name)
		ids[c.conn.Name] = got.ID
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	events, err := notify.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	// No deployment-wide webhook secrets are configured.
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Notify: events})
	call := func(method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
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
	type webhookResult struct {
		Connection connections.Connection `json:"connection"`
		Secret     string                 `json:"webhook_secret"`
		Receiver   string                 `json:"receiver_url"`
		Setup      string                 `json:"setup"`
	}
	setWebhook := func(name, body string, status int) webhookResult {
		t.Helper()
		var out webhookResult
		w := must(call("POST", "/connections/"+ids[name].String()+":webhook", admin, body, nil), status)
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}

	// A connection gets its own secret and receiver; the secret is shown once.
	_, writer, _ := store.CreateToken(ctx, connections.Token{Name: "ci", Scopes: []string{"write"}}, uuid.Nil)
	must(call("POST", "/connections/"+ids["gh"].String()+":webhook", writer, "", nil), 403)
	gh := setWebhook("gh", "", 200)
	if len(gh.Secret) != 64 || gh.Receiver != "/scrs/v1/ingest/github/gh" || !gh.Connection.Webhook.Configured || gh.Connection.Webhook.RotatedAt == nil || !strings.Contains(gh.Setup, "Secret") {
		t.Fatalf("webhook setup %+v", gh)
	}
	if body := must(call("GET", "/connections/"+ids["gh"].String(), admin, "", nil), 200).Body.String(); strings.Contains(body, gh.Secret) || !strings.Contains(body, `"configured":true`) {
		t.Fatal("connection view leaks the secret or lacks webhook state", body)
	}
	var sealed []byte
	_ = pool.QueryRow(ctx, `SELECT webhook_secret_ciphertext FROM `+schema+`.connections WHERE name='gh'`).Scan(&sealed)
	if bytes.Contains(sealed, []byte(gh.Secret)) {
		t.Fatal("webhook secret stored in clear")
	}

	// GitHub: signed with the connection's secret, scoped to its repositories.
	sign := func(secret, body string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(body))
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	push := func(repo string) string {
		return `{"ref":"refs/heads/main","after":"` + strings.Repeat("a", 40) + `","repository":{"full_name":"` + repo + `","default_branch":"main"},"pusher":{"name":"dev"},"commits":[]}`
	}
	github := func(secret, body string) map[string]string {
		return map[string]string{"X-GitHub-Event": "push", "X-GitHub-Delivery": uuid.NewString(), "X-Hub-Signature-256": sign(secret, body)}
	}
	body := push("org/api")
	var queued assessments.Assessment
	_ = json.Unmarshal(must(call("POST", "/ingest/github/gh", "", body, github(gh.Secret, body)), 202).Body.Bytes(), &queued)
	if queued.Request.Connection != "gh" || queued.ConnectionID != ids["gh"] {
		t.Fatalf("push not bound to its connection %+v", queued.Request)
	}
	must(call("POST", "/ingest/github/gh", "", body, github(strings.Repeat("x", 64), body)), 401)
	must(call("POST", "/ingest/github/gh", "", body, map[string]string{"X-GitHub-Event": "push", "X-GitHub-Delivery": uuid.NewString()}), 401)
	must(call("POST", "/ingest/github/nobody", "", body, github(gh.Secret, body)), 401)
	must(call("POST", "/ingest/github/gh2", "", body, github(gh.Secret, body)), 401)
	if out := must(call("POST", "/ingest/github", "", body, github(gh.Secret, body)), 503).Body.String(); !strings.Contains(out, "use /ingest/github/") {
		t.Fatal(out)
	}
	// Another organization's repository is out of this connection's scope.
	foreign := push("other/web")
	if out := must(call("POST", "/ingest/github/gh", "", foreign, github(gh.Secret, foreign)), 200).Body.String(); !strings.Contains(out, "ignored_out_of_scope") {
		t.Fatal(out)
	}
	// Rotation replaces the secret; the old one stops working.
	rotated := setWebhook("gh", `{"rotate_secret":true}`, 200)
	if rotated.Secret == gh.Secret {
		t.Fatal("secret not rotated")
	}
	again := push("org/api")
	must(call("POST", "/ingest/github/gh", "", again, github(gh.Secret, again)), 401)
	must(call("POST", "/ingest/github/gh", "", again, github(rotated.Secret, again)), 202)
	// A hook URL alone keeps the secret; GitLab connections take no hook URL.
	if kept := setWebhook("gh", `{"hook_url":"https://relay.example.com/hooks/scrs"}`, 200); kept.Secret != "" || kept.Connection.Webhook.HookURL != "https://relay.example.com/hooks/scrs" {
		t.Fatalf("hook url %+v", kept)
	}
	setWebhook("gl", `{"hook_url":"https://relay.example.com/x"}`, 400)
	setWebhook("gh", `{"secret":"too-short"}`, 400)

	// GitLab: X-Gitlab-Token is the connection's secret.
	gl := setWebhook("gl", `{"secret":"`+strings.Repeat("g", 40)+`"}`, 200)
	if gl.Secret != strings.Repeat("g", 40) || gl.Receiver != "/scrs/v1/ingest/gitlab/gl" {
		t.Fatalf("gitlab webhook %+v", gl)
	}
	lab := `{"object_kind":"push","ref":"refs/heads/main","before":"` + strings.Repeat("0", 40) + `","after":"` + strings.Repeat("c", 40) + `","user_username":"dev","project":{"path_with_namespace":"team/app","default_branch":"main"},"commits":[]}`
	must(call("POST", "/ingest/gitlab/gl", "", lab, map[string]string{"X-Gitlab-Token": "wrong", "X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": uuid.NewString()}), 401)
	must(call("POST", "/ingest/gitlab/gl", "", lab, map[string]string{"X-Gitlab-Token": gl.Secret, "X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": uuid.NewString()}), 202)

	// Registries: Harbor's Auth Header, Docker Hub's URL token; no relay
	// token or SCRS_RELAY_ENABLED needed.
	hb := setWebhook("hb", "", 200)
	if hb.Receiver != "/scrs/v1/ingest/registry/harbor/hb" || !strings.Contains(hb.Setup, "Auth Header") {
		t.Fatalf("harbor webhook %+v", hb)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	harbor := `{"type":"PUSH_ARTIFACT","event_data":{"resources":[{"digest":"` + digest + `","tag":"1.0","resource_url":"harbor.example.com/apps/web:1.0"}],"repository":{"repo_full_name":"apps/web"}}}`
	must(call("POST", "/ingest/registry/harbor/hb", "", harbor, nil), 401)
	must(call("POST", "/ingest/registry/harbor/hb", "wrong", harbor, nil), 401)
	must(call("POST", "/ingest/registry/dockerhub/hb", hb.Secret, harbor, nil), 401)
	if out := must(call("POST", "/ingest/registry/harbor/hb", hb.Secret, harbor, nil), 202).Body.String(); !strings.Contains(out, `"queued"`) {
		t.Fatal(out)
	}
	dh := setWebhook("dh", "", 200)
	hub := `{"push_data":{"tag":"v2"},"repository":{"repo_name":"acme/api"}}`
	must(call("POST", "/ingest/registry/dockerhub/dh?token=wrong", "", hub, nil), 401)
	must(call("POST", "/ingest/registry/dockerhub/dh?token="+dh.Secret, "", hub, nil), 202)
	// The Harbor connection's images are not reachable through Docker Hub's receiver.
	strayHub := `{"push_data":{"tag":"v3"},"repository":{"repo_name":"apps/web"}}`
	if out := must(call("POST", "/ingest/registry/dockerhub/dh?token="+dh.Secret, "", strayHub, nil), 200).Body.String(); !strings.Contains(out, "ignored_out_of_scope") {
		t.Fatal(out)
	}

	// Outbound: a subscription scoped to gh receives only gh's events and
	// platform events; an unscoped one receives everything.
	sub := func(name string, conns []uuid.UUID) uuid.UUID {
		t.Helper()
		s, _, err := events.Create(ctx, notify.Subscription{Name: name, URL: "https://hooks.example.com/" + name, Events: []string{"assessment.completed", "feed.stale"}, Connections: conns}, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		return s.ID
	}
	scoped, all := sub("gh-only", []uuid.UUID{ids["gh"]}), sub("everything", nil)
	if _, _, err := events.Create(ctx, notify.Subscription{Name: "bad", URL: "https://hooks.example.com/bad", Events: []string{"feed.stale"}, Connections: []uuid.UUID{uuid.New()}}, uuid.Nil); err != notify.ErrInput {
		t.Fatal("unknown connection accepted", err)
	}
	var ghAsset uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator='org/api'`).Scan(&ghAsset)
	emit := func(event string, scope notify.Scope) {
		t.Helper()
		tx, _ := pool.Begin(ctx)
		if _, err := notify.EmitScoped(ctx, tx, schema, event, map[string]any{}, nil, scope); err != nil {
			t.Fatal(err)
		}
		_ = tx.Commit(ctx)
	}
	count := func(id uuid.UUID) int {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.webhook_deliveries WHERE subscription_id=$1`, id).Scan(&n)
		return n
	}
	emit("assessment.completed", notify.Scope{Connection: ids["hb"]})
	if count(scoped) != 0 || count(all) != 1 {
		t.Fatal("another connection's event reached the scoped subscription", count(scoped), count(all))
	}
	emit("assessment.completed", notify.Scope{Connection: ids["gh"]})
	emit("assessment.completed", notify.Scope{Asset: ghAsset})
	emit("feed.stale", notify.Scope{})
	if count(scoped) != 3 || count(all) != 4 {
		t.Fatal("scoped delivery", count(scoped), count(all))
	}
	// Removing the scope makes it receive every connection's events again.
	cleared := []uuid.UUID{}
	if updated, err := events.Update(ctx, scoped, 1, notify.Change{Connections: &cleared}, uuid.Nil); err != nil || len(updated.Connections) != 0 {
		t.Fatal(updated, err)
	}
	emit("assessment.completed", notify.Scope{Connection: ids["hb"]})
	if count(scoped) != 4 {
		t.Fatal("cleared scope not applied")
	}
	_ = http.StatusOK
}
