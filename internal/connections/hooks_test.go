package connections

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
)

func TestGitHubHooksReadOrgAndAppWebhooks(t *testing.T) {
	now := time.Now().UTC()
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	var redelivered []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/orgs/org/hooks" && bearer == "Bearer pat":
			_, _ = w.Write([]byte(`[{"id":8,"active":true,"events":["*"],"config":{"url":"https://n8n.example/hook","content_type":"json","insecure_ssl":"0"}},
				{"id":7,"active":true,"events":["push","pull_request"],"config":{"url":"https://scrs.example/scrs/v1/webhooks/github","content_type":"json","insecure_ssl":"0"}}]`))
		case r.URL.Path == "/orgs/empty/hooks":
			_, _ = w.Write([]byte(`[{"id":8,"active":true,"events":["*"],"config":{"url":"https://n8n.example/hook","content_type":"json","insecure_ssl":"0"}}]`))
		case r.URL.Path == "/orgs/org/hooks/7/deliveries" && r.URL.Query().Get("cursor") == "":
			w.Header().Set("Link", `<`+server.URL+`/orgs/org/hooks/7/deliveries?per_page=100&cursor=p2>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":3,"guid":"g3","delivered_at":"` + at(time.Minute) + `","status_code":502,"event":"push"},{"id":2,"guid":"g2","delivered_at":"` + at(2*time.Minute) + `","status_code":202,"event":"push"}]`))
		case r.URL.Path == "/orgs/org/hooks/7/deliveries" && r.URL.Query().Get("cursor") == "p2":
			// The second page crosses the window start; the walk stops there.
			w.Header().Set("Link", `<https://evil.example/steal?cursor=p3>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":1,"guid":"g1","delivered_at":"` + at(3*time.Minute) + `","status_code":0,"event":"push"},{"id":0,"guid":"old","delivered_at":"` + at(2*time.Hour) + `","status_code":500,"event":"push"}]`))
		case r.URL.Path == "/orgs/org/hooks/8/deliveries":
			_, _ = w.Write([]byte(`[]`))
		case r.URL.Path == "/orgs/org/hooks/7/deliveries/3/attempts" && r.Method == http.MethodPost:
			redelivered = append(redelivered, "org:3")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/app/hook/config" && strings.HasPrefix(bearer, "Bearer ey"):
			_, _ = w.Write([]byte(`{"url":"https://scrs.example/scrs/v1/ingest/github","content_type":"form","insecure_ssl":"1"}`))
		case r.URL.Path == "/app" && strings.HasPrefix(bearer, "Bearer ey"):
			_, _ = w.Write([]byte(`{"events":["pull_request"]}`))
		case r.URL.Path == "/app/hook/deliveries":
			// A relay page that loops back must not be followed off-endpoint.
			w.Header().Set("Link", `<`+server.URL+`/orgs/org/hooks/7/deliveries?cursor=x>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":9,"guid":"a9","delivered_at":"` + at(time.Minute) + `","status_code":503,"event":"push"}]`))
		case r.URL.Path == "/app/hook/deliveries/9/attempts" && r.Method == http.MethodPost:
			redelivered = append(redelivered, "app:9")
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a := NativeAdapters{Client: server.Client(), GitHubAPI: server.URL}
	pat := Connection{Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`)}
	hooks, err := a.GitHubHooks(context.Background(), pat, json.RawMessage(`{"token":"pat"}`), "", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 || hooks[0].ID != 7 || hooks[0].Source != "org" || len(hooks[0].Problems) != 0 || hooks[0].Truncated {
		t.Fatalf("only the hook pointing at SCRS is checked: %+v", hooks)
	}
	var guids []string
	for _, d := range hooks[0].Deliveries {
		guids = append(guids, d.GUID)
	}
	if strings.Join(guids, ",") != "g3,g2,g1" {
		t.Fatal("deliveries walk pages until the window start", guids)
	}
	if err := a.RedeliverGitHub(context.Background(), pat, json.RawMessage(`{"token":"pat"}`), hooks[0], 3); err != nil {
		t.Fatal(err)
	}
	// An explicit public URL (for example a relay) replaces the path match.
	if hooks, err = a.GitHubHooks(context.Background(), pat, json.RawMessage(`{"token":"pat"}`), "https://n8n.example/hook/", now.Add(-time.Hour)); err != nil || len(hooks) != 1 || hooks[0].ID != 8 {
		t.Fatal("configured hook URL", hooks, err)
	}
	empty := Connection{Provider: "github", Config: json.RawMessage(`{"organization":"empty","auth_type":"fine_grained_pat"}`)}
	if hooks, err = a.GitHubHooks(context.Background(), empty, json.RawMessage(`{"token":"pat"}`), "", now.Add(-time.Hour)); err != nil || len(hooks) != 1 || hooks[0].ID != 0 || !strings.Contains(strings.Join(hooks[0].Problems, ";"), "no organization webhook") {
		t.Fatal("a missing hook is a reported problem", hooks, err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	secret, _ := json.Marshal(map[string]string{"private_key_pem": private})
	app := Connection{Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"github_app","app_id":"1","installation_id":42}`)}
	hooks, err = a.GitHubHooks(context.Background(), app, secret, "", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	problems := strings.Join(hooks[0].Problems, ";")
	if len(hooks) != 1 || hooks[0].Source != "app" || !strings.Contains(problems, "push events") || !strings.Contains(problems, "application/json") || !strings.Contains(problems, "TLS") {
		t.Fatalf("app webhook configuration problems: %+v", hooks)
	}
	if len(hooks[0].Deliveries) != 1 || hooks[0].Deliveries[0].GUID != "a9" {
		t.Fatal("app deliveries; an off-endpoint next link is not followed", hooks[0].Deliveries)
	}
	if err := a.RedeliverGitHub(context.Background(), app, secret, hooks[0], 9); err != nil {
		t.Fatal(err)
	}
	if strings.Join(redelivered, ",") != "org:3,app:9" {
		t.Fatal("redelivery requests", redelivered)
	}
	for config, valid := range map[string]bool{
		`{"organization":"org","auth_type":"fine_grained_pat","webhook_source":"org"}`: true,
		`{"organization":"org","auth_type":"fine_grained_pat","webhook_source":"app"}`: false,
		`{"organization":"org","auth_type":"fine_grained_pat","webhook_source":"x"}`:   false,
	} {
		err := ValidateInput(Connection{Name: "gh", Provider: "github", Config: json.RawMessage(config)}, json.RawMessage(`{"token":"t"}`))
		if (err == nil) != valid {
			t.Error("webhook_source validation", config, err)
		}
	}
}

type fakeHooks struct {
	deliveries  []HookDelivery
	err         error
	since       []time.Time
	redelivered []int64
}

func (f *fakeHooks) GitHubHooks(_ context.Context, _ Connection, _ json.RawMessage, _ string, since time.Time) ([]GitHubHook, error) {
	f.since = append(f.since, since)
	if f.err != nil {
		return nil, f.err
	}
	return []GitHubHook{{Source: "org", ID: 7, Problems: []string{}, Deliveries: f.deliveries}}, nil
}

func (f *fakeHooks) RedeliverGitHub(_ context.Context, _ Connection, _ json.RawMessage, h GitHubHook, id int64) error {
	if h.Source != "org" || h.ID != 7 {
		return errors.New("wrong hook")
	}
	f.redelivered = append(f.redelivered, id)
	return nil
}

// Failed events are redelivered with backoff until GitHub's log shows them
// delivered; configuration rejections alert instead; exhausted or expired
// events are abandoned loudly; a failed check never skips deliveries.
func TestPostgresGitHubHookCheck(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable SCRS_TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.New().String()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: url, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, url, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() { _, _ = s.pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	gh := Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: Scope{Include: []string{"org/*"}}}
	if _, err := s.Put(ctx, gh, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	d := func(id int64, guid, event string, code int, ago time.Duration) HookDelivery {
		return HookDelivery{ID: id, GUID: guid, Event: event, StatusCode: code, DeliveredAt: base.Add(-ago)}
	}
	api := &fakeHooks{deliveries: []HookDelivery{
		d(11, "a", "push", 502, time.Minute),
		d(10, "b", "push", 200, 2*time.Minute), // b's redelivery already succeeded
		d(9, "b", "push", 500, 3*time.Minute),
		d(8, "c", "push", 401, 4*time.Minute),
		d(7, "d", "watch", 500, 5*time.Minute), // SCRS ignores watch events
		d(6, "e", "pull_request", 0, 6*time.Minute),
	}}
	check := func(at time.Duration) HookCheck {
		t.Helper()
		checks, ran, err := s.CheckGitHubHooks(ctx, api, "", base.Add(at))
		if err != nil || !ran || len(checks) != 1 {
			t.Fatal("check", checks, ran, err)
		}
		return checks[0]
	}
	status := func(guid string) string {
		var st string
		_ = s.pool.QueryRow(ctx, `SELECT status FROM `+schema+`.github_redeliveries WHERE guid=$1`, guid).Scan(&st)
		return st
	}

	first := check(0)
	if first.Redelivered != 2 || first.Rejected != 1 || first.State != "degraded" || !strings.Contains(strings.Join(first.Problems, ";"), "HTTP 401") {
		t.Fatalf("first check: %+v", first)
	}
	if !api.since[0].Equal(base.Add(-24 * time.Hour)) {
		t.Fatal("first window is 24 hours", api.since[0])
	}
	if status("b") != "" || status("d") != "" || status("c") != "rejected" {
		t.Fatal("settled, ignored and rejected deliveries", status("b"), status("d"), status("c"))
	}
	second := check(time.Minute)
	if second.Redelivered != 0 || second.Retrying != 2 || second.Rejected != 0 || second.State != "ok" {
		t.Fatalf("backoff holds redelivery and a rejection alerts once: %+v", second)
	}
	if !api.since[1].Equal(base.Add(-hookCheckOverlap)) {
		t.Fatal("window overlaps the last successful check", api.since[1])
	}
	// GitHub now lists a's redelivery as delivered.
	api.deliveries = append([]HookDelivery{d(12, "a", "push", 202, -5*time.Minute)}, api.deliveries...)
	if third := check(6 * time.Minute); third.Redelivered != 1 || status("a") != "delivered" {
		t.Fatalf("a settles and e retries after 5 minutes: %+v %s", third, status("a"))
	}
	for _, at := range []time.Duration{16, 36, 76} {
		check(at * time.Minute)
	}
	last := check(200 * time.Minute)
	if last.Abandoned != 1 || status("e") != "abandoned" || last.State != "degraded" || !strings.Contains(strings.Join(last.Problems, ";"), "could not be redelivered") {
		t.Fatalf("e is abandoned after five attempts: %+v", last)
	}
	// a once; e at 0, +6, +16, +36 and +76 minutes (5, 10, 20, 40 minute backoff).
	if got := len(api.redelivered); got != 6 {
		t.Fatal("redelivery calls", api.redelivered)
	}
	var audited int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action='connection.webhook_redelivery' AND details->'abandoned'->0->>'guid'='e'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("abandoned events are audited", audited, err)
	}

	// A failed check keeps the window anchored on the last success.
	api.err = errors.New("provider returned HTTP 401")
	if failed := check(210 * time.Minute); failed.State != "failed" || !failed.LastSuccess.Equal(base.Add(200*time.Minute)) {
		t.Fatalf("failed check: %+v", failed)
	}
	api.err = nil
	check(220 * time.Minute)
	if got := api.since[len(api.since)-1]; !got.Equal(base.Add(200*time.Minute - hookCheckOverlap)) {
		t.Fatal("deliveries during the failed check are not skipped", got)
	}
	listed, err := s.GitHubHookChecks(ctx)
	if err != nil || len(listed) != 1 || listed[0].Connection != "gh" || listed[0].CheckedAt.IsZero() {
		t.Fatal("latest check is listed", listed, err)
	}

	// Only one replica checks at a time.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".github_hook_check"); err != nil {
		t.Fatal(err)
	}
	if _, ran, err := s.CheckGitHubHooks(ctx, api, "", base.Add(230*time.Minute)); ran || err != nil {
		t.Fatal("a concurrent check must skip", ran, err)
	}
}
