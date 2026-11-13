package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
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

type receiver struct {
	mu       sync.Mutex
	status   int
	received []map[string]any
	headers  []http.Header
	bodies   [][]byte
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	rc.received = append(rc.received, v)
	rc.headers = append(rc.headers, r.Header.Clone())
	rc.bodies = append(rc.bodies, body)
	w.WriteHeader(rc.status)
}

func (rc *receiver) types() map[string]int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := map[string]int{}
	for _, v := range rc.received {
		if e, ok := v["event"].(map[string]any); ok {
			out[e["type"].(string)]++
		}
	}
	return out
}

func TestPostgresIngestRelayIntegrityAndOutboundWebhooks(t *testing.T) {
	databaseURL := os.Getenv("SCRS_TEST_DATABASE_URL")
	redisURL := os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := strings.Repeat("a", 40)
	if _, err := store.SyncBootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	c := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := store.Put(ctx, c, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Discover(ctx, "gh", fixtureInventory{}); err != nil {
		t.Fatal(err)
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
	events.PrivateHosts = map[string]bool{"127.0.0.1": true}
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	secret := strings.Repeat("h", 40)
	build := func(relay bool) http.Handler {
		return HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Notify: events, GitHubWebhookSecret: secret, RelayEnabled: relay})
	}
	handler := build(true)
	call := func(h http.Handler, method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	must := func(w *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
		t.Helper()
		if w.Code != status {
			t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body)
		}
		return w
	}
	signed := func(event, body string) map[string]string {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(body))
		return map[string]string{"X-GitHub-Event": event, "X-GitHub-Delivery": uuid.NewString(), "X-Hub-Signature-256": "sha256=" + hex.EncodeToString(mac.Sum(nil))}
	}
	relayed := func(event string) map[string]string {
		return map[string]string{"X-GitHub-Event": event, "X-GitHub-Delivery": uuid.NewString()}
	}

	// Outbound subscription API: URL policy, one-time secret, revisioned updates.
	rc := &receiver{status: 200}
	sink := httptest.NewServer(rc)
	defer sink.Close()
	must(call(handler, "POST", "/webhooks", admin, `{"name":"bad","url":"http://example.com/hook","events":["integrity.alert"]}`, nil), 400)
	must(call(handler, "POST", "/webhooks", admin, `{"name":"bad","url":"https://10.0.0.5/hook","events":["integrity.alert"]}`, nil), 400)
	must(call(handler, "POST", "/webhooks", admin, `{"name":"bad","url":"`+sink.URL+`","events":["assessment.completed"],"profile":"agent"}`, nil), 400)
	w := must(call(handler, "POST", "/webhooks", admin, `{"name":"n8n","url":"`+sink.URL+`","events":["assessment.completed","assessment.failed","finding.created","integrity.alert","finding.status_changed"],"profile":"agent","egress_ack":true}`, nil), 201)
	var created struct {
		Secret       string              `json:"secret"`
		Subscription notify.Subscription `json:"subscription"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || !strings.HasPrefix(created.Secret, "whsec_") {
		t.Fatal("subscription secret not issued", err, w.Body)
	}
	subPath := "/webhooks/" + created.Subscription.ID.String()
	if strings.Contains(must(call(handler, "GET", "/webhooks", admin, "", nil), 200).Body.String(), created.Secret) {
		t.Fatal("subscription list leaked secret")
	}
	must(call(handler, "PATCH", subPath, admin, `{"profile":"summary"}`, nil), 428)
	must(call(handler, "PATCH", subPath, admin, `{"profile":"summary"}`, map[string]string{"If-Match": `"99"`}), 409)
	must(call(handler, "PATCH", subPath, admin, `{"profile":"full"}`, map[string]string{"If-Match": `"1"`}), 200)
	_, reader, err := store.CreateToken(ctx, connections.Token{Name: "reader", Scopes: []string{"read"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	must(call(handler, "GET", "/webhooks", reader, "", nil), 403)

	// Relay: ingest:relay token, disabled switch, scope enforcement, idempotent replay.
	_, relayToken, err := store.CreateToken(ctx, connections.Token{Name: "n8n-relay", Scopes: []string{"ingest:relay"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	push := `{"ref":"refs/heads/main","after":"` + strings.Repeat("a", 40) + `","created":true,"repository":{"full_name":"org/api","default_branch":"main"},"pusher":{"name":"dev"}}`
	must(call(build(false), "POST", "/ingest/github", relayToken, push, relayed("push")), 503)
	must(call(handler, "POST", "/ingest/github", reader, push, relayed("push")), 403)
	headers := relayed("push")
	w = must(call(handler, "POST", "/ingest/github", relayToken, push, headers), 202)
	var queued assessments.Assessment
	if err := json.Unmarshal(w.Body.Bytes(), &queued); err != nil || queued.Request.Trigger.Origin != "github_relay" || queued.Request.Trigger.Actor != "dev" {
		t.Fatal("relay request not normalized", err, w.Body)
	}
	must(call(handler, "POST", "/ingest/github", relayToken, push, headers), 200)
	var mode string
	if err := pool.QueryRow(ctx, "SELECT mode FROM "+schema+".inbound_events WHERE assessment_id=$1", queued.ID).Scan(&mode); err != nil || mode != "relay" {
		t.Fatal("relay mode not recorded", err, mode)
	}
	// Direct mode on the same endpoint selects HMAC by the signature header.
	must(call(handler, "POST", "/ingest/github", "", push, map[string]string{"X-GitHub-Event": "push", "X-GitHub-Delivery": uuid.NewString(), "X-Hub-Signature-256": "sha256=00"}), 401)

	// Integrity signals: force push to the default branch, churn, campaign patterns.
	forced := strings.Replace(push, `"created":true`, `"forced":true`, 1)
	forced = strings.Replace(forced, strings.Repeat("a", 40), strings.Repeat("b", 40), 1)
	must(call(handler, "POST", "/ingest/github", "", forced, signed("push", forced)), 202)
	var severity string
	if err := pool.QueryRow(ctx, "SELECT severity FROM "+schema+".findings WHERE advisory_id='SCRS-EVENT-FORCE-PUSH'").Scan(&severity); err != nil || severity != "critical" {
		t.Fatal("force push to default branch not raised as critical", err, severity)
	}
	deleted := `{"ref":"main","ref_type":"branch","repository":{"full_name":"org/api"},"sender":{"login":"dev"}}`
	h := signed("delete", deleted)
	must(call(handler, "POST", "/webhooks/github", "", deleted, h), 200)
	must(call(handler, "POST", "/webhooks/github", "", deleted, h), 200) // replay is a no-op
	var kinds []string
	rows, err := pool.Query(ctx, "SELECT kind FROM "+schema+".integrity_events ORDER BY kind")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		kinds = append(kinds, k)
	}
	rows.Close()
	if strings.Join(kinds, ",") != "branch_churn,force_push,ref_deleted" {
		t.Fatal("unexpected integrity events", kinds)
	}
	bundle := `{"version":"wfx-loot","indicators":[{"id":"probe-title","type":"pr_title_regex","value":"(?i)dependency audit","valid_until":"2099-01-01T00:00:00Z"},{"id":"probe-branch","type":"git_branch_regex","value":"^wfx-docs$","valid_until":"2099-01-01T00:00:00Z"}]}`
	if _, err := jobs.ImportIndicators(ctx, uuid.Nil, []byte(bundle)); err != nil {
		t.Fatal(err)
	}
	pr := `{"action":"opened","pull_request":{"number":7,"title":"docs: dependency audit notes","head":{"ref":"wfx-docs","sha":"` + strings.Repeat("c", 40) + `"},"base":{"ref":"main"}},"repository":{"full_name":"org/api"},"sender":{"login":"stranger"}}`
	w = must(call(handler, "POST", "/webhooks/github", "", pr, signed("pull_request", pr)), 202)
	var prJob assessments.Assessment
	if err := json.Unmarshal(w.Body.Bytes(), &prJob); err != nil || prJob.Request.Target.Ref != "pull/7" || prJob.Request.Target.PullRequest.BaseRef != "main" {
		t.Fatal("PR assessment not queued against head commit", err, w.Body)
	}
	var patterns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".integrity_events WHERE kind LIKE 'pattern_%' AND severity='critical'").Scan(&patterns); err != nil || patterns != 2 {
		t.Fatal("campaign patterns not matched", err, patterns)
	}
	tag := `{"ref":"refs/tags/v1","after":"` + strings.Repeat("d", 40) + `","repository":{"full_name":"org/api"}}`
	must(call(handler, "POST", "/webhooks/github", "", tag, signed("push", tag)), 200)
	outside := strings.Replace(push, "org/api", "other/repo", 1)
	if !strings.Contains(must(call(handler, "POST", "/webhooks/github", "", outside, signed("push", outside)), 200).Body.String(), "ignored_out_of_scope") {
		t.Fatal("out-of-scope push not acknowledged")
	}
	must(call(handler, "POST", "/webhooks/github", "", `{}`, signed("watch", `{}`)), 200)

	// Completion emits assessment.completed and finding.created in the same transaction.
	for {
		a, err := jobs.Claim(ctx)
		if err != nil {
			break
		}
		result := assessments.Result{Commit: strings.Repeat("e", 40), Complete: true, Findings: []assessments.Finding{{Type: "vulnerability", AdvisoryID: "GHSA-test", Title: "Synthetic", Severity: "high", Score: 45, Component: assessments.Component{PURL: "pkg:npm/x@1.0.0"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{"fixed_versions":["1.0.1"]}`)}}}
		if a.Request.Target.PullRequest != nil {
			result.Commit = a.Request.Target.Commit
		}
		if err := jobs.Complete(ctx, a, result); err != nil {
			t.Fatal(err)
		}
	}
	// The context document honours the agent safeguards.
	doc, err := jobs.ContextDocument(ctx, prJob.ID, "agent", false)
	if err != nil {
		t.Fatal(err)
	}
	var contextDoc struct {
		Notice    string           `json:"instructions_notice"`
		Untrusted []string         `json:"untrusted_paths"`
		Findings  []map[string]any `json:"findings"`
		Revision  map[string]any   `json:"revision"`
	}
	if err := json.Unmarshal(doc, &contextDoc); err != nil || contextDoc.Notice == "" || len(contextDoc.Untrusted) == 0 || len(contextDoc.Findings) != 1 || contextDoc.Findings[0]["change"] != "existing" { // already on the base branch
		t.Fatal("agent context incomplete", err, string(doc))
	}
	must(call(handler, "GET", "/assessments/"+prJob.ID.String()+"/context?profile=agent", reader, "", nil), 200)
	must(call(handler, "GET", "/assessments/"+prJob.ID.String()+"/context?profile=raw", reader, "", nil), 400)

	// TRG-007/011, INT-017: latest by commit, filters, batch per-item results, last known good.
	w = must(call(handler, "GET", "/assessments/latest?repository=org/api&commit="+strings.Repeat("c", 40), reader, "", nil), 200)
	if !strings.Contains(w.Body.String(), prJob.ID.String()) {
		t.Fatal("latest did not return the PR assessment", w.Body)
	}
	must(call(handler, "GET", "/assessments/latest?repository=org/api&commit="+strings.Repeat("f", 40), reader, "", nil), 404)
	w = must(call(handler, "GET", "/assessments?ref=pull/7&actor=stranger", reader, "", nil), 200)
	if !strings.Contains(w.Body.String(), prJob.ID.String()) {
		t.Fatal("ref/actor filter failed", w.Body)
	}
	must(call(handler, "GET", "/assessments?created_after=yesterday", reader, "", nil), 400)
	must(call(handler, "GET", "/assessments/"+prJob.ID.String()+"?wait=0", reader, "", nil), 200)
	must(call(handler, "GET", "/assessments/"+prJob.ID.String()+"?wait=61", reader, "", nil), 400)
	_, triggerToken, err := store.CreateToken(ctx, connections.Token{Name: "batcher", Scopes: []string{"trigger"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	w = must(call(handler, "POST", "/assessments:batch", triggerToken, `{"items":[{"idempotency_key":"b1","request":{"target":{"type":"git","repository":"org/api","ref":"main"}}},{"idempotency_key":"b2","request":{"target":{"type":"git","repository":"outside/repo"}}}]}`, nil), 207)
	var batch struct {
		Items []struct {
			Status int    `json:"status"`
			Error  string `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &batch); err != nil || len(batch.Items) != 2 || batch.Items[0].Status != 202 || batch.Items[1].Status != 404 {
		t.Fatal("batch per-item results wrong", err, w.Body)
	}
	must(call(handler, "POST", "/assessments:batch", reader, `{"items":[]}`, nil), 403)
	must(call(handler, "POST", "/assessments:batch", triggerToken, `{"items":[]}`, nil), 400)
	must(call(handler, "GET", "/assets/"+prJob.AssetID.String()+"/last-known-good?ref=main", reader, "", nil), 404)

	// M1: owners, asset attributes, request ids and metrics.
	_, writer, err := store.CreateToken(ctx, connections.Token{Name: "writer", Scopes: []string{"write"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	must(call(handler, "POST", "/owners", reader, `{"name":"Platform"}`, nil), 403)
	must(call(handler, "POST", "/owners", writer, `{"name":"Platform","email":"not-an-email"}`, nil), 400)
	w = must(call(handler, "POST", "/owners", writer, `{"name":"Platform","team":"platform","email":"platform@example.com"}`, nil), 201)
	var owner connections.Owner
	_ = json.Unmarshal(w.Body.Bytes(), &owner)
	must(call(handler, "POST", "/owners", writer, `{"name":"Platform"}`, nil), 409)
	assetPath := "/assets/" + prJob.AssetID.String()
	must(call(handler, "PATCH", assetPath, writer, `{"environment":"prod"}`, nil), 428)
	must(call(handler, "PATCH", assetPath, writer, `{"environment":"production"}`, map[string]string{"If-Match": `"1"`}), 400)
	must(call(handler, "PATCH", assetPath, writer, `{"labels":{"Bad Key":"x"}}`, map[string]string{"If-Match": `"1"`}), 400)
	must(call(handler, "PATCH", assetPath, writer, `{"owner_id":"`+uuid.NewString()+`"}`, map[string]string{"If-Match": `"1"`}), 400)
	w = must(call(handler, "PATCH", assetPath, writer, `{"owner_id":"`+owner.ID.String()+`","environment":"prod","criticality":5,"exposure":"internet","labels":{"tier":"payments"}}`, map[string]string{"If-Match": `"1"`}), 200)
	if !strings.Contains(w.Body.String(), `"criticality":5`) {
		t.Fatal("asset attributes not saved", w.Body)
	}
	must(call(handler, "PATCH", assetPath, writer, `{"criticality":1}`, map[string]string{"If-Match": `"1"`}), 409)
	must(call(handler, "PATCH", assetPath, reader, `{"criticality":1}`, map[string]string{"If-Match": `"2"`}), 403)
	if !strings.Contains(must(call(handler, "GET", assetPath, reader, "", nil), 200).Body.String(), owner.ID.String()) {
		t.Fatal("asset owner not readable")
	}
	full, err := jobs.ContextDocument(ctx, prJob.ID, "full", false)
	if err != nil || !strings.Contains(string(full), `"team":"platform"`) || strings.Contains(string(full), "platform@example.com") {
		t.Fatal("owner context or contact exclusion wrong", err)
	}
	w = must(call(handler, "POST", "/assessments", triggerToken, `{"target":{"type":"git","repository":"org/api","ref":"develop"}}`, map[string]string{"X-Request-Id": "n8n-exec-12345"}), 202)
	if w.Header().Get("X-Request-Id") != "n8n-exec-12345" || !strings.Contains(w.Body.String(), `"request_id":"n8n-exec-12345"`) {
		t.Fatal("request id not propagated", w.Header(), w.Body)
	}
	if id := must(call(handler, "GET", "/system/healthz", "", "", map[string]string{"X-Request-Id": "bad id with spaces"}), 200).Header().Get("X-Request-Id"); id == "" || strings.Contains(id, " ") {
		t.Fatal("unsafe request id echoed", id)
	}
	var findingID uuid.UUID
	// M7: OpenVEX reflects register triage; trigger tokens may read their own.
	if err := pool.QueryRow(ctx, "SELECT finding_id FROM "+schema+".assessment_findings WHERE assessment_id=$1", prJob.ID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Transition(ctx, findingID, uuid.Nil, "false_positive", "not reachable in our build", nil); err != nil {
		t.Fatal(err)
	}
	w = must(call(handler, "GET", "/assessments/"+prJob.ID.String()+"/vex", reader, "", nil), 200)
	var vex struct {
		Context    string           `json:"@context"`
		Statements []map[string]any `json:"statements"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &vex); err != nil || vex.Context != "https://openvex.dev/ns/v0.2.0" || len(vex.Statements) != 1 || vex.Statements[0]["status"] != "not_affected" || !strings.Contains(vex.Statements[0]["impact_statement"].(string), "not reachable") {
		t.Fatal("VEX export wrong", err, w.Body)
	}
	if err := jobs.Transition(ctx, findingID, uuid.Nil, "open", "reopened after VEX check", nil); err != nil {
		t.Fatal(err)
	}

	// M5: inbound event log with actor view, replay, retention classes and maintenance.
	w = must(call(handler, "GET", "/events/inbound?actor=stranger", admin, "", nil), 200)
	var inbound struct {
		Items []assessments.InboundEvent `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &inbound); err != nil || len(inbound.Items) == 0 {
		t.Fatal("actor view of inbound events empty", err, w.Body)
	}
	must(call(handler, "GET", "/events/inbound", reader, "", nil), 403)
	var replayable uuid.UUID
	for _, e := range inbound.Items {
		if e.AssessmentID != nil {
			replayable = e.ID
		}
	}
	w = must(call(handler, "POST", "/events/inbound/"+replayable.String()+":replay", admin, "", nil), 202)
	if !strings.Contains(w.Body.String(), `"origin":"replay"`) {
		t.Fatal("replay did not create a new assessment", w.Body)
	}
	w = must(call(handler, "GET", "/settings/retention", admin, "", nil), 200)
	etag := w.Header().Get("ETag")
	must(call(handler, "PUT", "/settings/retention", admin, `{"inbound_event_days":0,"webhook_delivery_days":30}`, map[string]string{"If-Match": etag}), 200)
	if _, err := pool.Exec(ctx, "INSERT INTO "+schema+".webhook_deliveries(id,subscription_id,event_id,event_type,payload,status,created_at) VALUES(gen_random_uuid(),$1,gen_random_uuid(),'ping','{}','delivered',now()-interval '31 days')", created.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".assessment_idempotency SET expires_at=now()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	must(call(handler, "POST", "/maintenance/run", reader, "", nil), 403)
	w = must(call(handler, "POST", "/maintenance/run", admin, "", nil), 200)
	var report assessments.MaintenanceReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || report.WebhookDeliveries == 0 || report.IdempotencyKeys == 0 {
		t.Fatal("maintenance did not apply retention", err, w.Body)
	}
	var remainingFindings int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".findings").Scan(&remainingFindings); err != nil || remainingFindings == 0 {
		t.Fatal("maintenance touched findings", err)
	}
	// Drain the queue so the rescan sees no pending default-branch job.
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".assessments SET status='cancelled' WHERE status IN ('queued','running')"); err != nil {
		t.Fatal(err)
	}
	first, err := jobs.EnqueueRescans(ctx, time.Hour, 10)
	if err != nil || first != 1 {
		t.Fatal("scheduled rescan not queued", err, first)
	}
	if again, err := jobs.EnqueueRescans(ctx, time.Hour, 10); err != nil || again != 0 {
		t.Fatal("rescan not idempotent within its window", err, again)
	}
	must(call(handler, "POST", "/maintenance/redeliver-dead", admin, "", nil), 202)

	must(call(handler, "GET", "/system/metrics", "", "", nil), 401)
	metricsBody := must(call(handler, "GET", "/system/metrics", reader, "", nil), 200).Body.String()
	for _, name := range []string{`scrs_assessment_queue_depth{status="queued"}`, `scrs_trigger_requests_total{mode="trigger",result="2xx"}`, `scrs_assessment_verdict_total{verdict="incomplete"}`, `scrs_webhook_deliveries{status="pending"}`, "scrs_store_up 1"} {
		if !strings.Contains(metricsBody, name) {
			t.Fatal("metric missing: "+name, metricsBody[:min(len(metricsBody), 2000)])
		}
	}

	// Dispatcher: signed delivery, profile document, retries, dead letter, redelivery.
	d := &notify.Dispatcher{Store: events, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Document: jobs.ProfileDocument}
	if err := d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got := rc.types()
	if got["integrity.alert"] < 4 || got["assessment.completed"] < 2 || got["finding.created"] < 1 {
		t.Fatal("expected events not delivered", got)
	}
	rc.mu.Lock()
	for i, body := range rc.bodies {
		if !notify.Verify(created.Secret, body, rc.headers[i].Get("X-SCRS-Signature")) || rc.headers[i].Get("Idempotency-Key") == "" {
			rc.mu.Unlock()
			t.Fatal("delivery signature or idempotency key invalid")
		}
		if e := rc.received[i]["event"].(map[string]any); e["type"] == "assessment.completed" && e["profile"] != "full" {
			rc.mu.Unlock()
			t.Fatal("profile document not applied", e)
		}
	}
	rc.mu.Unlock()
	var pending int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".webhook_deliveries WHERE status<>'delivered'").Scan(&pending); err != nil || pending != 0 {
		t.Fatal("deliveries not settled", err, pending)
	}
	rc.mu.Lock()
	rc.status = 500
	rc.mu.Unlock()
	if err := jobs.Transition(ctx, findingID, uuid.Nil, "triaged", "reviewed by test", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var deliveryID uuid.UUID
	var attempts, lastStatus int
	if err := pool.QueryRow(ctx, "SELECT id,attempts,last_status FROM "+schema+".webhook_deliveries WHERE event_type='finding.status_changed' AND status='pending'").Scan(&deliveryID, &attempts, &lastStatus); err != nil || attempts != 1 || lastStatus != 500 {
		t.Fatal("failed delivery not scheduled for retry", err, attempts, lastStatus)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".webhook_deliveries SET attempts=7,next_attempt_at=now() WHERE id=$1", deliveryID); err != nil {
		t.Fatal(err)
	}
	if err := d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	w = must(call(handler, "GET", subPath+"/deliveries?status=dead", admin, "", nil), 200)
	if !strings.Contains(w.Body.String(), deliveryID.String()) {
		t.Fatal("exhausted delivery not dead-lettered", w.Body)
	}
	rc.mu.Lock()
	rc.status = 204
	rc.mu.Unlock()
	must(call(handler, "POST", subPath+"/deliveries/"+deliveryID.String()+":redeliver", admin, "", nil), 202)
	must(call(handler, "POST", subPath+":test", admin, "", nil), 202)
	if err := d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := pool.QueryRow(ctx, "SELECT status FROM "+schema+".webhook_deliveries WHERE id=$1", deliveryID).Scan(&status); err != nil || status != "delivered" {
		t.Fatal("redelivery failed", err, status)
	}
	if rc.types()["ping"] != 1 {
		t.Fatal("test ping not delivered")
	}

	// SSRF: a hostname resolving to loopback is refused at dial time unless allow-listed.
	strict, err := notify.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Close()
	strict.PrivateHosts = map[string]bool{"127.0.0.1": true} // permits creation only
	u, _ := url.Parse(sink.URL)
	sub, _, err := strict.Create(ctx, notify.Subscription{Name: "rebind", URL: "https://localhost:" + u.Port(), Events: []string{"ping"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Ping(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	strict.PrivateHosts = map[string]bool{}
	before := len(rc.types())
	if err := (&notify.Dispatcher{Store: strict, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var lastError string
	if err := pool.QueryRow(ctx, "SELECT last_error FROM "+schema+".webhook_deliveries WHERE subscription_id=$1", sub.ID).Scan(&lastError); err != nil || lastError != "connection failed" || len(rc.types()) != before {
		t.Fatal("loopback destination was not refused", err, lastError)
	}
}
