package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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

// Inbound automation (n8n trigger mode): an external service triggers an
// assessment of a permitted asset with its own context, and receives that
// context back in the signed assessment.completed event. Also covers the
// manufacturing BOM of the completed revision.
func TestPostgresAutomationTriggerRoundTripAndMBOM(t *testing.T) {
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
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
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
	c := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}, Exclude: []string{"org/secret"}}}
	if _, err := store.Put(ctx, c, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Discover(ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}, {Type: "github_repo", Locator: "org/secret"}}); err != nil {
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
	events.PrivateHosts = map[string]bool{"n8n": true}
	if _, _, err := events.Create(ctx, notify.Subscription{Name: "n8n", URL: "http://n8n/webhook/scrs-events", Events: []string{"assessment.completed"}}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Notify: events, TrustedProxies: nil})
	call := func(remote, method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = remote + ":1234"
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
	const n8nIP = "198.51.100.7"
	_, trigger, err := store.CreateToken(ctx, connections.Token{Name: "n8n-trigger", Scopes: []string{"trigger"}, Networks: []string{"198.51.100.0/24"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	_, relay, err := store.CreateToken(ctx, connections.Token{Name: "n8n-relay", Scopes: []string{"ingest:relay"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("f", 40)
	event := `{"target":{"type":"git","repository":"org/api","ref":"main","commit":"` + commit + `"},"trigger":{"origin":"n8n","event":"release.requested","delivery_id":"exec-4711","actor":"release-bot","context":{"ticket":"CHG-1042","n8n.execution":"4711","environment":"prod"}}}`

	// Secured: unknown token, wrong network, wrong scope.
	must(call(n8nIP, "POST", "/assessments", "", event, nil), 401)
	must(call("203.0.113.9", "POST", "/assessments", trigger, event, nil), 401)
	must(call(n8nIP, "POST", "/assessments", relay, event, nil), 403)
	// Permitted: only discovered, in-scope assets; bounded context.
	must(call(n8nIP, "POST", "/assessments", trigger, strings.Replace(event, "org/api", "org/secret", 1), nil), 404)
	must(call(n8nIP, "POST", "/assessments", trigger, strings.Replace(event, "org/api", "other/repo", 1), nil), 404)
	must(call(n8nIP, "POST", "/assessments", trigger, strings.Replace(event, `"environment":"prod"`, `"Bad Key":"x"`, 1), nil), 400)
	must(call(n8nIP, "POST", "/assessments", trigger, strings.Replace(event, `"environment":"prod"`, `"environment":"a\nb"`, 1), nil), 400)

	w := must(call(n8nIP, "POST", "/assessments", trigger, event, map[string]string{"Idempotency-Key": "exec-4711"}), 202)
	var queued assessments.Assessment
	if err := json.Unmarshal(w.Body.Bytes(), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.Request.Trigger.Context["ticket"] != "CHG-1042" || queued.Request.Trigger.Origin != "n8n" || w.Header().Get("Location") == "" {
		t.Fatal("trigger context not recorded", queued.Request.Trigger)
	}
	// n8n retries are safe; a changed body under the same key is rejected.
	if must(call(n8nIP, "POST", "/assessments", trigger, event, map[string]string{"Idempotency-Key": "exec-4711"}), 200).Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("replay not flagged")
	}
	must(call(n8nIP, "POST", "/assessments", trigger, strings.Replace(event, "CHG-1042", "CHG-9", 1), map[string]string{"Idempotency-Key": "exec-4711"}), 409)
	var mode string
	if err := pool.QueryRow(ctx, "SELECT mode FROM "+schema+".inbound_events WHERE assessment_id=$1", queued.ID).Scan(&mode); err != nil || mode != "trigger" {
		t.Fatal("inbound event not logged", err, mode)
	}
	must(call(n8nIP, "GET", "/assessments/"+queued.ID.String()+"/mbom", trigger, "", nil), 409)

	// Complete it as a worker would, then check the outbound event and MBOM.
	a, err := jobs.Claim(ctx)
	if err != nil || a.ID != queued.ID {
		t.Fatal("claim", err)
	}
	sbom := []byte(`{"bomFormat":"CycloneDX"}`)
	digest := assessments.Hash(sbom)
	files := []assessments.FileEvidence{{Path: ".github/workflows/release.yml", SHA256: strings.Repeat("1", 64), Malware: "clean"}, {Path: "Dockerfile", SHA256: strings.Repeat("2", 64), Malware: "clean"}, {Path: "go.sum", SHA256: strings.Repeat("3", 64), Malware: "clean"}, {Path: "main.go", SHA256: strings.Repeat("4", 64), Malware: "clean"}}
	stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "malware", Status: "ok", Detail: "ClamAV 1.5.4/28178/Mon Nov  9 06:24:16 2026"}}
	if err := jobs.Complete(ctx, a, assessments.Result{Commit: commit, Files: files, Stages: stages, SBOMKey: "sbom/" + digest + ".cdx.json", SBOMSHA256: digest}); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := pool.QueryRow(ctx, "SELECT payload FROM "+schema+".webhook_deliveries WHERE event_type='assessment.completed'").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var delivered struct {
		Data struct {
			Assessment struct {
				ID      uuid.UUID `json:"id"`
				Trigger struct {
					DeliveryID string            `json:"delivery_id"`
					Context    map[string]string `json:"context"`
				} `json:"trigger"`
			} `json:"assessment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &delivered); err != nil || delivered.Data.Assessment.ID != queued.ID || delivered.Data.Assessment.Trigger.DeliveryID != "exec-4711" || delivered.Data.Assessment.Trigger.Context["n8n.execution"] != "4711" {
		t.Fatal("completion event lacks the caller's context", err, string(payload))
	}

	body := must(call(n8nIP, "GET", "/assessments/"+queued.ID.String()+"/mbom", trigger, "", nil), 200)
	if body.Header().Get("Content-Type") != "application/vnd.cyclonedx+json" {
		t.Fatal("MBOM content type", body.Header())
	}
	var mbom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Lifecycles []struct{ Phase string } `json:"lifecycles"`
			Component  struct {
				Type, PURL string
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name   string                     `json:"name"`
			Hashes []struct{ Content string } `json:"hashes"`
		} `json:"components"`
		Formulation []struct {
			Workflows []struct {
				ResourceReferences []struct{ Ref string } `json:"resourceReferences"`
			} `json:"workflows"`
		} `json:"formulation"`
	}
	if dump := os.Getenv("SCRS_TEST_MBOM_OUT"); dump != "" {
		_ = os.WriteFile(dump, body.Body.Bytes(), 0600)
	}
	if err := json.Unmarshal(body.Body.Bytes(), &mbom); err != nil {
		t.Fatal(err)
	}
	if mbom.BOMFormat != "CycloneDX" || mbom.SpecVersion != "1.6" || mbom.Metadata.Lifecycles[0].Phase != "build" || mbom.Metadata.Component.PURL != "pkg:github/org/api@"+commit {
		t.Fatal("MBOM header", mbom.Metadata)
	}
	if len(mbom.Components) != 3 || mbom.Components[0].Name != ".github/workflows/release.yml" || len(mbom.Formulation[0].Workflows[0].ResourceReferences) != 3 {
		t.Fatal("MBOM build inputs should be the workflow, Dockerfile and go.sum only", mbom.Components)
	}
}
