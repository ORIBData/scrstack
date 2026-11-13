package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
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

type staticInventory []connections.Resource

func (s staticInventory) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return s, nil
}

type memoryBundles map[string][]byte

func (m memoryBundles) OpenMirror(_ context.Context, key string) (io.ReadCloser, int64, error) {
	return io.NopCloser(bytes.NewReader(m[key])), int64(len(m[key])), nil
}

// GitLab ingest, registry push events, Trivy/SARIF import and git mirrors
// against PostgreSQL, through the real router and authorization.
func TestPostgresGitLabRegistryImportAndMirrors(t *testing.T) {
	databaseURL, redisURL := os.Getenv("SCRS_TEST_DATABASE_URL"), os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	gitlabSecret := strings.Repeat("g", 40)
	t.Setenv("SCRS_GITLAB_WEBHOOK_SECRET", gitlabSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	// Migrations are idempotent: a second bootstrap must not fail.
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal("re-bootstrap", err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := strings.Repeat("a", 40)
	if _, err := store.SyncBootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		conn       connections.Connection
		credential string
		inventory  staticInventory
	}{
		{connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}, `{"token":"t"}`, staticInventory{{Type: "github_repo", Locator: "org/api"}}},
		{connections.Connection{Name: "gl", Provider: "gitlab", Config: json.RawMessage(`{"group":"team","base_url":"https://gitlab.example.com"}`), Scope: connections.Scope{Include: []string{"team/**"}}}, `{"token":"t"}`, staticInventory{{Type: "gitlab_repo", Locator: "team/platform/app"}}},
		{connections.Connection{Name: "hb", Provider: "harbor", Config: json.RawMessage(`{"url":"https://harbor.example.com","project":"apps","username":"robot$scrs"}`), Scope: connections.Scope{Include: []string{"harbor.example.com/apps/*"}}}, `{"token":"t"}`, staticInventory{{Type: "container_image", Locator: "harbor.example.com/apps/web"}}},
		{connections.Connection{Name: "dh", Provider: "dockerhub", Config: json.RawMessage(`{"namespace":"acme","identifier":"bot"}`), Scope: connections.Scope{Include: []string{"docker.io/acme/*"}}}, `{"token":"t"}`, staticInventory{{Type: "container_image", Locator: "docker.io/acme/api"}}},
		{connections.Connection{Name: "reg", Provider: "oci", Config: json.RawMessage(`{"registry":"reg.example.com","repositories":["apps/tool"]}`), Scope: connections.Scope{Include: []string{"reg.example.com/**"}}}, `{}`, staticInventory{{Type: "container_image", Locator: "reg.example.com/apps/tool"}}},
	} {
		if _, err := store.Put(ctx, c.conn, json.RawMessage(c.credential), false); err != nil {
			t.Fatal("provider rejected by schema", c.conn.Provider, err)
		}
		if _, err := store.Discover(ctx, c.conn.Name, c.inventory); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	bundles := memoryBundles{}
	build := func(relay bool) http.Handler {
		return HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Mirrors: bundles, RelayEnabled: relay})
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
	decode := func(w *httptest.ResponseRecorder, v any) {
		t.Helper()
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
			t.Fatal(err, w.Body)
		}
	}
	_, relayToken, err := store.CreateToken(ctx, connections.Token{Name: "relay", Scopes: []string{"ingest:relay"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	_, writer, err := store.CreateToken(ctx, connections.Token{Name: "ci", Scopes: []string{"write"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := store.CreateToken(ctx, connections.Token{Name: "ro", Scopes: []string{"read"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}

	// GitLab direct: shared token, nested group path, provider-pinned target.
	zero, sha := strings.Repeat("0", 40), strings.Repeat("c", 40)
	gitlab := func(token, event, body string) map[string]string {
		return map[string]string{"X-Gitlab-Token": token, "X-Gitlab-Event": event, "X-Gitlab-Event-UUID": uuid.NewString()}
	}
	created := `{"object_kind":"push","ref":"refs/heads/tmp","before":"` + zero + `","after":"` + sha + `","user_username":"dev","project":{"path_with_namespace":"team/platform/app","default_branch":"main"},"commits":[]}`
	must(call(handler, "POST", "/ingest/gitlab", "", created, gitlab("wrong", "Push Hook", created)), 401)
	var queued assessments.Assessment
	decode(must(call(handler, "POST", "/ingest/gitlab", "", created, gitlab(gitlabSecret, "Push Hook", created)), 202), &queued)
	if queued.Request.Target.Provider != "gitlab" || queued.Request.Target.Repository != "team/platform/app" || queued.Request.Trigger.Origin != "gitlab_direct" {
		t.Fatal("GitLab push not normalized", queued.Request)
	}
	deleted := `{"object_kind":"push","ref":"refs/heads/tmp","before":"` + sha + `","after":"` + zero + `","user_username":"dev","project":{"path_with_namespace":"team/platform/app","default_branch":"main"},"commits":[]}`
	var outcome struct {
		Status  string `json:"status"`
		Signals int    `json:"integrity_signals"`
	}
	decode(must(call(handler, "POST", "/ingest/gitlab", "", deleted, gitlab(gitlabSecret, "Push Hook", deleted)), 200), &outcome)
	if outcome.Signals != 2 {
		t.Fatal("GitLab branch deletion should raise ref_deleted and branch_churn", outcome)
	}
	mr := `{"object_kind":"merge_request","user":{"username":"dev"},"project":{"path_with_namespace":"team/platform/app"},"object_attributes":{"iid":9,"title":"feat","source_branch":"feat","target_branch":"main","action":"open","last_commit":{"id":"` + sha + `"}}}`
	decode(must(call(handler, "POST", "/ingest/gitlab", relayToken, mr, map[string]string{"X-Gitlab-Event": "Merge Request Hook", "X-Gitlab-Event-UUID": uuid.NewString(), "X-Gitlab-Token": gitlabSecret}), 202), &queued)
	if queued.Request.Target.PullRequest == nil || queued.Request.Target.Ref != "pull/9" || queued.Request.Trigger.Origin != "gitlab_relay" {
		t.Fatal("GitLab merge request not normalized", queued.Request)
	}

	// Registry push events: relay token only, digest pinning, idempotent replay.
	digest := "sha256:" + strings.Repeat("d", 64)
	harbor := `{"type":"PUSH_ARTIFACT","event_data":{"resources":[{"digest":"` + digest + `","tag":"1.0","resource_url":"harbor.example.com/apps/web:1.0"}],"repository":{"repo_full_name":"apps/web"}}}`
	must(call(build(false), "POST", "/ingest/registry/harbor", relayToken, harbor, nil), 503)
	must(call(handler, "POST", "/ingest/registry/harbor", writer, harbor, nil), 403)
	must(call(handler, "POST", "/ingest/registry/quay", relayToken, harbor, nil), 404)
	var pushed struct {
		Items []struct {
			Status       string    `json:"status"`
			AssessmentID uuid.UUID `json:"assessment_id"`
		} `json:"items"`
	}
	decode(must(call(handler, "POST", "/ingest/registry/harbor", relayToken, harbor, nil), 202), &pushed)
	first := pushed.Items[0].AssessmentID
	a, err := jobs.Get(ctx, first)
	if err != nil || a.Request.Target.Commit != digest || a.Request.Target.Type != "image" {
		t.Fatal("harbor push not pinned to digest", a.Request, err)
	}
	decode(must(call(handler, "POST", "/ingest/registry/harbor", relayToken, harbor, nil), 200), &pushed)
	if pushed.Items[0].Status != "replayed" || pushed.Items[0].AssessmentID != first {
		t.Fatal("registry retry created a duplicate", pushed)
	}
	decode(must(call(handler, "POST", "/ingest/registry/dockerhub", relayToken, `{"push_data":{"tag":"v2"},"repository":{"repo_name":"acme/api"}}`, nil), 202), &pushed)
	decode(must(call(handler, "POST", "/ingest/registry/dockerhub", relayToken, `{"push_data":{"tag":"v2"},"repository":{"repo_name":"stranger/api"}}`, nil), 200), &pushed)
	if pushed.Items[0].Status != "ignored_out_of_scope" {
		t.Fatal("undiscovered image scanned", pushed)
	}

	// Imports: Trivy into the register and gate; secrets never stored.
	commit := strings.Repeat("e", 40)
	trivy := func(misconfig bool) string {
		results := `{"Target":"package-lock.json","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-9","PkgName":"lodash","InstalledVersion":"4.17.0","FixedVersion":"4.17.21","Severity":"CRITICAL","Title":"pp","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.0"}}]},{"Target":".env","Secrets":[{"RuleID":"aws-access-key-id","Severity":"HIGH","Title":"AWS key","StartLine":2,"Match":"AKIAIOSFODNN7EXAMPLE"}]}`
		if misconfig {
			results += `,{"Target":"Dockerfile","Misconfigurations":[{"ID":"DS002","Title":"root","Severity":"HIGH","Status":"FAIL"}]}`
		}
		return `{"target":{"type":"git","repository":"org/api","ref":"main","commit":"` + commit + `"},"format":"trivy","report":{"SchemaVersion":2,"Results":[` + results + `]}}`
	}
	must(call(handler, "POST", "/assessments:import", reader, trivy(true), nil), 403)
	must(call(handler, "POST", "/assessments:import", writer, `{"target":{"type":"git","repository":"org/api","ref":"main"},"format":"trivy","report":{"SchemaVersion":2}}`, nil), 400)
	w := must(call(handler, "POST", "/assessments:import", writer, trivy(true), map[string]string{"Idempotency-Key": "imp-1"}), 201)
	var imported assessments.Assessment
	decode(w, &imported)
	if imported.Status != "succeeded" || imported.Verdict != "fail" || imported.Request.Import == nil || imported.Request.Import.Tool != "trivy" || len(imported.Stages) != 1 || imported.Stages[0].Name != "import" {
		t.Fatal("Trivy import not recorded", imported)
	}
	must(call(handler, "POST", "/assessments:import", writer, trivy(true), map[string]string{"Idempotency-Key": "imp-1"}), 200)
	findings := must(call(handler, "GET", "/assessments/"+imported.ID.String()+"/findings", reader, "", nil), 200).Body.String()
	if strings.Contains(findings, "AKIA") || !strings.Contains(findings, "DS002") || !strings.Contains(findings, "CVE-2024-9") {
		t.Fatal("import findings wrong or secret leaked", findings)
	}
	if _, err := jobs.Claim(ctx); err == nil {
		// Claimable work exists from ingest above; none of it may be an import.
		var imports int
		_ = pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".assessments WHERE request->'import' IS NOT NULL AND status<>'succeeded'").Scan(&imports)
		if imports != 0 {
			t.Fatal("import left claimable")
		}
	}
	// A newer Trivy import without the misconfiguration closes it, but never
	// closes the shared vulnerability type.
	must(call(handler, "POST", "/assessments:import", writer, trivy(false), nil), 201)
	var misconfig, vuln string
	_ = pool.QueryRow(ctx, "SELECT status FROM "+schema+".findings WHERE advisory_id='DS002'").Scan(&misconfig)
	_ = pool.QueryRow(ctx, "SELECT status FROM "+schema+".findings WHERE advisory_id='CVE-2024-9'").Scan(&vuln)
	if misconfig != "fixed" || vuln != "open" {
		t.Fatal("import closure wrong", misconfig, vuln)
	}
	sarif := `{"target":{"type":"git","repository":"org/api","ref":"main","commit":"` + commit + `"},"format":"sarif","report":{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","rules":[{"id":"r1","properties":{"security-severity":"7.5"}}]}},"results":[{"ruleId":"r1","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":3}}}]}]}]}}`
	decode(must(call(handler, "POST", "/assessments:import", writer, sarif, nil), 201), &imported)
	if imported.Verdict != "warn" || imported.Request.Import.Tool != "semgrep" {
		t.Fatal("SARIF high finding should warn", imported.Verdict, imported.Request.Import)
	}
	// The internal import marker cannot be injected through a normal trigger.
	decode(must(call(handler, "POST", "/assessments", writer, `{"target":{"type":"git","repository":"org/api","ref":"main"},"import":{"format":"trivy","tool":"x"}}`, nil), 202), &queued)
	if queued.Request.Import != nil || queued.Status != "queued" {
		t.Fatal("import marker injected", queued.Request)
	}
	// Imports never serve as a scan baseline or last-known-good.
	must(call(handler, "GET", "/assets/"+imported.AssetID.String()+"/last-known-good?ref=main", reader, "", nil), 404)

	// Mirrors: queue, dedupe, scope, claim, prune and verified download.
	var gh, img uuid.UUID
	_ = pool.QueryRow(ctx, "SELECT id FROM "+schema+".assets WHERE locator='org/api'").Scan(&gh)
	_ = pool.QueryRow(ctx, "SELECT id FROM "+schema+".assets WHERE locator='docker.io/acme/api'").Scan(&img)
	must(call(handler, "POST", "/assets/"+gh.String()+"/mirrors", reader, "", nil), 403)
	must(call(handler, "POST", "/assets/"+img.String()+"/mirrors", writer, "", nil), 404)
	var m assessments.Mirror
	decode(must(call(handler, "POST", "/assets/"+gh.String()+"/mirrors", writer, "", nil), 202), &m)
	var again assessments.Mirror
	decode(must(call(handler, "POST", "/assets/"+gh.String()+"/mirrors", writer, "", nil), 200), &again)
	if again.ID != m.ID || m.Status != "queued" {
		t.Fatal("duplicate mirror queued", m, again)
	}
	keys := []string{}
	for i := 0; i < 2; i++ {
		if i > 0 {
			must(call(handler, "POST", "/assets/"+gh.String()+"/mirrors", writer, "", nil), 202)
		}
		claimed, err := jobs.ClaimMirror(ctx)
		if err != nil || claimed.Locator != "org/api" {
			t.Fatal("mirror claim", claimed, err)
		}
		objectKey := "mirrors/" + claimed.ID.String() + ".bundle"
		bundles[objectKey] = []byte("# v2 git bundle\n")
		pruned, err := jobs.FinishMirror(ctx, claimed, &assessments.Mirror{ObjectKey: objectKey, SHA256: strings.Repeat("f", 64), SizeBytes: int64(len(bundles[objectKey])), Refs: 3}, "", 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jobs.FinishMirror(ctx, claimed, nil, "late", 1); err != assessments.ErrLease {
			t.Fatal("finished mirror accepted a second result", err)
		}
		keys = append(keys, objectKey)
		if i == 1 && (len(pruned) != 1 || pruned[0] != keys[0]) {
			t.Fatal("older bundle not pruned", pruned)
		}
	}
	var listed struct {
		Items []assessments.Mirror `json:"items"`
	}
	decode(must(call(handler, "GET", "/assets/"+gh.String()+"/mirrors", reader, "", nil), 200), &listed)
	if len(listed.Items) != 2 || listed.Items[0].Status != "succeeded" || listed.Items[1].Status != "pruned" {
		t.Fatal("mirror history", listed)
	}
	latest := listed.Items[0].ID.String()
	must(call(handler, "GET", "/assets/"+gh.String()+"/mirrors/"+latest+"/bundle", writer, "", nil), 403)
	w = must(call(handler, "GET", "/assets/"+gh.String()+"/mirrors/"+latest+"/bundle", admin, "", nil), 200)
	if w.Header().Get("X-Content-SHA256") != strings.Repeat("f", 64) || w.Header().Get("Content-Type") != "application/x-git-bundle" {
		t.Fatal("bundle headers", w.Header())
	}
	must(call(handler, "GET", "/assets/"+gh.String()+"/mirrors/"+listed.Items[1].ID.String()+"/bundle", admin, "", nil), 409)
	if n, err := jobs.ScheduleMirrors(ctx, time.Hour); err != nil || n != 0 {
		t.Fatal("unlabelled assets scheduled", n, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".assets SET labels='{\"mirror\":\"true\"}' WHERE id=$1", gh); err != nil {
		t.Fatal(err)
	}
	if n, err := jobs.ScheduleMirrors(ctx, time.Hour); err != nil || n != 0 {
		t.Fatal("fresh mirror rescheduled", n, err)
	}
	if n, err := jobs.ScheduleMirrors(ctx, time.Nanosecond); err != nil || n != 1 {
		t.Fatal("stale labelled mirror not scheduled", n, err)
	}
}
