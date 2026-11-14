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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/intelligence"
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
	_, triggerOnly, err := store.CreateToken(ctx, connections.Token{Name: "n8n", Scopes: []string{"trigger"}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}

	// INT-001 backstop: the GitHub delivery check is readable with read and
	// runnable with admin; a missing SCRS webhook degrades the connection.
	hooks := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, GitHubHooks: missingHook{}})
	must(call(hooks, "POST", "/system/github-webhooks:check", reader, "", nil), 403)
	var checked struct{ Items []connections.HookCheck }
	decode(must(call(hooks, "POST", "/system/github-webhooks:check", admin, "", nil), 200), &checked)
	if len(checked.Items) != 1 || checked.Items[0].Connection != "gh" || checked.Items[0].State != "degraded" {
		t.Fatal("delivery check run", checked.Items)
	}
	checked.Items = nil
	decode(must(call(hooks, "GET", "/system/github-webhooks", reader, "", nil), 200), &checked)
	if len(checked.Items) != 1 || checked.Items[0].State != "degraded" || !strings.Contains(strings.Join(checked.Items[0].Problems, ";"), "no organization webhook") {
		t.Fatal("delivery check state", checked.Items)
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
	// GitLab retries reuse Idempotency-Key (not a UUID) while recursive hooks
	// share X-Gitlab-Event-UUID: the key decides.
	other := strings.Replace(created, sha, strings.Repeat("9", 40), 1)
	shared := uuid.NewString()
	retry := map[string]string{"X-Gitlab-Token": gitlabSecret, "X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": shared, "Idempotency-Key": strings.Repeat("ab", 32)}
	must(call(handler, "POST", "/ingest/gitlab", "", other, retry), 202)
	must(call(handler, "POST", "/ingest/gitlab", "", other, retry), 200)
	third := strings.Replace(created, sha, strings.Repeat("8", 40), 1)
	must(call(handler, "POST", "/ingest/gitlab", "", third, map[string]string{"X-Gitlab-Token": gitlabSecret, "X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": shared, "Idempotency-Key": strings.Repeat("cd", 32)}), 202)
	must(call(handler, "POST", "/ingest/gitlab", "", third, map[string]string{"X-Gitlab-Token": gitlabSecret, "X-Gitlab-Event": "Push Hook"}), 400)
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
	replace := "false"
	trivy := func(misconfig bool) string {
		results := `{"Target":"package-lock.json","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-9","PkgName":"lodash","InstalledVersion":"4.17.0","FixedVersion":"4.17.21","Severity":"CRITICAL","Title":"pp","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.17.0"}}]},{"Target":".env","Secrets":[{"RuleID":"aws-access-key-id","Severity":"HIGH","Title":"AWS key","StartLine":2,"Match":"AKIAIOSFODNN7EXAMPLE"}]}`
		if misconfig {
			results += `,{"Target":"Dockerfile","Misconfigurations":[{"ID":"DS002","Title":"root","Severity":"HIGH","Status":"FAIL"}]}`
		}
		return `{"target":{"type":"git","repository":"org/api","ref":"main","commit":"` + commit + `"},"format":"trivy","replace_previous":` + replace + `,"report":{"SchemaVersion":2,"Results":[` + results + `]}}`
	}
	status := func(advisory string) string {
		var v string
		_ = pool.QueryRow(ctx, "SELECT status FROM "+schema+".findings WHERE advisory_id=$1", advisory).Scan(&v)
		return v
	}
	must(call(handler, "POST", "/assessments:import", reader, trivy(true), nil), 403)
	// replace_previous closes findings: a trigger-only token may import but not close.
	replace = "true"
	must(call(handler, "POST", "/assessments:import", triggerOnly, trivy(true), nil), 403)
	replace = "false"
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
	// A partial Trivy run (no misconfiguration scan) must not mark the
	// earlier misconfiguration fixed.
	must(call(handler, "POST", "/assessments:import", writer, trivy(false), nil), 201)
	if status("DS002") != "open" {
		t.Fatal("partial import closed another scanner's finding", status("DS002"))
	}
	// A complete SCRS scan of the ref never closes imported findings: SCRS
	// and Trivy name the same issue differently.
	scan := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/api", Ref: "main", Commit: commit}}
	if _, _, err := jobs.Enqueue(ctx, scan, uuid.New(), "qa", ""); err != nil {
		t.Fatal(err)
	}
	for {
		claimed, err := jobs.Claim(ctx)
		if err != nil {
			break
		}
		if claimed.Request.Target.Repository != "org/api" {
			_ = jobs.Fail(ctx, claimed, "not under test", false)
			continue
		}
		sbom := assessments.Hash([]byte("sbom"))
		var all []assessments.Stage
		for _, n := range []string{"resolve", "fetch", "inventory", "sbom", "match_vuln", "match_malicious", "malware", "yara", "ioc", "integrity"} {
			all = append(all, assessments.Stage{Name: n, Status: "ok"})
		}
		if err := jobs.Complete(ctx, claimed, assessments.Result{Commit: commit, Stages: all, Components: []assessments.Component{{Name: "x", PURL: "pkg:npm/x@1"}}, SBOMKey: "sbom/" + sbom + ".cdx.json", SBOMSHA256: sbom}); err != nil {
			t.Fatal(err)
		}
	}
	if status("CVE-2024-9") != "open" || status("aws-access-key-id") != "open" {
		t.Fatal("SCRS scan closed imported findings", status("CVE-2024-9"), status("aws-access-key-id"))
	}
	// Declared complete, the next Trivy import closes what it no longer reports.
	replace = "true"
	must(call(handler, "POST", "/assessments:import", writer, trivy(false), nil), 201)
	if status("DS002") != "fixed" || status("CVE-2024-9") != "open" {
		t.Fatal("replace_previous closure wrong", status("DS002"), status("CVE-2024-9"))
	}
	replace = "false"
	sarif := `{"target":{"type":"git","repository":"org/api","ref":"main","commit":"` + commit + `"},"format":"sarif","report":{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","rules":[{"id":"r1","properties":{"security-severity":"7.5"}}]}},"results":[{"ruleId":"r1","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":3}}}]}]}]}}`
	decode(must(call(handler, "POST", "/assessments:import", writer, sarif, nil), 201), &imported)
	if imported.Verdict != "warn" || imported.Request.Import.Tool != "semgrep" {
		t.Fatal("SARIF high finding should warn", imported.Verdict, imported.Request.Import)
	}
	// Callers cannot claim origins SCRS assigns to provider events.
	must(call(handler, "POST", "/assessments", writer, `{"target":{"type":"git","repository":"org/api","ref":"main"},"trigger":{"origin":"github_direct"}}`, nil), 400)
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
		pruned, err := jobs.FinishMirror(ctx, claimed, &assessments.Mirror{ObjectKey: objectKey, SHA256: strings.Repeat("f", 64), SizeBytes: int64(len(bundles[objectKey])), Refs: 3}, "", 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jobs.FinishMirror(ctx, claimed, nil, "late", 1, 0); err != assessments.ErrLease {
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
	// Backups survive repeated mirroring of a compromised repository: a bundle
	// is pruned only beyond keep AND older than the age floor, and the newest
	// bundle taken before an open integrity entry is never pruned.
	mirrorOnce := func(minAgeDays int) (uuid.UUID, []string) {
		t.Helper()
		must(call(handler, "POST", "/assets/"+gh.String()+"/mirrors", writer, "", nil), 202)
		claimed, err := jobs.ClaimMirror(ctx)
		if err != nil {
			t.Fatal(err)
		}
		key := "mirrors/" + claimed.ID.String() + ".bundle"
		pruned, err := jobs.FinishMirror(ctx, claimed, &assessments.Mirror{ObjectKey: key, SHA256: strings.Repeat("e", 64), SizeBytes: 1, Refs: 1}, "", 1, minAgeDays)
		if err != nil {
			t.Fatal(err)
		}
		return claimed.ID, pruned
	}
	backdate := func(id uuid.UUID, days int) {
		t.Helper()
		if _, err := pool.Exec(ctx, "UPDATE "+schema+".asset_mirrors SET created_at=clock_timestamp()-($2*interval '1 day') WHERE id=$1", id, days); err != nil {
			t.Fatal(err)
		}
	}
	clean := listed.Items[0].ID
	backdate(clean, 60)
	incident := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO "+schema+".findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,first_seen) VALUES($1,$2,$3,'main','integrity','SCRS-EVENT-FORCE-PUSH','Force push','critical',100,'{}','{}','{}',clock_timestamp()-interval '50 days')", incident, gh, "fp-"+incident.String()); err != nil {
		t.Fatal(err)
	}
	if _, pruned := mirrorOnce(30); len(pruned) != 0 {
		t.Fatal("pre-incident backup pruned", pruned)
	}
	afterIncident, _ := mirrorOnce(30)
	if _, pruned := mirrorOnce(30); len(pruned) != 0 {
		t.Fatal("bundle younger than the age floor pruned", pruned)
	}
	backdate(afterIncident, 40)
	if _, pruned := mirrorOnce(30); len(pruned) != 1 || pruned[0] != "mirrors/"+afterIncident.String()+".bundle" {
		t.Fatal("old post-incident bundle not pruned", pruned)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".findings SET status='fixed' WHERE asset_id=$1 AND type='integrity'", gh); err != nil {
		t.Fatal(err)
	}
	if _, pruned := mirrorOnce(30); len(pruned) != 1 || pruned[0] != "mirrors/"+clean.String()+".bundle" {
		t.Fatal("protection outlived the integrity entry", pruned)
	}
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
	// A mirror whose worker died is released even when nothing else is
	// queued, so the asset can be mirrored again.
	dead, err := jobs.ClaimMirror(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".asset_mirrors SET lease_until=clock_timestamp()-interval '1 minute' WHERE id=$1", dead.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.ClaimMirror(ctx); err != assessments.ErrNotFound {
		t.Fatal("expected empty queue", err)
	}
	if got, err := jobs.GetMirror(ctx, gh, dead.ID); err != nil || got.Status != "failed" {
		t.Fatal("expired mirror still blocks its asset", got.Status, err)
	}
	must(call(handler, "POST", "/assets/"+gh.String()+"/mirrors", writer, "", nil), 202)

	// TIF YARA rulesets: write manages hunt rulesets, admin promotes them.
	compiler := func(_ context.Context, rules string) ([]intelligence.Diagnostic, error) {
		if strings.Contains(rules, "BROKEN") {
			return nil, &intelligence.RuleError{Diagnostics: []intelligence.Diagnostic{{Level: "error", Message: "unknown pattern", Line: 2, Column: 3}}}
		}
		return []intelligence.Diagnostic{}, nil
	}
	intel := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, ValidateRules: compiler})
	rule := func(name, mode, rules string) string {
		body, _ := json.Marshal(map[string]any{"name": name, "mode": mode, "rules": rules, "kind": "external", "origin": map[string]string{"vendor": "YARA Forge", "url": "https://yarahq.github.io/", "license": "DRL-1.1"}})
		return string(body)
	}
	valid := "rule Env_Exfil { strings: $a = \"printenv | base64\" condition: $a }"
	must(call(intel, "POST", "/intel/yara-rulesets", reader, rule("team_hunt", "", valid), nil), 403)
	must(call(intel, "POST", "/intel/yara-rulesets", writer, rule("team_block", "block", valid), nil), 403)
	failed := must(call(intel, "POST", "/intel/yara-rulesets", writer, rule("team_hunt", "", "rule A {\n BROKEN }"), nil), 422).Body.String()
	if !strings.Contains(failed, `"line":2`) {
		t.Fatal("compile errors are located", failed)
	}
	must(call(intel, "POST", "/intel/yara-rulesets:validate", writer, `{"rules":"rule A { condition: true }"}`, nil), 200)
	var ruleset assessments.RuleSetRecord
	decode(must(call(intel, "POST", "/intel/yara-rulesets", writer, rule("team_hunt", "", valid), nil), 201), &ruleset)
	if ruleset.Mode != "hunt" || !ruleset.Enabled || ruleset.RuleCount != 1 || ruleset.Rules != "" || ruleset.Origin.License != "DRL-1.1" {
		t.Fatalf("new rulesets hunt: %+v", ruleset)
	}
	must(call(intel, "POST", "/intel/yara-rulesets", writer, rule("team_hunt", "", valid), nil), 409)
	must(call(intel, "POST", "/intel/yara-rulesets", writer, rule("Bad-Name", "", valid), nil), 400)
	if !strings.Contains(must(call(intel, "GET", "/intel/yara-rulesets/"+ruleset.ID.String(), reader, "", nil), 200).Body.String(), "printenv") {
		t.Fatal("a ruleset is readable with its rules")
	}
	item := "/intel/yara-rulesets/" + ruleset.ID.String()
	revision := map[string]string{"If-Match": `"1"`}
	must(call(intel, "PATCH", item, writer, `{"mode":"alert"}`, revision), 403)
	must(call(intel, "PATCH", item, admin, `{"mode":"alert"}`, nil), 428)
	decode(must(call(intel, "PATCH", item, admin, `{"mode":"alert","severity":"high"}`, revision), 200), &ruleset)
	must(call(intel, "PATCH", item, admin, `{"enabled":false}`, revision), 409)
	// Once a ruleset gates verdicts, write tokens cannot change or delete it.
	must(call(intel, "PATCH", item, writer, `{"description":"x"}`, map[string]string{"If-Match": `"2"`}), 403)
	must(call(intel, "DELETE", item, writer, "", nil), 403)
	pack, err := jobs.ActiveRulePack(ctx)
	if err != nil || !strings.Contains(string(pack), `"mode":"alert"`) || !strings.Contains(string(pack), `"name":"team_hunt"`) {
		t.Fatal("enabled rulesets form the scan pack", string(pack), err)
	}
	if queued := must(call(intel, "POST", item+":hunt", writer, "", nil), 202).Body.String(); !strings.Contains(queued, "rescans_queued") {
		t.Fatal("retro-hunt queues rescans", queued)
	}
	must(call(intel, "PATCH", item, admin, `{"enabled":false}`, map[string]string{"If-Match": `"2"`}), 200)
	must(call(intel, "POST", item+":hunt", writer, "", nil), 409)
	if pack, err := jobs.ActiveRulePack(ctx); err != nil || pack != nil {
		t.Fatal("disabled rulesets are not sent to the scanner", string(pack), err)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action='yara_ruleset.mode_changed' AND target_id=$1`, ruleset.ID).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("promotion is audited", audited, err)
	}
	must(call(intel, "DELETE", item, admin, "", nil), 204)
	must(call(intel, "GET", item, reader, "", nil), 404)

	// TIF indicator sources follow the ruleset permission model.
	must(call(intel, "POST", "/intel/indicator-sources", reader, `{"name":"partner_feed"}`, nil), 403)
	must(call(intel, "POST", "/intel/indicator-sources", writer, `{"name":"partner_feed","mode":"block"}`, nil), 403)
	must(call(intel, "POST", "/intel/indicator-sources", writer, `{"name":"partner_feed","kind":"taxii"}`, nil), 400)
	var source assessments.IndicatorSource
	decode(must(call(intel, "POST", "/intel/indicator-sources", writer, `{"name":"partner_feed","min_confidence":60,"origin":{"vendor":"Partner CERT","url":"https://cert.example/feed"}}`, nil), 201), &source)
	if source.Mode != "hunt" || source.Severity != "high" || !source.Enabled || source.IndicatorCount != 0 {
		t.Fatalf("new sources hunt: %+v", source)
	}
	sourcePath := "/intel/indicator-sources/" + source.ID.String()
	indicators := `{"version":"2026-11-14","indicators":[{"id":"drop","type":"url","value":"hxxps://evil[.]example/drop.sh","confidence":90,"valid_until":"2099-01-01T00:00:00Z"}]}`
	must(call(intel, "PUT", sourcePath+"/indicators", reader, indicators, nil), 403)
	must(call(intel, "PUT", sourcePath+"/indicators", writer, `{"version":"x","indicators":[{"id":"a","type":"url","value":"ftp:/x","valid_until":"2099-01-01T00:00:00Z"}]}`, nil), 400)
	must(call(intel, "PUT", sourcePath+"/indicators", writer, strings.Replace(indicators, `"confidence":90`, `"mode":"block"`, 1), nil), 400)
	decode(must(call(intel, "PUT", sourcePath+"/indicators", writer, indicators, nil), 200), &source)
	if source.IndicatorCount != 1 || source.Version != "2026-11-14" || source.Revision != 2 {
		t.Fatalf("import not recorded: %+v", source)
	}
	if listed := must(call(intel, "GET", sourcePath+"/indicators", reader, "", nil), 200).Body.String(); !strings.Contains(listed, `"value":"https://evil.example/drop.sh"`) {
		t.Fatal("indicators are listed normalized", listed)
	}
	must(call(intel, "GET", sourcePath+"/elsewhere", reader, "", nil), 404)
	must(call(intel, "PATCH", sourcePath, writer, `{"mode":"alert"}`, map[string]string{"If-Match": `"2"`}), 403)
	must(call(intel, "PATCH", sourcePath, admin, `{"mode":"alert","severity":"critical"}`, map[string]string{"If-Match": `"1"`}), 409)
	decode(must(call(intel, "PATCH", sourcePath, admin, `{"mode":"alert","severity":"critical"}`, map[string]string{"If-Match": `"2"`}), 200), &source)
	// Once a source gates verdicts, write tokens cannot import into, change or delete it.
	must(call(intel, "PUT", sourcePath+"/indicators", writer, indicators, nil), 403)
	must(call(intel, "DELETE", sourcePath, writer, "", nil), 403)
	if scan, err := jobs.ScanIndicators(ctx); err != nil || !strings.Contains(string(scan), `"source":"partner_feed","mode":"alert","severity":"critical"`) {
		t.Fatal("alert source missing from the scan bundle", string(scan), err)
	}
	must(call(intel, "POST", sourcePath+":hunt", writer, "", nil), 202)
	// Enabling a source past the scan bundle limit is refused.
	var big strings.Builder
	big.WriteString(`{"version":"big","indicators":[`)
	for n := range intelligence.MaxImportIndicators {
		if n > 0 {
			big.WriteByte(',')
		}
		big.WriteString(`{"id":"` + strconv.Itoa(n) + `","type":"domain","value":"h` + strconv.Itoa(n) + `.example","valid_until":"2099-01-01T00:00:00Z"}`)
	}
	big.WriteString(`]}`)
	// With partner_feed's indicator, the second import would pass 100000.
	for _, step := range []struct {
		name   string
		status int
	}{{"bulk_one", 200}, {"bulk_two", 422}} {
		var bulk assessments.IndicatorSource
		decode(must(call(intel, "POST", "/intel/indicator-sources", writer, `{"name":"`+step.name+`"}`, nil), 201), &bulk)
		must(call(intel, "PUT", "/intel/indicator-sources/"+bulk.ID.String()+"/indicators", writer, big.String(), nil), step.status)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action='indicator_source.mode_changed' AND target_id=$1`, source.ID).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("source promotion is audited", audited, err)
	}
	must(call(intel, "DELETE", sourcePath, admin, "", nil), 204)
	must(call(intel, "GET", sourcePath, reader, "", nil), 404)
}

// missingHook is a GitHub organization without a webhook pointing at SCRS.
type missingHook struct{}

func (missingHook) GitHubHooks(context.Context, connections.Connection, json.RawMessage, string, time.Time) ([]connections.GitHubHook, error) {
	return []connections.GitHubHook{{Source: "org", Problems: []string{"no organization webhook points at SCRS"}}}, nil
}

func (missingHook) RedeliverGitHub(context.Context, connections.Connection, json.RawMessage, connections.GitHubHook, int64) error {
	return nil
}
