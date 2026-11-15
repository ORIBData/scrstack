package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/advisory"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// memoryObjects records deleted object keys.
type memoryObjects struct{ deleted []string }

func (m *memoryObjects) DeleteObject(_ context.Context, key string) error {
	m.deleted = append(m.deleted, key)
	return nil
}

// M4 and M5 remainder through the real router: CSV indicators, VEX and
// advisory lookup, the source registry, retention classes with legal hold,
// maintenance actions, the audit query and event schemas.
func TestPostgresAdvisoriesRetentionAndMaintenance(t *testing.T) {
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
	store, err := connections.Open(ctx, databaseURL, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
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
	if _, err := store.Discover(ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}, {Type: "github_repo", Locator: "org/held"}}); err != nil {
		t.Fatal(err)
	}
	asset := map[string]uuid.UUID{}
	for _, name := range []string{"org/api", "org/held"} {
		var id uuid.UUID
		_ = pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator=$1`, name).Scan(&id)
		asset[name] = id
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	objects := &memoryObjects{}
	jobs.UseObjects(objects)
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs})
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
	decode := func(w *httptest.ResponseRecorder, v any) {
		t.Helper()
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
			t.Fatal(err, w.Body)
		}
	}
	_, writer, _ := store.CreateToken(ctx, connections.Token{Name: "ci", Scopes: []string{"write"}}, uuid.Nil)
	_, reader, _ := store.CreateToken(ctx, connections.Token{Name: "ro", Scopes: []string{"read"}}, uuid.Nil)

	// CSV indicators into a manual hunt source.
	var src assessments.IndicatorSource
	decode(must(call("POST", "/intel/indicator-sources", writer, `{"name":"vendor_csv","kind":"manual","mode":"hunt"}`, nil), 201), &src)
	csvBody := "ioc,kind,campaign\n2001:db8::dead,ip,Loot\nevil.example,domain,Loot\nbroken,md5,\n"
	var imported struct {
		Source assessments.IndicatorSource `json:"source"`
		Report struct{ Accepted, Skipped int }
	}
	decode(must(call("POST", "/intel/indicator-sources/"+src.ID.String()+":import-csv?value_column=ioc&type_column=kind&label_column=campaign", writer, csvBody, map[string]string{"Content-Type": "text/csv"}), 200), &imported)
	if imported.Source.IndicatorCount != 2 || imported.Report.Accepted != 2 || imported.Report.Skipped != 1 {
		t.Fatalf("csv import %+v", imported)
	}
	decode(must(call("POST", "/intel/indicator-sources/"+src.ID.String()+":import-csv?merge=true&type=sha256", writer, "value\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n", nil), 200), &imported)
	if imported.Source.IndicatorCount != 3 {
		t.Fatalf("merge kept %d", imported.Source.IndicatorCount)
	}
	must(call("POST", "/intel/indicator-sources/"+src.ID.String()+":import-csv?delimiter=pipe", writer, "value\nx\n", nil), 400)

	// Source registry: seeded, managed sources refuse changes, NVD can be rescheduled.
	var sources struct{ Items []assessments.VulnSource }
	decode(must(call("GET", "/intel/vulnerability-sources", reader, "", nil), 200), &sources)
	keys := map[string]assessments.VulnSource{}
	for _, v := range sources.Items {
		keys[v.Key] = v
	}
	if len(keys) != 7 || keys["nvd"].ManagedBy != "worker" || keys["osv"].ManagedBy != "feed-sync" || keys["epss"].Licence == "" {
		t.Fatalf("sources %+v", keys)
	}
	must(call("PATCH", "/intel/vulnerability-sources/osv", admin, `{"enabled":false}`, map[string]string{"If-Match": `"1"`}), 409)
	must(call("PATCH", "/intel/vulnerability-sources/nvd", writer, `{"schedule_minutes":60}`, map[string]string{"If-Match": `"1"`}), 403)
	if body := must(call("PATCH", "/intel/vulnerability-sources/nvd", admin, `{"schedule_minutes":60}`, map[string]string{"If-Match": `"1"`}), 200).Body.String(); !strings.Contains(body, `"schedule_minutes":60`) {
		t.Fatal(body)
	}
	must(call("POST", "/intel/vulnerability-sources/nvd:sync", admin, "", nil), 202)
	must(call("POST", "/intel/vulnerability-sources/kev:sync", admin, "", nil), 409)

	// VEX: import, duplicate, lookup joined with advisory records.
	raw, _ := advisory.ParseCVE5([]byte(`{"cveMetadata":{"cveId":"CVE-2021-44228","state":"PUBLISHED","datePublished":"2021-12-10T00:00:00Z","dateUpdated":"2025-02-04T00:00:00Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Log4Shell"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-502"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10,"baseSeverity":"CRITICAL"}}]}}}`))
	if err := jobs.SaveAdvisoryRecords(ctx, []advisory.Raw{raw}); err != nil {
		t.Fatal(err)
	}
	vex := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme.example/vex/1","author":"Acme","timestamp":"2026-11-01T00:00:00Z","statements":[{"vulnerability":{"name":"CVE-2021-44228"},"products":[{"@id":"pkg:maven/org.apache.logging.log4j/log4j-core"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`
	must(call("POST", "/intel/vex-documents", reader, vex, nil), 403)
	var doc assessments.VEXDocument
	decode(must(call("POST", "/intel/vex-documents", writer, vex, nil), 201), &doc)
	must(call("POST", "/intel/vex-documents", writer, vex, nil), 409)
	must(call("POST", "/intel/vex-documents", writer, `{"bomFormat":"SPDX"}`, nil), 400)
	var view assessments.AdvisoryView
	decode(must(call("GET", "/intel/vulnerabilities/cve-2021-44228?purl=pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", reader, "", nil), 200), &view)
	if len(view.Records) != 1 || len(view.SeveritySources) != 1 || view.CWE[0] != "CWE-502" || len(view.Statements) != 1 || view.Statements[0].Publisher != "Acme" || view.Statements[0].Status != "not_affected" {
		t.Fatalf("vulnerability view %+v", view)
	}
	decode(must(call("GET", "/intel/vulnerabilities/CVE-2021-44228?purl=pkg:npm/other@1", reader, "", nil), 200), &view)
	if len(view.Statements) != 0 {
		t.Fatal("statement leaked to another product")
	}
	must(call("GET", "/intel/vulnerabilities/CVE-2099-0001", reader, "", nil), 404)
	if body := must(call("GET", "/intel/vex-statements?vulnerability=CVE-2021-44228", reader, "", nil), 200).Body.String(); !strings.Contains(body, "log4j-core") {
		t.Fatal(body)
	}
	must(call("DELETE", "/intel/vex-documents/"+doc.ID.String(), writer, "", nil), 403)
	must(call("DELETE", "/intel/vex-documents/"+doc.ID.String(), admin, "", nil), 204)

	// Retention classes: old closed findings on both assets; one is on legal hold.
	for name, id := range asset {
		fp := assessments.Hash([]byte(name))
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,status,component,evidence,guidance,last_seen) VALUES($1,$2,$3,'main','vulnerability','CVE-2021-44228','x','high',45,'fixed','{}','{}','{}',now()-interval '400 days')`, uuid.New(), id, fp); err != nil {
			t.Fatal(err)
		}
	}
	var heldAsset connections.Asset
	decode(must(call("GET", "/assets/"+asset["org/held"].String(), admin, "", nil), 200), &heldAsset)
	must(call("PATCH", "/assets/"+asset["org/held"].String(), writer, `{"legal_hold":true}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, heldAsset.Revision)}), 403)
	must(call("PATCH", "/assets/"+asset["org/held"].String(), admin, `{"legal_hold":true}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, heldAsset.Revision)}), 200)
	var policy assessments.Retention
	decode(must(call("GET", "/settings/retention", admin, "", nil), 200), &policy)
	if len(policy.Classes) != 11 {
		t.Fatalf("classes %+v", policy.Classes)
	}
	if body := must(call("POST", "/settings/retention:preview", admin, `{"classes":{"closed_findings":30,"audit_log":null}}`, nil), 200).Body.String(); !strings.Contains(body, `"closed_findings":1`) {
		t.Fatal("legal hold not excluded from preview", body)
	}
	must(call("PUT", "/settings/retention", admin, `{"classes":{"audit_log":100}}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, policy.Revision)}), 400)
	must(call("PUT", "/settings/retention", admin, `{"classes":{"nope":1}}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, policy.Revision)}), 400)
	decode(must(call("PUT", "/settings/retention", admin, `{"classes":{"closed_findings":30,"audit_log":400}}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, policy.Revision)}), 200), &policy)
	for _, c := range policy.Classes {
		if c.Class == "closed_findings" && (c.EffectiveDays != 30 || c.Source != "policy") {
			t.Fatalf("class %+v", c)
		}
	}
	var purge struct{ Purged map[string]int64 }
	decode(must(call("POST", "/settings/retention:purge", admin, "", map[string]string{"If-Match": fmt.Sprintf(`"%d"`, policy.Revision)}), 200), &purge)
	var left int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.findings`).Scan(&left)
	if purge.Purged["closed_findings"] != 1 || left != 1 {
		t.Fatalf("purge %+v left %d", purge, left)
	}

	// Maintenance actions.
	must(call("POST", "/maintenance/reset", admin, `{"scope":"asset_findings","asset_id":"`+asset["org/held"].String()+`","confirm":"nope"}`, nil), 400)
	must(call("POST", "/maintenance/reset", admin, `{"scope":"asset_findings","asset_id":"`+asset["org/held"].String()+`","confirm":"asset_findings"}`, nil), 409)
	if body := must(call("POST", "/maintenance/reset", admin, `{"scope":"feed_state","confirm":"feed_state"}`, nil), 200).Body.String(); !strings.Contains(body, `"vulnerability_sources":2`) {
		t.Fatal(body)
	}
	if body := must(call("POST", "/maintenance/reset", admin, `{"scope":"indicators","source_id":"`+src.ID.String()+`","confirm":"indicators"}`, nil), 200).Body.String(); !strings.Contains(body, `"indicators":3`) {
		t.Fatal(body)
	}
	must(call("POST", "/maintenance/rebuild", admin, "", nil), 202)
	if body := must(call("POST", "/maintenance/update-sensors", admin, "", nil), 202).Body.String(); !strings.Contains(body, `"advisory_sources":2`) {
		t.Fatal(body)
	}
	if err := jobs.RecordJob(ctx, "maintenance", time.Hour, time.Now(), nil, map[string]int{"x": 1}); err != nil {
		t.Fatal(err)
	}
	if body := must(call("GET", "/maintenance/schedule", admin, "", nil), 200).Body.String(); !strings.Contains(body, `"job":"maintenance"`) || !strings.Contains(body, `"job":"source:nvd"`) {
		t.Fatal(body)
	}
	if body := must(call("GET", "/maintenance/versions", admin, "", nil), 200).Body.String(); !strings.Contains(body, `"go":"go`) {
		t.Fatal(body)
	}

	// Audit query.
	var audit struct {
		Items []assessments.AuditEntry
		Next  string `json:"next_cursor"`
	}
	must(call("GET", "/audit", writer, "", nil), 403)
	decode(must(call("GET", "/audit?action=maintenance.*", admin, "", nil), 200), &audit)
	actions := map[string]bool{}
	for _, e := range audit.Items {
		actions[e.Action] = true
	}
	if !actions["maintenance.reset"] || !actions["maintenance.rebuild"] || !actions["maintenance.update_sensors"] || actions["retention.purged"] {
		t.Fatalf("audit actions %v", actions)
	}
	decode(must(call("GET", "/audit?action=retention.purged&limit=1", admin, "", nil), 200), &audit)
	if len(audit.Items) != 1 || audit.Next == "" {
		t.Fatalf("audit page %+v", audit)
	}
	must(call("GET", "/audit?since=yesterday", admin, "", nil), 400)

	// Event schemas.
	if body := must(call("GET", "/schemas/events", reader, "", nil), 200).Body.String(); !strings.Contains(body, "finding.rescored") || !strings.Contains(body, "malicious_dependency.reported") {
		t.Fatal(body)
	}
	if body := must(call("GET", "/schemas/events/finding.rescored/1", reader, "", nil), 200).Body.String(); !strings.Contains(body, `"previous_severity"`) {
		t.Fatal(body)
	}
	must(call("GET", "/schemas/events/finding.rescored/2", reader, "", nil), 404)
}
