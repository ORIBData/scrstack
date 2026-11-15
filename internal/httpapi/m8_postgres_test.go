package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/compliance"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/sbom"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// memoryArtifacts serves stored SBOMs and reports by key.
type memoryArtifacts map[string][]byte

func (m memoryArtifacts) GetSBOM(_ context.Context, key string) ([]byte, error) {
	if b, ok := m[key]; ok {
		return b, nil
	}
	return nil, errors.New("missing")
}
func (m memoryArtifacts) GetReport(ctx context.Context, key string) ([]byte, error) {
	return m.GetSBOM(ctx, key)
}

// M8 through the real router: licence policy and categories with If-Match
// and admin scope, dry-run evaluation, asset distribution, licence
// inventory, report and notices, SBOM export formats (SBM-011), framework
// packs, and report jobs with download.
func TestPostgresLicenceAndComplianceAPI(t *testing.T) {
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
	if _, err := store.Discover(ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/app"}, {Type: "github_repo", Locator: "org/never"}}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	artifacts := memoryArtifacts{}
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Artifacts: artifacts})
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
	var app uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator='org/app'`).Scan(&app)

	// Policy: corporate-default at revision 0, admin-only replacement with If-Match.
	var record assessments.PolicyRecord
	got := must(call("GET", "/policies/license", reader, "", nil), 200)
	decode(got, &record)
	if !record.Builtin || record.Policy.Name != "corporate-default" || record.Revision != 0 || got.Header().Get("ETag") != `"0"` {
		t.Fatalf("default policy %+v", record)
	}
	must(call("GET", "/policies/gate", reader, "", nil), 200)
	policy, _ := json.Marshal(record.Policy)
	must(call("PUT", "/policies/license", writer, string(policy), map[string]string{"If-Match": `"0"`}), 403)
	must(call("PUT", "/policies/license", admin, string(policy), nil), 428)
	must(call("PUT", "/policies/license", admin, `{"name":"x","default":"maybe","matrix":{}}`, map[string]string{"If-Match": `"0"`}), 400)
	custom := strings.Replace(string(policy), `"rules":[]`, `"rules":[{"effect":"allow","packages":["pkg:npm/approved-agpl"],"reason":"counsel 2026-11"}]`, 1)
	custom = strings.Replace(custom, `"name":"corporate-default"`, `"name":"acme-legal"`, 1)
	decode(must(call("PUT", "/policies/license", admin, custom, map[string]string{"If-Match": `"0"`}), 200), &record)
	if record.Revision != 1 || record.Policy.Name != "acme-legal" || len(record.Policy.Rules) != 1 {
		t.Fatalf("stored policy %+v", record)
	}
	must(call("PUT", "/policies/license", admin, custom, map[string]string{"If-Match": `"0"`}), 409)

	// Dry run: aliases normalise, AGPL is denied for SaaS, the rule allows the package.
	var evaluated struct {
		Normalized struct{ Expression string }
		Decision   struct{ Effect, Basis, Category string }
	}
	decode(must(call("POST", "/policies/license:evaluate", reader, `{"expression":"GNU Affero General Public License v3","distribution":"saas"}`, nil), 200), &evaluated)
	if evaluated.Normalized.Expression != "AGPL-3.0-only" || evaluated.Decision.Effect != "deny" || evaluated.Decision.Category != "network_copyleft" {
		t.Fatalf("evaluate %+v", evaluated)
	}
	decode(must(call("POST", "/policies/license:evaluate", reader, `{"expression":"AGPL-3.0-only","purl":"pkg:npm/approved-agpl@1.0.0"}`, nil), 200), &evaluated)
	if evaluated.Decision.Effect != "allow" || evaluated.Decision.Basis != "rule:0" {
		t.Fatalf("rule %+v", evaluated)
	}
	must(call("POST", "/policies/license:evaluate", reader, `{"expression":"MIT","distribution":"onprem"}`, nil), 400)

	// Categories: overrides are versioned, admin-only and audited.
	var categories struct {
		Revision   int64
		Categories map[string]string
		Counts     map[string]int
	}
	decode(must(call("GET", "/licenses/categories", reader, "", nil), 200), &categories)
	if categories.Revision != 0 || categories.Categories["MPL-2.0"] != "weak_copyleft" || categories.Counts["unknown"] != 0 {
		t.Fatalf("categories %+v", categories.Counts)
	}
	must(call("PUT", "/licenses/categories", writer, `{"overrides":{}}`, map[string]string{"If-Match": `"0"`}), 403)
	must(call("PUT", "/licenses/categories", admin, `{"overrides":{"MIT":"copyleft"}}`, map[string]string{"If-Match": `"0"`}), 400)
	must(call("PUT", "/licenses/categories", admin, `{"overrides":{"LicenseRef-acme-eula":"proprietary","WTFPL":"unknown"},"note":"WTFPL needs review"}`, map[string]string{"If-Match": `"0"`}), 200)
	var history struct{ Items []assessments.CategoryVersion }
	decode(must(call("GET", "/licenses/categories/history", reader, "", nil), 200), &history)
	if len(history.Items) != 1 || history.Items[0].Overrides["WTFPL"] != "unknown" {
		t.Fatalf("history %+v", history)
	}

	// Distribution: admin only; distributed makes GPL a review.
	var asset connections.Asset
	decode(must(call("GET", "/assets/"+app.String(), admin, "", nil), 200), &asset)
	if asset.Distribution != "saas" {
		t.Fatalf("default distribution %q", asset.Distribution)
	}
	must(call("PATCH", "/assets/"+app.String(), writer, `{"distribution":"distributed"}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, asset.Revision)}), 403)
	must(call("PATCH", "/assets/"+app.String(), admin, `{"distribution":"store"}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, asset.Revision)}), 400)
	decode(must(call("PATCH", "/assets/"+app.String(), admin, `{"distribution":"distributed"}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, asset.Revision)}), 200), &asset)

	// An assessment with licensed components, recorded as the worker would.
	commit := strings.Repeat("c", 40)
	if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/app", Ref: "main", Commit: commit}}, uuid.New(), "qa", ""); err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	components := []assessments.Component{
		{Name: "gpl-lib", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/gpl-lib@2.0.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "GPL-3.0-only", Source: "declared", Copyright: []string{"Copyright (c) 2020 GPL Author"}}},
		{Name: "=cmd", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/%3Dcmd@1.0.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "MIT", Source: "metadata", Evidence: "deps.dev"}},
		{Name: "eula", Version: "3.1.0", Ecosystem: "npm", PURL: "pkg:npm/eula@3.1.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "LicenseRef-acme-eula", Source: "declared", Refs: map[string]string{"LicenseRef-acme-eula": "Acme EULA"}}},
		{Name: "jest", Version: "29.0.0", Ecosystem: "npm", PURL: "pkg:npm/jest@29.0.0", Path: "package-lock.json", Groups: []string{"dev"}, License: &assessments.ComponentLicense{Expression: "MIT", Source: "declared"}},
	}
	meta := sbom.Meta{AssessmentID: claimed.ID, Asset: "org/app", Kind: "git", Revision: commit, Ref: "main", Version: "test", Generated: time.Now()}
	document, _ := sbom.CycloneDX(meta, components, false)
	digest := assessments.Hash(document)
	artifacts["sbom/"+digest+".cdx.json"] = document
	var stages []assessments.Stage
	for _, n := range []string{"resolve", "fetch", "inventory", "sbom", "match_vuln", "match_malicious", "malware", "yara", "ioc", "integrity", "license"} {
		stages = append(stages, assessments.Stage{Name: n, Status: "ok"})
	}
	if err := jobs.Complete(ctx, claimed, assessments.Result{Commit: commit, Stages: stages, Components: components, SBOMKey: "sbom/" + digest + ".cdx.json", SBOMSHA256: digest, Complete: true}); err != nil {
		t.Fatal(err)
	}
	done, _ := jobs.Get(ctx, claimed.ID)
	// GPL in a distributed asset and the proprietary EULA are reviews:
	// report-only, so they do not gate.
	if done.Verdict != "pass" || done.Counts["license"] != 2 {
		t.Fatalf("verdict %s %v", done.Verdict, done.Counts)
	}

	// Inventory, CSV report (formula-safe) and notices (dev dependencies omitted).
	var inventory assessments.LicenseInventory
	decode(must(call("GET", "/assets/"+app.String()+"/licenses", reader, "", nil), 200), &inventory)
	if inventory.Distribution != "distributed" || inventory.Counts["review"] != 2 || inventory.Counts["allow"] != 2 || inventory.Policy != "acme-legal" {
		t.Fatalf("inventory %+v", inventory.Counts)
	}
	csvBody := must(call("GET", "/reports/licenses?format=csv&asset_id="+app.String(), reader, "", nil), 200).Body.String()
	rows, err := csv.NewReader(strings.NewReader(csvBody)).ReadAll()
	if err != nil || len(rows) != 5 || rows[0][10] != "expression" {
		t.Fatalf("csv %v %s", err, csvBody)
	}
	for _, row := range rows[1:] {
		if strings.HasPrefix(row[4], "=") {
			t.Fatal("formula cell not neutralised", row)
		}
	}
	must(call("GET", "/reports/licenses?format=md", reader, "", nil), 200)
	must(call("GET", "/reports/licenses?format=pdf", reader, "", nil), 400)
	notices := must(call("GET", "/assets/"+app.String()+"/licenses/notices", reader, "", nil), 200).Body.String()
	if !strings.Contains(notices, "Copyright (c) 2020 GPL Author") || !strings.Contains(notices, "https://spdx.org/licenses/GPL-3.0-only.html") || !strings.Contains(notices, "Acme EULA") || strings.Contains(notices, "jest") {
		t.Fatalf("notices %s", notices)
	}
	must(call("GET", "/assets/"+uuid.NewString()+"/licenses", reader, "", nil), 404)

	// SBOM exports: stored CycloneDX JSON (ETag), XML, SPDX with the same count.
	cdxJSON := must(call("GET", "/assessments/"+claimed.ID.String()+"/sbom", reader, "", nil), 200)
	if cdxJSON.Header().Get("ETag") != `"`+digest+`"` || cdxJSON.Header().Get("X-SCRS-Version") == "" {
		t.Fatalf("CycloneDX headers %v", cdxJSON.Header())
	}
	xmlBody := must(call("GET", "/assessments/"+claimed.ID.String()+"/sbom?format=cyclonedx-xml", reader, "", nil), 200)
	if !strings.HasPrefix(xmlBody.Header().Get("Content-Type"), "application/vnd.cyclonedx+xml") || !strings.Contains(xmlBody.Body.String(), "<bom") {
		t.Fatalf("XML %s", xmlBody.Body.String()[:200])
	}
	spdx := must(call("GET", "/sboms/"+digest+"/download?format=spdx-json", reader, "", nil), 200)
	var spdxDoc struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			LicenseDeclared string `json:"licenseDeclared"`
		} `json:"packages"`
	}
	decode(spdx, &spdxDoc)
	if spdxDoc.SPDXVersion != "SPDX-2.3" || len(spdxDoc.Packages)-1 != sbom.ComponentCount(cdxJSON.Body.Bytes()) || spdx.Header().Get("X-SCRS-Generated-At") == "" {
		t.Fatalf("SPDX %+v", spdxDoc)
	}
	must(call("GET", "/assessments/"+claimed.ID.String()+"/sbom?format=spdx-tv", reader, "", nil), 400)
	must(call("GET", "/sboms/"+strings.Repeat("f", 64)+"/download", reader, "", nil), 404)

	// Schemas and framework packs: shipped packs are listed and reserved.
	if body := must(call("GET", "/schemas/license-policy", reader, "", nil), 200).Body.String(); !strings.Contains(body, "draft/2020-12") {
		t.Fatal(body)
	}
	must(call("GET", "/schemas/framework-pack", reader, "", nil), 200)
	must(call("GET", "/schemas/nope", reader, "", nil), 404)
	var packs struct{ Items []compliance.Pack }
	decode(must(call("GET", "/reports/frameworks", reader, "", nil), 200), &packs)
	if len(packs.Items) != 5 {
		t.Fatalf("packs %d", len(packs.Items))
	}
	pack := `{"id":"acme-secure-coding","name":"Acme secure coding","version":"1","kind":"cwe_mapping","categories":[{"id":"injection","name":"Injection","cwes":[79,89]}],"type_categories":{"vulnerability":"injection"}}`
	must(call("POST", "/reports/frameworks", writer, pack, nil), 403)
	must(call("POST", "/reports/frameworks", admin, strings.Replace(pack, "acme-secure-coding", "owasp-top10-2021", 1), nil), 400)
	must(call("POST", "/reports/frameworks", admin, pack, nil), 201)
	must(call("GET", "/frameworks/acme-secure-coding", reader, "", nil), 200)
	must(call("DELETE", "/frameworks/owasp-top10-2025", admin, "", nil), 409)

	// Reports: queued by write, built by the worker loop (stubbed here),
	// downloaded with their digest.
	must(call("POST", "/reports", reader, `{"framework":"owasp-top10-2021","scope":{"kind":"portfolio"}}`, nil), 403)
	must(call("POST", "/reports", writer, `{"framework":"owasp-top10-2021","scope":{"kind":"asset"}}`, nil), 400)
	must(call("POST", "/reports", writer, `{"framework":"owasp-top10-2021","scope":{"kind":"portfolio"},"since":"2025-01-01T00:00:00Z","until":"2026-11-01T00:00:00Z"}`, nil), 400)
	var job assessments.ReportJob
	queued := must(call("POST", "/reports", writer, `{"framework":"acme-secure-coding","scope":{"kind":"portfolio"},"format":"csv","params":{"sbom_max_age_days":7}}`, nil), 202)
	decode(queued, &job)
	if job.Status != "queued" || queued.Header().Get("Location") == "" {
		t.Fatalf("job %+v", job)
	}
	must(call("GET", "/reports/"+job.ID.String()+"/download", reader, "", nil), 409)
	claimedReport, err := jobs.ClaimReport(ctx)
	if err != nil || claimedReport == nil {
		t.Fatal("report not claimable", err)
	}
	packData, input, err := jobs.ReportInput(ctx, *claimedReport)
	if err != nil {
		t.Fatal(err)
	}
	input.DataAsOf, input.Version = time.Now().UTC(), "test"
	report := compliance.Build(packData, input)
	file, _ := compliance.Render(report, "csv")
	reportKey := "reports/" + assessments.Hash(file) + ".csv"
	artifacts[reportKey] = file
	if err := jobs.FinishReport(ctx, *claimedReport, reportKey, assessments.Hash(file), int64(len(file)), input.DataAsOf, "test", report.Feeds, map[string]int{"gaps": len(report.Gaps)}); err != nil {
		t.Fatal(err)
	}
	decode(must(call("GET", "/reports/"+job.ID.String(), reader, "", nil), 200), &job)
	if job.Status != "succeeded" || job.SHA256 == "" || job.DataAsOf == nil {
		t.Fatalf("finished %+v", job)
	}
	download := must(call("GET", "/reports/"+job.ID.String()+"/download", reader, "", nil), 200)
	// org/never was never assessed: it is the portfolio's SBOM gap.
	if download.Header().Get("X-SCRS-Report-SHA256") != job.SHA256 || !strings.Contains(download.Body.String(), "gap,") || !strings.Contains(download.Body.String(), "org/never") || !strings.Contains(download.Body.String(), "no compliance verdict") {
		t.Fatalf("download %s", download.Body)
	}
	var list struct{ Items []assessments.ReportJob }
	decode(must(call("GET", "/reports", reader, "", nil), 200), &list)
	if len(list.Items) != 1 {
		t.Fatalf("reports %d", len(list.Items))
	}
	var audits int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action IN ('license_policy.updated','license_categories.updated','framework_pack.saved','report.requested')`).Scan(&audits)
	if audits != 4 {
		t.Fatalf("audit records %d", audits)
	}
}
