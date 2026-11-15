package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/compliance"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/depsdev"
	"github.com/ORIBData/scrstack/internal/license"
	"github.com/ORIBData/scrstack/internal/sbom"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/ORIBData/scrstack/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type complianceSink struct{ files map[string][]byte }

func (r *complianceSink) PutReport(_ context.Context, data []byte, extension string) (string, string, error) {
	digest := assessments.Hash(data)
	key := "reports/" + digest + "." + extension
	r.files[key] = append([]byte{}, data...)
	return key, digest, nil
}

// M8 through the worker: declared licences from the scanner, deps.dev
// metadata (cached), licence entries and the verdict under report-only
// and enforcing policies with a waiver (AT-25), safe versions (VUL-008),
// the generated CycloneDX SBOM against SPDX (AT-26) and evidence reports
// for an asset and the portfolio (AT-30).
func TestPostgresLicencesSafeVersionsSBOMAndReports(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: db, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, c.Name, syntheticSource{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()

	// deps.dev: one licence, one version list, one unknown package, one outage.
	var mu sync.Mutex
	lookups := map[string]int{}
	count := func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return lookups[path]
	}
	deps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lookups[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/v3/systems/npm/packages/left-pad/versions/1.3.0":
			_, _ = w.Write([]byte(`{"licenses":["WTFPL"]}`))
		case "/v3/systems/pypi/packages/ghost/versions/0.1":
			http.NotFound(w, r)
		case "/v3/systems/npm/packages/flaky/versions/2.0.0":
			http.Error(w, "unavailable", 503)
		case "/v3/systems/npm/packages/lodash":
			_, _ = w.Write([]byte(`{"versions":[{"versionKey":{"version":"4.17.20"}},{"versionKey":{"version":"4.17.21"}},{"versionKey":{"version":"4.17.22"},"isDeprecated":true},{"versionKey":{"version":"4.18.0-rc.1"}},{"versionKey":{"version":"4.18.1"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer deps.Close()
	client := depsdev.New(deps.URL+"/v3", map[string]bool{"127.0.0.1": true})

	osv := `{"id":"GHSA-lodash-1","summary":"Prototype pollution","database_specific":{"severity":"HIGH","cwe_ids":["CWE-1321"]},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	later := versions.Advisory{ID: "GHSA-lodash-2", Affected: []versions.Affected{{Ecosystem: "npm", Name: "lodash", Ranges: []versions.Range{{Type: "SEMVER", Events: []versions.Event{{Introduced: "4.17.21"}, {Fixed: "4.18.1"}}}}}}}
	first, _ := scanner.ParseAdvisory([]byte(osv), "npm", "lodash")
	output := scanner.Output{
		Components: []assessments.Component{
			{Name: "agpl-lib", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/agpl-lib@1.0.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "AGPL-3.0-only", Source: "declared", Evidence: "package-lock.json"}},
			{Name: "express", Version: "4.21.2", Ecosystem: "npm", PURL: "pkg:npm/express@4.21.2", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "MIT", Source: "declared", Copyright: []string{"Copyright (c) 2009 TJ"}}},
			{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm", PURL: "pkg:npm/left-pad@1.3.0", Path: "package-lock.json"},
			{Name: "ghost", Version: "0.1", Ecosystem: "PyPI", PURL: "pkg:pypi/ghost@0.1", Path: "requirements.txt"},
			{Name: "flaky", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/flaky@2.0.0", Path: "package-lock.json", Groups: []string{"dev"}},
			{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.20", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "MIT", Source: "declared"}},
		},
		Findings: []assessments.Finding{{Type: "vulnerability", AdvisoryID: "GHSA-lodash-1", Title: "Prototype pollution", Severity: "high", Score: 45, Component: assessments.Component{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.20", Path: "package-lock.json"}, Evidence: json.RawMessage(osv), Guidance: json.RawMessage(`{"summary":"upgrade","aliases":["CVE-2026-0001"]}`)}},
		Packages: []versions.Package{{Ecosystem: "npm", Name: "lodash", Advisories: []versions.Advisory{first, later}, Complete: true}},
	}
	for _, n := range []string{"inventory", "match_vuln", "match_malicious", "malware", "yara", "ioc", "integrity"} {
		output.Stages = append(output.Stages, assessments.Stage{Name: n, Status: "ok"})
	}
	scan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(output) }))
	defer scan.Close()
	sink := &artifactSink{}
	w := Worker{Store: jobs, Connections: providers, Source: syntheticSource{}, Artifacts: sink, ScannerURL: scan.URL + "/scan", ScannerToken: strings.Repeat("s", 40), Logger: slog.Default(), DepsDev: &client}
	run := func(label string) assessments.Assessment {
		t.Helper()
		if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}, uuid.New(), "tester", label); err != nil {
			t.Fatal(err)
		}
		job, err := jobs.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.run(ctx, &job); err != nil {
			t.Fatal(err)
		}
		done, err := jobs.Get(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		return done
	}
	first1 := run("m8-1")
	stage := map[string]assessments.Stage{}
	for _, s := range first1.Stages {
		stage[s.Name] = s
	}
	if stage["license"].Status != "partial" || !strings.Contains(stage["license"].Detail, "metadata 1, none 1, unresolved 1") || stage["sbom"].Status != "ok" || stage["safe_versions"].Status != "ok" {
		t.Fatalf("stages %+v", stage)
	}
	// Report-only corporate-default: AGPL in a SaaS asset is a deny entry
	// that warns; the unknown licence is a review entry; MIT, WTFPL none.
	findings, err := jobs.Findings(ctx, first1.ID, uuid.Nil, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	licences := map[string]assessments.Finding{}
	var vuln assessments.Finding
	for _, f := range findings {
		if f.Type == "license" {
			licences[f.Component.Name] = f
		}
		if f.Type == "vulnerability" {
			vuln = f
		}
	}
	if len(licences) != 2 || licences["agpl-lib"].Severity != "high" || licences["agpl-lib"].AdvisoryID != "SCRS-LICENSE:AGPL-3.0-only" || licences["ghost"].AdvisoryID != "SCRS-LICENSE:NOASSERTION" || first1.Verdict != "warn" || first1.Counts["license"] != 2 {
		t.Fatalf("licence entries %v verdict %s counts %v", licences, first1.Verdict, first1.Counts)
	}
	// VUL-008: 4.17.21 fixes the matched advisory but the mirror's second
	// advisory affects it; the deprecated and pre-release versions are
	// skipped, so 4.18.1 is both the smallest and latest safe upgrade.
	var guidance struct {
		Fixed    []string       `json:"fixed_versions"`
		Safe     []string       `json:"safe_versions"`
		Smallest string         `json:"smallest_safe_upgrade"`
		Latest   string         `json:"latest_safe"`
		Basis    versions.Basis `json:"safe_basis"`
		Aliases  []string       `json:"aliases"`
	}
	if err := json.Unmarshal(vuln.Guidance, &guidance); err != nil {
		t.Fatal(err)
	}
	if guidance.Smallest != "4.18.1" || guidance.Latest != "4.18.1" || len(guidance.Fixed) != 1 || guidance.Fixed[0] != "4.17.21" || !guidance.Basis.Mirror || guidance.Basis.Versions != "registry" || len(guidance.Aliases) != 1 {
		t.Fatalf("safe versions %+v", guidance)
	}
	// AT-26: the stored SBOM is SCRS's CycloneDX with licences; SPDX from the
	// same components lists the same number of packages.
	components, err := jobs.AllComponents(ctx, first1.ID)
	if err != nil {
		t.Fatal(err)
	}
	spdx, err := sbom.SPDX(sbom.Meta{AssessmentID: first1.ID, Asset: "org/repo", Kind: "git", Revision: first1.Commit, Version: "test", Generated: time.Now()}, components)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Packages []struct {
			Name             string `json:"name"`
			LicenseConcluded string `json:"licenseConcluded"`
		} `json:"packages"`
	}
	_ = json.Unmarshal(spdx, &doc)
	if sbom.ComponentCount(sink.saved) != 6 || len(doc.Packages)-1 != 6 || !bytes.Contains(sink.saved, []byte(`"expression":"AGPL-3.0-only"`)) || !bytes.Contains(sink.saved, []byte(`"expression":"WTFPL"`)) {
		t.Fatalf("SBOM %s / SPDX %d", sink.saved, len(doc.Packages))
	}

	// deps.dev results are cached: a second assessment fetches only the
	// package that failed.
	before := count("/v3/systems/npm/packages/left-pad/versions/1.3.0")
	if _, err := jobs.SetLicensePolicy(ctx, enforcing(t), 0, uuid.New()); err != nil {
		t.Fatal(err)
	}
	second := run("m8-2")
	if count("/v3/systems/npm/packages/left-pad/versions/1.3.0") != before || count("/v3/systems/npm/packages/flaky/versions/2.0.0") < 2 {
		t.Fatal("deps.dev cache not used")
	}
	// Enforcing: the AGPL deny fails the verdict; unresolved licences make
	// an enforcing assessment incomplete, but fail outranks incomplete.
	if second.Verdict != "fail" {
		t.Fatalf("enforcing verdict %s %v", second.Verdict, second.Counts)
	}
	// A waiver clears the deny (LIC-006) and is audited; the review entry
	// still warns, and the unresolved lookup keeps it incomplete.
	until := time.Now().Add(30 * 24 * time.Hour)
	if err := jobs.Transition(ctx, licences["agpl-lib"].ID, uuid.New(), "accepted", "counsel approved for internal tooling", &until); err != nil {
		t.Fatal(err)
	}
	third := run("m8-3")
	if third.Verdict != "incomplete" || third.Counts["waived"] != 1 {
		t.Fatalf("waived verdict %s %v", third.Verdict, third.Counts)
	}
	var audited int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.finding_events WHERE finding_id=$1 AND action<>'detected'`, licences["agpl-lib"].ID).Scan(&audited)
	if audited == 0 {
		t.Fatal("waiver not recorded in finding history")
	}
	inventory, err := jobs.AssetLicenses(ctx, first1.AssetID, "")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]assessments.LicenseRow{}
	for _, r := range inventory.Items {
		rows[r.Name] = r
	}
	if inventory.Distribution != "saas" || !inventory.Enforcing || rows["agpl-lib"].Effect != "deny" || rows["agpl-lib"].Status != "accepted" || rows["left-pad"].Source != "metadata" || rows["flaky"].Source != "unresolved" || !rows["flaky"].Dev || rows["express"].Effect != "allow" {
		t.Fatalf("inventory %+v", inventory)
	}

	// AT-30: OWASP Top 10 2025 for the asset and PCI DSS 6.3.2 for the
	// portfolio, with data time, scope, freshness and SBOM gaps.
	reports := &complianceSink{files: map[string][]byte{}}
	w.Reports = reports
	asset := first1.AssetID
	owasp, err := jobs.CreateReport(ctx, assessments.ReportRequest{Framework: "owasp-top10-2025", Scope: compliance.Scope{Kind: "asset", ID: &asset}, Format: "json"}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	pci, err := jobs.CreateReport(ctx, assessments.ReportRequest{Framework: "pci-dss-4.0.1", Scope: compliance.Scope{Kind: "portfolio"}, Format: "md", Params: compliance.Params{SBOMMaxAgeDays: 7}}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if built, err := w.BuildReportOnce(ctx); err != nil || !built {
			t.Fatal("report not built", built, err)
		}
	}
	got, err := jobs.Report(ctx, owasp.ID)
	if err != nil || got.Status != "succeeded" || got.DataAsOf == nil || got.SHA256 == "" || got.Version == "" {
		t.Fatalf("report job %+v %v", got, err)
	}
	var built compliance.Report
	if err := json.Unmarshal(reports.files[got.Key], &built); err != nil {
		t.Fatal(err)
	}
	categories := map[string]compliance.CategoryResult{}
	for _, c := range built.Categories {
		categories[c.ID] = c
	}
	if built.Statement != compliance.Statement || built.Meta.Scope.Name != "org/repo" || len(built.Gaps) != 0 || categories["A03:2025"].Open != 1 || categories["A03:2025"].MappedByType != 1 || built.Totals.Excluded["license"] != 2 {
		t.Fatalf("OWASP report %+v", built)
	}
	if bytes.Contains(reports.files[got.Key], []byte(`"verdict"`)) {
		t.Fatal("evidence report carries a verdict")
	}
	pciJob, _ := jobs.Report(ctx, pci.ID)
	if pciJob.Status != "succeeded" || !bytes.Contains(reports.files[pciJob.Key], []byte("## Requirement 6.3.2")) || !bytes.Contains(reports.files[pciJob.Key], []byte("Every asset in scope has a recent SBOM")) {
		t.Fatalf("PCI report %s", reports.files[pciJob.Key])
	}
	if _, err := jobs.CreateReport(ctx, assessments.ReportRequest{Framework: "nope-pack", Scope: compliance.Scope{Kind: "portfolio"}}, uuid.New()); err != assessments.ErrNotFound {
		t.Fatalf("unknown framework: %v", err)
	}
}

func enforcing(t *testing.T) license.Policy {
	t.Helper()
	p := license.CorporateDefault()
	p.Name, p.Enforcing = "acme", true
	return p
}
