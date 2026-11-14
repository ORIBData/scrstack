package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type deletedObjects struct {
	mu   sync.Mutex
	keys []string
}

func (d *deletedObjects) DeleteObject(_ context.Context, key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys = append(d.keys, key)
	return nil
}

func TestPostgresEventsAdvisorySyncAndObjectRetention(t *testing.T) {
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
	pool, _ := pgxpool.New(ctx, db)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	providers, err := connections.Open(ctx, db, schema, key)
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
	events, err := notify.Open(ctx, db, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.webhook_subscriptions(id,name,url,secret_ciphertext,events) VALUES($1,'all','https://hooks.example.com/x','\x00','["finding.rescored","malicious_dependency.reported","feed.stale"]')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	countEvents := func(event string) int {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.webhook_deliveries WHERE event_type=$1`, event).Scan(&n)
		return n
	}

	// The scanner: one vulnerability (severity per scan), one malicious package,
	// an SBOM that differs per scan, and the /feeds freshness endpoint.
	severity, sbom := "high", 0
	var mu sync.Mutex
	scan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feeds" {
			_ = json.NewEncoder(w).Encode(map[string]any{"osv": map[string]any{"fetched_at": time.Now().UTC(), "ecosystems": []string{"npm", "Go"}}, "kev": map[string]any{"present": true, "modified": time.Now().UTC(), "bytes": 10}, "epss": map[string]any{"present": false}})
			return
		}
		mu.Lock()
		sbom++
		out := scanner.Output{SBOM: json.RawMessage(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:%d"}`, sbom)), Stages: []assessments.Stage{{Name: "inventory", Status: "ok"}}, Findings: []assessments.Finding{
			{Type: "vulnerability", AdvisoryID: "GHSA-jfh8-c2jp-5v3q", Title: "log4j", Severity: severity, Score: map[string]int{"high": 45, "critical": 60}[severity], Component: assessments.Component{Name: "log4j-core", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Path: "pom.xml"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{"aliases":["CVE-2021-44228"]}`)},
			{Type: "malicious_dependency", AdvisoryID: "MAL-2026-1", Title: "evil", Severity: "critical", Score: 100, Component: assessments.Component{Name: "evil", PURL: "pkg:npm/evil@1.0.0", Path: "package-lock.json"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)},
		}}
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer scan.Close()
	sink := &artifactSink{}
	w := Worker{Store: jobs, Connections: providers, Source: syntheticSource{}, Artifacts: sink, ScannerURL: scan.URL + "/scan", ScannerToken: strings.Repeat("s", 40), Logger: slog.Default(), Notify: events}
	assess := func() assessments.Assessment {
		t.Helper()
		if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}, uuid.New(), "tester", uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		job, err := jobs.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.run(ctx, &job); err != nil {
			t.Fatal(err)
		}
		done, _ := jobs.Get(ctx, job.ID)
		return done
	}

	// malicious_dependency.reported on the first report; finding.rescored
	// when the next scan changes the vulnerability's severity.
	first := assess()
	if countEvents("malicious_dependency.reported") != 1 || countEvents("finding.rescored") != 0 {
		t.Fatal("first scan events", countEvents("malicious_dependency.reported"), countEvents("finding.rescored"))
	}
	mu.Lock()
	severity = "critical"
	mu.Unlock()
	second := assess()
	if countEvents("malicious_dependency.reported") != 1 || countEvents("finding.rescored") != 1 {
		t.Fatal("second scan events", countEvents("malicious_dependency.reported"), countEvents("finding.rescored"))
	}
	var payload []byte
	_ = pool.QueryRow(ctx, `SELECT payload FROM `+schema+`.webhook_deliveries WHERE event_type='finding.rescored'`).Scan(&payload)
	compact := strings.ReplaceAll(string(payload), " ", "")
	if !strings.Contains(compact, `"previous_severity":"high"`) || !strings.Contains(compact, `"severity":"critical"`) {
		t.Fatal(string(payload))
	}

	// NVD and CVE Program sync for the CVE the register references by alias.
	var nvdQueries []string
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		nvdQueries = append(nvdQueries, r.URL.RawQuery)
		mu.Unlock()
		if r.URL.Query().Get("lastModStartDate") != "" {
			fmt.Fprint(w, `{"resultsPerPage":2,"startIndex":0,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","lastModified":"2026-11-14T00:00:00.000","vulnStatus":"Modified","descriptions":[{"lang":"en","value":"updated"}]}},{"cve":{"id":"CVE-2020-0001","lastModified":"2026-11-14T00:00:00.000","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"untracked"}]}}]}`)
			return
		}
		fmt.Fprint(w, `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","lastModified":"2025-02-04T15:15:13.773","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Log4Shell"}],"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10,"baseSeverity":"CRITICAL"}}]},"weaknesses":[{"description":[{"lang":"en","value":"CWE-917"}]}]}}]}`)
	}))
	defer nvd.Close()
	cve := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/CVE-2021-44228") {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, `{"cveMetadata":{"cveId":"CVE-2021-44228","state":"PUBLISHED","assignerShortName":"apache","datePublished":"2021-12-10T00:00:00Z","dateUpdated":"2025-02-04T00:00:00Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Log4j2 JNDI"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-502"}]}]}}}`)
	}))
	defer cve.Close()
	w.NVDURL, w.CVEURL, w.AdvisoryPace = nvd.URL, cve.URL+"/api/cve", time.Millisecond
	synced := map[string]bool{}
	for i := 0; i < 2; i++ {
		key, err := w.SyncAdvisoryOnce(ctx)
		if err != nil || key == "" {
			t.Fatal("advisory sync", key, err)
		}
		synced[key] = true
	}
	if !synced["nvd"] || !synced["cve_program"] {
		t.Fatal(synced)
	}
	view, err := jobs.Advisory(ctx, "CVE-2021-44228", "")
	if err != nil || len(view.Records) != 2 || len(view.SeveritySources) != 1 || strings.Join(view.CWE, ",") != "CWE-502,CWE-917" {
		t.Fatalf("advisory view %+v %v", view, err)
	}
	src, _ := jobs.VulnerabilitySource(ctx, "nvd")
	if src.RecordCount != 1 || src.LastSuccessAt == nil || !strings.Contains(string(src.State), "cursor") || src.Failures != 0 {
		t.Fatalf("nvd source %+v", src)
	}
	// The next NVD run reads the modified window and refreshes only tracked records.
	if err := jobs.SyncVulnerabilitySourceNow(ctx, "nvd"); err != nil {
		t.Fatal(err)
	}
	if key, err := w.SyncAdvisoryOnce(ctx); err != nil || key != "nvd" {
		t.Fatal(key, err)
	}
	mu.Lock()
	last := nvdQueries[len(nvdQueries)-1]
	mu.Unlock()
	if !strings.Contains(last, "lastModStartDate") {
		t.Fatal("no modified window", nvdQueries)
	}
	if _, err := jobs.Advisory(ctx, "CVE-2020-0001", ""); err != assessments.ErrNotFound {
		t.Fatal("untracked CVE stored", err)
	}
	if view, _ := jobs.Advisory(ctx, "CVE-2021-44228", ""); !strings.Contains(string(view.Records[1]), "updated") {
		t.Fatal("tracked record not refreshed", string(view.Records[1]))
	}

	// Feed health from the scanner; KEV going stale raises feed.stale once.
	w.ScannerURL = scan.URL + "/scan"
	if err := w.recordFeedHealth(ctx, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	osv, _ := jobs.VulnerabilitySource(ctx, "osv")
	epss, _ := jobs.VulnerabilitySource(ctx, "epss")
	if osv.RecordCount != 2 || osv.LastSuccessAt == nil || epss.LastError == "" {
		t.Fatalf("feed health %+v %+v", osv, epss)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.vulnerability_sources SET last_success_at=now()-interval '2 days' WHERE key='kev'`); err != nil {
		t.Fatal(err)
	}
	scanStale := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"osv": map[string]any{"fetched_at": time.Now().UTC(), "ecosystems": []string{"npm"}}, "kev": map[string]any{"present": true}, "epss": map[string]any{"present": true}})
	}))
	defer scanStale.Close()
	w.ScannerURL = scanStale.URL + "/scan"
	for i := 0; i < 2; i++ {
		if err := w.recordFeedHealth(ctx, http.DefaultClient); err != nil {
			t.Fatal(err)
		}
	}
	if countEvents("feed.stale") != 1 {
		t.Fatal("feed.stale", countEvents("feed.stale"))
	}

	// Object-backed retention: the superseded assessment's SBOM is deleted.
	objects := &deletedObjects{}
	jobs.UseObjects(objects)
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.assessments SET created_at=now()-interval '400 days' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	policy, _ := jobs.Retention(ctx)
	thirty := 30
	if _, err := jobs.SetRetentionClasses(ctx, uuid.Nil, policy.Revision, map[string]*int{"sbom_documents": &thirty, "scan_artifacts": &thirty}); err != nil {
		t.Fatal(err)
	}
	report, err := jobs.Maintain(ctx, uuid.Nil, "scheduled")
	if err != nil {
		t.Fatal(err)
	}
	old, _ := jobs.Get(ctx, first.ID)
	current, _ := jobs.Get(ctx, second.ID)
	if report.Purged["sbom_documents"] != 1 || report.ObjectsDeleted != 1 || len(objects.keys) != 1 || objects.keys[0] != first.SBOMKey || old.SBOMKey != "" || current.SBOMKey == "" {
		t.Fatalf("report %+v deleted %v old %q current %q", report, objects.keys, old.SBOMKey, current.SBOMKey)
	}
}
