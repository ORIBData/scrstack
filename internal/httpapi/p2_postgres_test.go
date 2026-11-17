package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/ORIBData/scrstack/internal/dtrack"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/sbom"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/ORIBData/scrstack/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// P2 through the real router: STIG import and a PDF report job, live
// events from a committed assessment, the Dependency-Track export queued
// in Complete's transaction and pushed by the worker, and outbound-licence
// entries against the repository's own licence.
func TestPostgresP2Features(t *testing.T) {
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
	// Migrations run again on every start: the P2 DDL must be re-runnable.
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, databaseURL)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, masterKey)
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
	if _, err := store.Discover(ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/app"}}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, databaseURL, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	events, err := notify.Open(ctx, databaseURL, schema, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	artifacts := memoryArtifacts{}
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()

	// A fake Dependency-Track that fails once, then accepts.
	var mu sync.Mutex
	var uploads []map[string]any
	failNext := true
	// What the fake reports about processing: still running, and when the
	// project's last BOM import happened.
	dtProcessing := true
	dtPerms := `[{"name":"BOM_UPLOAD"},{"name":"PROJECT_CREATION_UPLOAD"},{"name":"VIEW_PORTFOLIO"}]`
	dtFindings, dtFindingsStatus := `[]`, 200
	var dtAnalyses []map[string]any
	dtImportedAt := time.Now().Add(time.Hour).UnixMilli()
	dtrackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/version":
			_, _ = w.Write([]byte(`{"version":"4.13.2"}`))
		case r.URL.Path == "/api/v1/team/self" && r.Header.Get("X-Api-Key") == "odt_0123456789abcdef":
			mu.Lock()
			defer mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"name":"scrs","permissions":%s}`, dtPerms)
		case strings.HasPrefix(r.URL.Path, "/api/v1/finding/project/") && r.Header.Get("X-Api-Key") == "odt_0123456789abcdef":
			mu.Lock()
			defer mu.Unlock()
			w.WriteHeader(dtFindingsStatus)
			_, _ = w.Write([]byte(dtFindings))
		case r.URL.Path == "/api/v1/analysis" && r.Method == http.MethodPut && r.Header.Get("X-Api-Key") == "odt_0123456789abcdef":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			dtAnalyses = append(dtAnalyses, body)
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/event/token/") && r.Header.Get("X-Api-Key") == "odt_0123456789abcdef":
			mu.Lock()
			defer mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"processing":%t}`, dtProcessing)
		case r.URL.Path == "/api/v1/project/lookup" && r.Header.Get("X-Api-Key") == "odt_0123456789abcdef":
			mu.Lock()
			defer mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"uuid":"11111111-1111-1111-1111-111111111111","lastBomImport":%d}`, dtImportedAt)
		case r.URL.Path == "/api/v1/bom" && r.Header.Get("X-Api-Key") == "odt_0123456789abcdef":
			mu.Lock()
			defer mu.Unlock()
			if failNext {
				failNext = false
				w.WriteHeader(503)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			uploads = append(uploads, body)
			_, _ = w.Write([]byte(`{"token":"5e2f0b4a-7f5e-4b55-9d0e-1c1f3a3c1b2a"}`))
		default:
			w.WriteHeader(401)
		}
	}))
	defer dtrackServer.Close()
	private := map[string]bool{"127.0.0.1": true}

	live := &notify.Hub{MaxStreams: 10, PerToken: 2}
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Artifacts: artifacts, Live: live, DTrackPrivateHosts: private})
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

	// STIG import (CMP-004): admin only; the XCCDF becomes a stig pack.
	xccdf, err := os.ReadFile("../compliance/testdata/asd-sample-xccdf.xml")
	if err != nil {
		t.Fatal(err)
	}
	must(call("POST", "/reports/frameworks/stig", writer, string(xccdf), nil), 403)
	must(call("POST", "/reports/frameworks/stig", admin, `<Benchmark id="x"><title>T</title></Benchmark>`, nil), 400)
	var imported compliance.STIGImport
	decode(must(call("POST", "/reports/frameworks/stig", admin, string(xccdf), nil), 201), &imported)
	if imported.Mapped != 3 || imported.Pack.Kind != compliance.KindSTIG {
		t.Fatalf("import %+v", imported)
	}
	var stored compliance.Pack
	decode(must(call("GET", "/frameworks/"+imported.Pack.ID, reader, "", nil), 200), &stored)
	if len(stored.Categories) != 4 || stored.Benchmark == nil {
		t.Fatalf("stored pack %+v", stored)
	}
	// The pack can be edited and uploaded again through the pack API.
	stored.Categories[3].CWEs = []int{307}
	edited, _ := json.Marshal(stored)
	must(call("POST", "/reports/frameworks", admin, string(edited), nil), 201)

	// Dependency-Track settings: admin, If-Match, write-only key.
	var settings assessments.DTrackSettings
	decode(must(call("GET", "/integrations/dependency-track", reader, "", nil), 200), &settings)
	if settings.Enabled || settings.APIKeySet {
		t.Fatalf("default settings %+v", settings)
	}
	rev := map[string]string{"If-Match": fmt.Sprintf(`"%d"`, settings.Revision)}
	must(call("PUT", "/integrations/dependency-track", writer, `{}`, rev), 403)
	must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":true,"url":"`+dtrackServer.URL+`"}`, nil), 428)
	must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":true,"url":"http://dtrack.example.com","api_key":"odt_0123456789abcdef"}`, rev), 400)
	must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":true,"url":"`+dtrackServer.URL+`"}`, rev), 400)
	resp := must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":true,"url":"`+dtrackServer.URL+`","api_key":"odt_0123456789abcdef"}`, rev), 200)
	decode(resp, &settings)
	if !settings.Enabled || !settings.APIKeySet || strings.Contains(resp.Body.String(), "odt_") {
		t.Fatalf("settings %s", resp.Body)
	}
	must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":false}`, rev), 409)
	var check map[string]any
	decode(must(call("POST", "/integrations/dependency-track:test", admin, "", nil), 200), &check)
	if check["ok"] != true || check["version"] != "4.13.2" || fmt.Sprint(check["missing_permissions"]) != "[]" || !strings.Contains(fmt.Sprint(check["permissions"]), "BOM_UPLOAD") {
		t.Fatalf("test %+v", check)
	}

	// Live events: a stream through a real HTTP server.
	server := httptest.NewServer(handler)
	defer server.Close()
	streamReq, _ := http.NewRequestWithContext(ctx, "GET", server.URL+BasePath+"/events?types=assessment.completed", nil)
	streamReq.Header.Set("Authorization", "Bearer "+reader)
	stream, err := http.DefaultClient.Do(streamReq)
	if err != nil || stream.StatusCode != 200 || stream.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream %v %+v", err, stream)
	}
	defer stream.Body.Close()
	lines := bufio.NewReader(stream.Body)
	next := func(want string) map[string]any {
		t.Helper()
		var event string
		for {
			line, err := lines.ReadString('\n')
			if err != nil {
				t.Fatalf("stream ended waiting for %s: %v", want, err)
			}
			line = strings.TrimRight(line, "\n")
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				event = v
			}
			if v, ok := strings.CutPrefix(line, "data: "); ok && event == want {
				var data map[string]any
				_ = json.Unmarshal([]byte(v), &data)
				return data
			}
		}
	}
	next("ready")
	must(call("GET", "/events?types=nope", reader, "", nil), 400)
	listenCtx, stopListen := context.WithCancel(ctx)
	defer stopListen()
	go events.Listen(listenCtx, live)
	next("resync") // the listener is connected

	// A completed scan: an MIT repository with a GPL runtime dependency in a
	// distributed asset.
	var app uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator='org/app'`).Scan(&app); err != nil {
		t.Fatal(err)
	}
	var asset connections.Asset
	decode(must(call("GET", "/assets/"+app.String(), admin, "", nil), 200), &asset)
	must(call("PATCH", "/assets/"+app.String(), admin, `{"distribution":"distributed"}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, asset.Revision)}), 200)
	commit := strings.Repeat("d", 40)
	if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/app", Ref: "main", Commit: commit}}, uuid.New(), "qa", ""); err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	components := []assessments.Component{
		{Name: "gpl-lib", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/gpl-lib@2.0.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "GPL-3.0-only", Source: "declared"}},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.21", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "MIT", Source: "declared"}},
		{Name: "gpl-test-tool", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/gpl-test-tool@1.0.0", Path: "package-lock.json", Groups: []string{"dev"}, License: &assessments.ComponentLicense{Expression: "GPL-3.0-only", Source: "declared"}},
	}
	meta := sbom.Meta{AssessmentID: claimed.ID, Asset: "org/app", Kind: "git", Revision: commit, Ref: "main", Version: "test", Generated: time.Now()}
	document, _ := sbom.CycloneDX(meta, components, false)
	digest := assessments.Hash(document)
	sbomKey := "sbom/" + digest + ".cdx.json"
	artifacts[sbomKey] = document
	var stages []assessments.Stage
	for _, n := range []string{"resolve", "fetch", "inventory", "sbom", "match_vuln", "match_malicious", "malware", "yara", "ioc", "integrity", "license"} {
		stages = append(stages, assessments.Stage{Name: n, Status: "ok"})
	}
	project := &assessments.ComponentLicense{Expression: "MIT", Source: "detected", Confidence: 1, Evidence: "LICENSE"}
	if err := jobs.Complete(ctx, claimed, assessments.Result{Commit: commit, Stages: stages, Components: components, SBOMKey: sbomKey, SBOMSHA256: digest, Complete: true, ProjectLicense: project}); err != nil {
		t.Fatal(err)
	}

	// The committed completion reached the stream.
	notice := next("assessment.completed")
	if refs, _ := notice["refs"].(map[string]any); notice["type"] != "assessment.completed" || refs["assessment.id"] != claimed.ID.String() {
		t.Fatalf("live notice %+v", notice)
	}
	if strings.Contains(fmt.Sprint(notice), "gpl-lib") {
		t.Fatal("live notices carry ids only")
	}

	// LIC-005: GPL-3.0 in an MIT project is an outbound deny (report-only:
	// warns); the policy reviews of both GPL components stay; the dev tool
	// gets no outbound check.
	done, _ := jobs.Get(ctx, claimed.ID)
	if done.Verdict != "warn" || done.Counts["license"] != 3 {
		t.Fatalf("verdict %s %v", done.Verdict, done.Counts)
	}
	var outbound, title string
	if err := pool.QueryRow(ctx, `SELECT advisory_id,title FROM `+schema+`.findings WHERE asset_id=$1 AND advisory_id LIKE 'SCRS-LICENSE-OUTBOUND:%'`, app).Scan(&outbound, &title); err != nil {
		t.Fatal(err)
	}
	if outbound != "SCRS-LICENSE-OUTBOUND:MIT:GPL-3.0-only" || !strings.Contains(title, "incompatible with the project licence MIT") {
		t.Fatalf("outbound entry %s %s", outbound, title)
	}
	var inventory assessments.LicenseInventory
	decode(must(call("GET", "/assets/"+app.String()+"/licenses", reader, "", nil), 200), &inventory)
	if inventory.ProjectLicense == nil || inventory.ProjectLicense.Expression != "MIT" || inventory.Outbound["deny"] != 1 || inventory.Outbound["allow"] != 1 || inventory.Counts["review"] != 2 {
		t.Fatalf("inventory %+v %+v %+v", inventory.ProjectLicense, inventory.Outbound, inventory.Counts)
	}
	var dry map[string]json.RawMessage
	decode(must(call("POST", "/policies/license:evaluate", reader, `{"expression":"Apache-2.0","project_license":"GPL-2.0-only","distribution":"distributed"}`, nil), 200), &dry)
	if !strings.Contains(string(dry["outbound"]), `"effect":"deny"`) {
		t.Fatalf("dry run %s", dry["outbound"])
	}
	must(call("POST", "/policies/license:evaluate", reader, `{"expression":"MIT","project_license":"LicenseRef-x-eula"}`, nil), 400)

	// Dependency-Track: the upload was queued with the completion; the
	// first push fails (503) and is retried, the second succeeds.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := worker.Worker{Store: jobs, Connections: store, SBOMs: artifacts, DTrackPrivateHosts: private, Logger: logger}
	if pushed, err := w.PushDependencyTrackOnce(ctx); !pushed || err != nil {
		t.Fatal(pushed, err)
	}
	var list struct {
		Items []assessments.DTrackUpload `json:"items"`
	}
	decode(must(call("GET", "/integrations/dependency-track/uploads", reader, "", nil), 200), &list)
	if len(list.Items) != 1 || list.Items[0].Status != "queued" || list.Items[0].Attempts != 1 || !strings.Contains(list.Items[0].Error, "503") || list.Items[0].ProjectName != "github/org/app" || list.Items[0].ProjectVersion != "main" {
		t.Fatalf("after a transient failure %+v", list.Items)
	}
	if pushed, _ := w.PushDependencyTrackOnce(ctx); pushed {
		t.Fatal("a backed-off upload was claimed early")
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.dtrack_uploads SET next_attempt_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if pushed, err := w.PushDependencyTrackOnce(ctx); !pushed || err != nil {
		t.Fatal(pushed, err)
	}
	decode(must(call("GET", "/integrations/dependency-track/uploads?status=uploaded", reader, "", nil), 200), &list)
	mu.Lock()
	sent := uploads
	mu.Unlock()
	if len(list.Items) != 1 || list.Items[0].Token != "5e2f0b4a-7f5e-4b55-9d0e-1c1f3a3c1b2a" || len(sent) != 1 || sent[0]["projectName"] != "github/org/app" || sent[0]["autoCreate"] != true {
		t.Fatalf("uploaded %+v %+v", list.Items, sent)
	}
	bom, _ := base64.StdEncoding.DecodeString(sent[0]["bom"].(string))
	if !bytes.Equal(bom, document) {
		t.Fatal("uploaded BOM differs from the stored SBOM")
	}
	must(call("POST", "/integrations/dependency-track/uploads/"+list.Items[0].ID.String()+"/retry", admin, "", nil), 404)

	// The upload is accepted, not yet known to be imported: its processing
	// is checked later, first while Dependency-Track is still busy, then
	// once it has finished and stamped a newer import than the upload.
	if list.Items[0].Processing != "pending" {
		t.Fatalf("a fresh upload is unverified: %+v", list.Items[0])
	}
	if checked, _ := w.VerifyDependencyTrackOnce(ctx); checked {
		t.Fatal("processing was checked before its delay")
	}
	due := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.dtrack_uploads SET processing_next_at=clock_timestamp()`); err != nil {
			t.Fatal(err)
		}
	}
	processingOf := func() (state, detail string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT processing,processing_error FROM `+schema+`.dtrack_uploads`).Scan(&state, &detail); err != nil {
			t.Fatal(err)
		}
		return
	}
	due()
	if checked, err := w.VerifyDependencyTrackOnce(ctx); !checked || err != nil {
		t.Fatal(checked, err)
	}
	if state, _ := processingOf(); state != "pending" {
		t.Fatalf("still processing stays pending, got %s", state)
	}
	mu.Lock()
	dtProcessing = false
	mu.Unlock()
	due()
	if checked, err := w.VerifyDependencyTrackOnce(ctx); !checked || err != nil {
		t.Fatal(checked, err)
	}
	if state, detail := processingOf(); state != "processed" || detail != "" {
		t.Fatalf("finished and imported: %s %s", state, detail)
	}
	decode(must(call("GET", "/integrations/dependency-track/uploads?status=uploaded", reader, "", nil), 200), &list)
	if list.Items[0].Processing != "processed" || list.Items[0].ProcessedAt == nil {
		t.Fatalf("processed upload %+v", list.Items[0])
	}

	// A subscription to the failure event, then an upload that Dependency-
	// Track finished without importing (its last import predates the upload).
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.webhook_subscriptions(id,name,url,secret_ciphertext,events) VALUES(gen_random_uuid(),'dt-alerts','https://hooks.example.com/dt','\x00','["dependency_track.upload_failed"]')`); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	dtImportedAt = time.Now().Add(-time.Hour).UnixMilli()
	mu.Unlock()
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.dtrack_uploads SET processing='pending',processing_attempts=0,processed_at=NULL,processing_next_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if checked, err := w.VerifyDependencyTrackOnce(ctx); !checked || err != nil {
		t.Fatal(checked, err)
	}
	if state, detail := processingOf(); state != "failed" || !strings.Contains(detail, "without importing") {
		t.Fatalf("not imported: %s %s", state, detail)
	}
	var failedPayload string
	if err := pool.QueryRow(ctx, `SELECT payload::text FROM `+schema+`.webhook_deliveries WHERE event_type='dependency_track.upload_failed'`).Scan(&failedPayload); err != nil || !strings.Contains(failedPayload, `"stage": "processing"`) && !strings.Contains(failedPayload, `"stage":"processing"`) || !strings.Contains(failedPayload, "org/app") {
		t.Fatalf("failure event %s %v", failedPayload, err)
	}
	if checked, _ := w.VerifyDependencyTrackOnce(ctx); checked {
		t.Fatal("a finished check was repeated")
	}
	// A permanent upload failure (a key without upload permission) announces
	// itself too, at the upload stage.
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dtrack_uploads(id,assessment_id,asset_id,project_name,project_version,sbom_key) VALUES(gen_random_uuid(),gen_random_uuid(),$1,'org/app','dev','sbom')`, app); err != nil {
		t.Fatal(err)
	}
	rejected, err := jobs.ClaimDTrack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.FinishDTrack(ctx, rejected, "", errors.Join(dtrack.ErrRejected, errors.New("HTTP 403")), true); err != nil {
		t.Fatal(err)
	}
	var uploadStage int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.webhook_deliveries WHERE event_type='dependency_track.upload_failed' AND payload::text LIKE '%upload%' AND payload::text LIKE '%HTTP 403%'`).Scan(&uploadStage); err != nil || uploadStage != 1 {
		t.Fatal("upload-stage failure event", uploadStage, err)
	}
	// The status view reports the failure.
	summary, err := jobs.DTrackSummary(ctx)
	if err != nil || summary.ProcessingFailed24h != 1 || summary.FailedLast24h != 1 || summary.Queued != 0 || summary.LastUploadedAt == nil {
		t.Fatalf("summary %+v %v", summary, err)
	}

	// ---- Dependency-Track read-back (F1), shared triage (F4), one entry per vulnerability (F6) ----
	const dtComponentA, dtVulnA1, dtVulnA2 = "aaaaaaaa-0000-0000-0000-00000000000a", "bbbbbbbb-0000-0000-0000-0000000000a1", "bbbbbbbb-0000-0000-0000-0000000000a2"
	const dtComponentB, dtVulnB = "aaaaaaaa-0000-0000-0000-00000000000b", "bbbbbbbb-0000-0000-0000-0000000000b1"
	const dtComponentC, dtVulnC = "aaaaaaaa-0000-0000-0000-00000000000c", "bbbbbbbb-0000-0000-0000-0000000000c1"
	dtFinding := func(component, purl, vulnerability, source, vulnID, severity, analyzer, state string, suppressed bool, aliases string) string {
		return fmt.Sprintf(`{"component":{"uuid":%q,"name":"pkg","version":"1","purl":%q},"vulnerability":{"uuid":%q,"source":%q,"vulnId":%q,"title":"title %s","severity":%q,"cvssV3BaseScore":7.5,"aliases":[%s]},"analysis":{"state":%q,"isSuppressed":%t},"attribution":{"analyzerIdentity":%q}}`,
			component, purl, vulnerability, source, vulnID, vulnID, severity, aliases, state, suppressed, analyzer)
	}
	const lodash = "pkg:npm/lodash@4.17.20"
	allFindings := "[" + strings.Join([]string{
		// SCRS already reports this one under its GHSA ID; Dependency-Track has it
		// twice, once per source. One register entry results.
		dtFinding(dtComponentA, lodash+"?type=x", dtVulnA1, "NVD", "CVE-2021-23337", "HIGH", "INTERNAL_ANALYZER", "NOT_SET", false, ""),
		dtFinding(dtComponentA, lodash, dtVulnA2, "GITHUB", "GHSA-35jh-r3h4-6jhm", "CRITICAL", "TRIVY_ANALYZER", "NOT_SET", false, `{"cveId":"CVE-2021-23337"}`),
		// Only Dependency-Track (through Trivy) reports these two; an analyst
		// already marked the second a false positive there.
		dtFinding(dtComponentB, "pkg:npm/express@4.0.0", dtVulnB, "TRIVY", "CVE-2024-1111", "CRITICAL", "TRIVY_ANALYZER", "NOT_SET", false, ""),
		dtFinding(dtComponentC, "pkg:npm/minimist@1.0.0", dtVulnC, "OSV", "CVE-2020-7598", "MEDIUM", "OSV_ANALYZER", "FALSE_POSITIVE", true, ""),
	}, ",") + "]"
	withoutB := "[" + strings.Join([]string{
		dtFinding(dtComponentA, lodash, dtVulnA1, "NVD", "CVE-2021-23337", "HIGH", "INTERNAL_ANALYZER", "NOT_SET", false, ""),
		dtFinding(dtComponentA, lodash, dtVulnA2, "GITHUB", "GHSA-35jh-r3h4-6jhm", "CRITICAL", "TRIVY_ANALYZER", "NOT_SET", false, `{"cveId":"CVE-2021-23337"}`),
		dtFinding(dtComponentC, "pkg:npm/minimist@1.0.0", dtVulnC, "OSV", "CVE-2020-7598", "MEDIUM", "OSV_ANALYZER", "FALSE_POSITIVE", true, ""),
	}, ",") + "]"
	setFindings := func(body string, status int) {
		mu.Lock()
		dtFindings, dtFindingsStatus = body, status
		mu.Unlock()
	}
	setFindings(allFindings, 200)

	// SCRS's own scan found lodash's vulnerability under the GHSA ID.
	var scrsFinding uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO `+schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES(gen_random_uuid(),$1,'scrs-lodash','main','vulnerability','GHSA-35JH-R3H4-6JHM','lodash command injection','high',45,$2,'{}',$3,$4) RETURNING id`,
		app, `{"name":"lodash","version":"4.17.20","ecosystem":"npm","purl":"`+lodash+`","path":"package-lock.json"}`, `{"aliases":["CVE-2021-23337"]}`, claimed.ID).Scan(&scrsFinding); err != nil {
		t.Fatal(err)
	}

	// Nothing is read back until importing is switched on.
	if synced, _ := w.SyncDependencyTrackOnce(ctx); synced {
		t.Fatal("a project was synced while import_findings is off")
	}
	var current assessments.DTrackSettings
	decode(must(call("GET", "/integrations/dependency-track", reader, "", nil), 200), &current)
	enable := `{"enabled":true,"url":"` + dtrackServer.URL + `","import_findings":true,"sync_triage":true,"tags":["scrs"]}`
	must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":true,"url":"`+dtrackServer.URL+`","sync_triage":true}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, current.Revision)}), 400) // triage needs import
	must(call("PUT", "/integrations/dependency-track", admin, `{"enabled":true,"url":"`+dtrackServer.URL+`","tags":["Bad Tag"]}`, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, current.Revision)}), 400)
	decode(must(call("PUT", "/integrations/dependency-track", admin, enable, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, current.Revision)}), 200), &current)
	if !current.ImportFindings || !current.SyncTriage || len(current.Tags) != 1 {
		t.Fatalf("settings %+v", current)
	}
	// The key now needs more than upload: the test names what is missing.
	var needs map[string]any
	decode(must(call("POST", "/integrations/dependency-track:test", admin, "", nil), 200), &needs)
	if needs["ok"] != false || !strings.Contains(fmt.Sprint(needs["missing_permissions"]), "VIEW_VULNERABILITY") || !strings.Contains(fmt.Sprint(needs["missing_permissions"]), "VULNERABILITY_ANALYSIS") || !strings.Contains(fmt.Sprint(needs["missing_permissions"]), "PORTFOLIO_MANAGEMENT") {
		t.Fatalf("test %+v", needs)
	}
	mu.Lock()
	dtPerms = `[{"name":"BOM_UPLOAD"},{"name":"PROJECT_CREATION_UPLOAD"},{"name":"VIEW_PORTFOLIO"},{"name":"VIEW_VULNERABILITY"},{"name":"VULNERABILITY_ANALYSIS"},{"name":"PORTFOLIO_MANAGEMENT"}]`
	mu.Unlock()
	decode(must(call("POST", "/integrations/dependency-track:test", admin, "", nil), 200), &needs)
	if needs["ok"] != true {
		t.Fatalf("test %+v", needs)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.webhook_subscriptions SET events='["dependency_track.upload_failed","finding.created"]'`); err != nil {
		t.Fatal(err)
	}

	// First sync.
	if synced, err := w.SyncDependencyTrackOnce(ctx); !synced || err != nil {
		t.Fatal(synced, err)
	}
	var dtList struct {
		Items []assessments.DTrackFinding `json:"items"`
	}
	decode(must(call("GET", "/integrations/dependency-track/findings", reader, "", nil), 200), &dtList)
	matchedCount, onlyCount := 0, 0
	for _, f := range dtList.Items {
		if f.Matched {
			matchedCount++
			if f.FindingID == nil || *f.FindingID != scrsFinding {
				t.Fatalf("both sources of lodash's vulnerability join SCRS's entry: %+v", f)
			}
		} else {
			onlyCount++
		}
	}
	if len(dtList.Items) != 4 || matchedCount != 2 || onlyCount != 2 {
		t.Fatalf("dependency-track findings %+v", dtList.Items)
	}
	decode(must(call("GET", "/integrations/dependency-track/findings?matched=false&asset_id="+app.String(), reader, "", nil), 200), &dtList)
	if len(dtList.Items) != 2 {
		t.Fatalf("unmatched %+v", dtList.Items)
	}
	must(call("GET", "/integrations/dependency-track/findings?matched=maybe", reader, "", nil), 400)
	// One register entry per vulnerability: lodash stayed SCRS's single entry.
	var lodashEntries, dtOnly int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.findings WHERE component->>'purl' LIKE 'pkg:npm/lodash%'`).Scan(&lodashEntries)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.findings WHERE type='dt_vulnerability'`).Scan(&dtOnly)
	if lodashEntries != 1 || dtOnly != 2 {
		t.Fatalf("register entries: lodash %d, only in dependency-track %d", lodashEntries, dtOnly)
	}
	var expressID, minimistID uuid.UUID
	var expressStatus, minimistStatus, expressSeverity string
	if err := pool.QueryRow(ctx, `SELECT id,status,severity FROM `+schema+`.findings WHERE advisory_id='CVE-2024-1111'`).Scan(&expressID, &expressStatus, &expressSeverity); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT id,status FROM `+schema+`.findings WHERE advisory_id='CVE-2020-7598'`).Scan(&minimistID, &minimistStatus); err != nil {
		t.Fatal(err)
	}
	// Report-only, shown with its source, and DT's triage imported where SCRS
	// had no decision.
	if expressStatus != "open" || expressSeverity != "critical" || minimistStatus != "false_positive" {
		t.Fatalf("statuses %s %s %s", expressStatus, expressSeverity, minimistStatus)
	}
	var corroborated int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.finding_events WHERE finding_id=$1 AND action='corroborated_by_dependency_track'`, scrsFinding).Scan(&corroborated)
	if corroborated != 1 {
		t.Fatal("the matched entry should record that Dependency-Track corroborates it, once:", corroborated)
	}
	var created string
	if err := pool.QueryRow(ctx, `SELECT string_agg(payload::text,' ') FROM `+schema+`.webhook_deliveries WHERE event_type='finding.created'`).Scan(&created); err != nil || !strings.Contains(created, "CVE-2024-1111") {
		t.Fatalf("finding.created for the new entries: %s %v", created, err)
	}
	var verdictBefore = done.Verdict
	if again, _ := jobs.Get(ctx, claimed.ID); again.Verdict != verdictBefore {
		t.Fatal("imported findings must never change an assessment's verdict")
	}

	// A sync that finds nothing new changes nothing and writes nothing back.
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.dtrack_projects SET next_sync_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if synced, err := w.SyncDependencyTrackOnce(ctx); !synced || err != nil {
		t.Fatal(synced, err)
	}
	mu.Lock()
	writes := len(dtAnalyses)
	mu.Unlock()
	if writes != 0 {
		t.Fatal("imported triage must not be written back:", writes)
	}

	// F4: a person's decision in SCRS reaches both DT findings of that
	// vulnerability at the next sync, which the decision makes due.
	must(call("PATCH", "/register/"+scrsFinding.String(), admin, `{"status":"false_positive","reason":"not reachable in our build"}`, nil), 204)
	var syncDue bool
	_ = pool.QueryRow(ctx, `SELECT next_sync_at<=clock_timestamp() FROM `+schema+`.dtrack_projects`).Scan(&syncDue)
	if !syncDue {
		t.Fatal("a triage decision should make the project's sync due")
	}
	if synced, err := w.SyncDependencyTrackOnce(ctx); !synced || err != nil {
		t.Fatal(synced, err)
	}
	mu.Lock()
	written := append([]map[string]any(nil), dtAnalyses...)
	mu.Unlock()
	if len(written) != 2 {
		t.Fatalf("analysis writes %+v", written)
	}
	for _, a := range written {
		if a["analysisState"] != "FALSE_POSITIVE" || a["isSuppressed"] != true || a["project"] != "11111111-1111-1111-1111-111111111111" || a["component"] != dtComponentA {
			t.Fatalf("analysis %+v", a)
		}
	}
	// Again: already in step, so nothing more is written.
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.dtrack_projects SET next_sync_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	_, _ = w.SyncDependencyTrackOnce(ctx)
	mu.Lock()
	writes = len(dtAnalyses)
	mu.Unlock()
	if writes != 2 {
		t.Fatal("a decision is written once:", writes)
	}
	// Reopening resets Dependency-Track's analysis.
	must(call("PATCH", "/register/"+scrsFinding.String(), admin, `{"status":"open","reason":"reopened after review"}`, nil), 204)
	_, _ = w.SyncDependencyTrackOnce(ctx)
	mu.Lock()
	reset := len(dtAnalyses) == 4 && dtAnalyses[3]["analysisState"] == "NOT_SET" && dtAnalyses[3]["isSuppressed"] == false
	mu.Unlock()
	if !reset {
		t.Fatalf("reopening should reset the analysis: %+v", dtAnalyses)
	}

	// Register aggregates and export cover the same entries as the list.
	var listed struct {
		Items []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(must(call("GET", "/register", admin, "", nil), 200).Body.Bytes(), &listed); err != nil || len(listed.Items) == 0 {
		t.Fatal(err, listed)
	}
	var registerSummary assessments.RegisterSummary
	if err := json.Unmarshal(must(call("GET", "/register/summary", admin, "", nil), 200).Body.Bytes(), &registerSummary); err != nil {
		t.Fatal(err)
	}
	if registerSummary.Total != len(listed.Items) || registerSummary.ByStatus["open"] == 0 || registerSummary.Open == 0 {
		t.Fatalf("registerSummary %+v for %d listed", registerSummary, len(listed.Items))
	}
	if only := must(call("GET", "/register?status=fixed&severity=critical", admin, "", nil), 200); strings.Contains(only.Body.String(), `"status":"open"`) {
		t.Fatal("status filter leaked", only.Body.String())
	}
	must(call("GET", "/register?status=bogus", admin, "", nil), 400)
	must(call("GET", "/register/summary?asset_id=nope", admin, "", nil), 400)
	var series struct {
		Days  int                         `json:"days"`
		Items []assessments.RegisterPoint `json:"items"`
	}
	if err := json.Unmarshal(must(call("GET", "/register/timeseries?days=7", admin, "", nil), 200).Body.Bytes(), &series); err != nil || len(series.Items) != 7 {
		t.Fatal(err, series)
	}
	detected := 0
	for _, point := range series.Items {
		detected += point.Detected
	}
	if detected == 0 {
		t.Fatalf("no detections in %+v", series.Items)
	}
	must(call("GET", "/register/timeseries?days=400", admin, "", nil), 400)
	var top struct {
		Items []assessments.TopAsset `json:"items"`
	}
	if err := json.Unmarshal(must(call("GET", "/register/top-assets?limit=5", admin, "", nil), 200).Body.Bytes(), &top); err != nil || len(top.Items) == 0 || top.Items[0].Open == 0 {
		t.Fatal(err, top)
	}
	must(call("GET", "/register/top-assets?limit=0", admin, "", nil), 400)
	csvExport := must(call("GET", "/register/export", admin, "", nil), 200)
	if !strings.HasPrefix(csvExport.Header().Get("Content-Type"), "text/csv") || !strings.HasPrefix(csvExport.Body.String(), "id,asset_id,") || strings.Count(csvExport.Body.String(), "\n") != len(listed.Items)+1 {
		t.Fatalf("csv export %q", csvExport.Body.String())
	}
	var jsonExport struct {
		Items     []json.RawMessage `json:"items"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal(must(call("GET", "/register/export?format=json", admin, "", nil), 200).Body.Bytes(), &jsonExport); err != nil || len(jsonExport.Items) != len(listed.Items) || jsonExport.Truncated {
		t.Fatal(err, len(jsonExport.Items))
	}
	must(call("GET", "/register/export?format=xml", admin, "", nil), 400)
	var vexDoc struct {
		Context    string           `json:"@context"`
		Statements []map[string]any `json:"statements"`
	}
	if err := json.Unmarshal(must(call("GET", "/register/vex", admin, "", nil), 200).Body.Bytes(), &vexDoc); err != nil || vexDoc.Context != "https://openvex.dev/ns/v0.2.0" || len(vexDoc.Statements) == 0 {
		t.Fatal(err, vexDoc)
	}
	must(call("POST", "/register/summary", admin, "", nil), 405)

	// Assets registered by hand: create, import, discovery, delete, revisions.
	var manual struct {
		ID    uuid.UUID       `json:"id"`
		Flags json.RawMessage `json:"flags"`
	}
	if err := json.Unmarshal(must(call("POST", "/assets", admin, `{"connection":"gh","locator":"org/new-repo","environment":"prod","criticality":3}`, nil), 201).Body.Bytes(), &manual); err != nil || !strings.Contains(string(manual.Flags), `"manual":true`) || !strings.Contains(string(manual.Flags), `"in_scope":true`) {
		t.Fatal(err, string(manual.Flags))
	}
	var again struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(must(call("POST", "/assets", admin, `{"connection":"gh","locator":"ORG/New-Repo"}`, nil), 200).Body.Bytes(), &again); err != nil || again.ID != manual.ID {
		t.Fatal("case-insensitive duplicate must return the existing asset", err)
	}
	must(call("POST", "/assets", admin, `{"connection":"gh","locator":"bad locator"}`, nil), 400)
	must(call("POST", "/assets", admin, `{"connection":"gh","locator":"org/x","type":"container_image"}`, nil), 400)
	must(call("POST", "/assets", admin, `{"connection":"gh","locator":"org/x","environment":"moon"}`, nil), 400)
	must(call("POST", "/assets", admin, `{"connection":"nope","locator":"org/x"}`, nil), 404)
	var bulkResult struct {
		Items []struct {
			Status  string `json:"status"`
			InScope bool   `json:"in_scope"`
		} `json:"items"`
	}
	if err := json.Unmarshal(must(call("POST", "/assets:import", admin, `{"connection":"gh","items":[{"locator":"org/bulk-a"},{"locator":"org/new-repo"},{"locator":"other/outside"},{"locator":"no good"}]}`, nil), 207).Body.Bytes(), &bulkResult); err != nil || len(bulkResult.Items) != 4 {
		t.Fatal(err, bulkResult)
	}
	for i, want := range []string{"created", "exists", "created", "invalid"} {
		if bulkResult.Items[i].Status != want {
			t.Fatalf("import item %d: %+v", i, bulkResult.Items)
		}
	}
	if bulkResult.Items[2].InScope {
		t.Fatal("an asset outside the connection scope must not be in scope")
	}
	must(call("POST", "/assets:import", admin, `{"connection":"gh","items":[]}`, nil), 400)
	// Discovery must keep a manual asset accessible and follow the scope.
	if _, err := store.Discover(ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/app"}}); err != nil {
		t.Fatal(err)
	}
	var manualAsset struct {
		Flags json.RawMessage `json:"flags"`
	}
	if err := json.Unmarshal(must(call("GET", "/assets/"+manual.ID.String(), admin, "", nil), 200).Body.Bytes(), &manualAsset); err != nil || !strings.Contains(string(manualAsset.Flags), `"accessible":true`) || !strings.Contains(string(manualAsset.Flags), `"in_scope":true`) {
		t.Fatal(err, string(manualAsset.Flags))
	}
	var discoveredID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM `+schema+`.assets WHERE locator='org/app'`).Scan(&discoveredID); err != nil {
		t.Fatal(err)
	}
	must(call("DELETE", "/assets/"+discoveredID.String(), admin, "", nil), 409)
	must(call("DELETE", "/assets/"+manual.ID.String(), admin, "", nil), 204)
	must(call("GET", "/assets/"+manual.ID.String(), admin, "", nil), 404)
	must(call("DELETE", "/assets/"+manual.ID.String(), admin, "", nil), 404)
	var revisions struct {
		Items []struct {
			Commit      string `json:"commit"`
			Assessments int    `json:"assessments"`
		} `json:"items"`
	}
	if err := json.Unmarshal(must(call("GET", "/assets/"+discoveredID.String()+"/revisions", admin, "", nil), 200).Body.Bytes(), &revisions); err != nil {
		t.Fatal(err)
	}
	for _, r := range revisions.Items {
		if r.Commit == "" || r.Assessments < 1 {
			t.Fatalf("revision %+v", r)
		}
	}
	must(call("GET", "/assets/"+discoveredID.String()+"/revisions?limit=0", admin, "", nil), 400)
	must(call("GET", "/assets/"+discoveredID.String()+"/revisions?before=yesterday", admin, "", nil), 400)

	// Local advisories over HTTP.
	must(call("POST", "/advisories", admin, `{"summary":"ok","affected":[]}`, nil), 400)
	newAdvisory := must(call("POST", "/advisories", admin, `{"summary":"internal-lib 2.0.1 ships a stealer","details":"Found in incident review.","aliases":["INC-7"],"affected":[{"package":{"ecosystem":"npm","name":"internal-lib"},"versions":["2.0.1"]}],"references":[{"type":"REPORT","url":"https://example.com/inc-7"}]}`, nil), 201)
	var localAdvisory struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(newAdvisory.Body.Bytes(), &localAdvisory); err != nil || !strings.HasPrefix(localAdvisory.ID, "x_SCRS-") || newAdvisory.Header().Get("Location") != BasePath+"/advisories/"+localAdvisory.ID {
		t.Fatal(err, newAdvisory.Header(), newAdvisory.Body.String())
	}
	if found := must(call("GET", "/advisories?q=stealer&origin=local", admin, "", nil), 200); !strings.Contains(found.Body.String(), localAdvisory.ID) {
		t.Fatal(found.Body.String())
	}
	must(call("GET", "/advisories?limit=0", admin, "", nil), 400)
	must(call("GET", "/advisories?withdrawn=maybe", admin, "", nil), 400)
	must(call("GET", "/advisories?cursor=broken", admin, "", nil), 400)
	for _, path := range []string{"/advisories/" + localAdvisory.ID, "/intel/vulnerabilities/" + localAdvisory.ID} {
		if got := must(call("GET", path, admin, "", nil), 200); !strings.Contains(got.Body.String(), "internal-lib") {
			t.Fatal(path, got.Body.String())
		}
	}
	must(call("GET", "/advisories/"+localAdvisory.ID+"/affected", admin, "", nil), 200)
	must(call("GET", "/advisories/x_SCRS-2000-0001", admin, "", nil), 404)
	must(call("POST", "/advisories/"+localAdvisory.ID+":withdraw", admin, `{"reason":"short"}`, nil), 400)
	must(call("POST", "/advisories/"+localAdvisory.ID+":withdraw", admin, `{"reason":"duplicate of another report"}`, nil), 200)
	must(call("POST", "/advisories/"+localAdvisory.ID+":withdraw", admin, `{"reason":"duplicate of another report"}`, nil), 409)
	must(call("DELETE", "/advisories/"+localAdvisory.ID, admin, "", nil), 405)

	// Dependency-Track stops reporting express's vulnerability: its entry
	// closes, its link goes, and the others stay.
	setFindings(withoutB, 200)
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.dtrack_projects SET next_sync_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if synced, err := w.SyncDependencyTrackOnce(ctx); !synced || err != nil {
		t.Fatal(synced, err)
	}
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE id=$1`, expressID).Scan(&expressStatus)
	var linksLeft int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.dtrack_findings`).Scan(&linksLeft)
	if expressStatus != "fixed" || linksLeft != 3 {
		t.Fatalf("express %s, links %d", expressStatus, linksLeft)
	}
	_ = pool.QueryRow(ctx, `SELECT status FROM `+schema+`.findings WHERE id=$1`, minimistID).Scan(&minimistStatus)
	if minimistStatus != "false_positive" {
		t.Fatal("the other entries stay:", minimistStatus)
	}
	// It comes back as the same entry.
	setFindings(allFindings, 200)
	_, _ = pool.Exec(ctx, `UPDATE `+schema+`.dtrack_projects SET next_sync_at=clock_timestamp()`)
	_, _ = w.SyncDependencyTrackOnce(ctx)
	var reopened uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM `+schema+`.findings WHERE advisory_id='CVE-2024-1111' AND status='open'`).Scan(&reopened)
	if reopened != expressID {
		t.Fatal("a returning finding reopens its entry instead of adding another")
	}

	// A key without read permission fails the sync with a clear message,
	// the status view says so, and a manual sync request makes it due again.
	setFindings(`{}`, 403)
	must(call("POST", "/integrations/dependency-track:sync", writer, "", nil), 403)
	var queued map[string]int
	decode(must(call("POST", "/integrations/dependency-track:sync", admin, "", nil), 202), &queued)
	if queued["projects_queued"] != 1 {
		t.Fatalf("queued %+v", queued)
	}
	if synced, err := w.SyncDependencyTrackOnce(ctx); !synced || err != nil {
		t.Fatal(synced, err)
	}
	var syncStatus, syncError string
	_ = pool.QueryRow(ctx, `SELECT status,error FROM `+schema+`.dtrack_projects`).Scan(&syncStatus, &syncError)
	if syncStatus != "error" || !strings.Contains(syncError, "VIEW_VULNERABILITY") {
		t.Fatalf("sync status %s %q", syncStatus, syncError)
	}
	summary, err = jobs.DTrackSummary(ctx)
	if err != nil || summary.SyncErrors != 1 || summary.LastSyncedAt == nil || summary.OnlyDTrackOpen != 1 {
		t.Fatalf("summary %+v %v", summary, err)
	}

	// A PDF report of the STIG pack, built as the worker would.
	var job assessments.ReportJob
	decode(must(call("POST", "/reports", writer, `{"framework":"`+imported.Pack.ID+`","scope":{"kind":"portfolio"},"format":"pdf"}`, nil), 202), &job)
	claimedReport, err := jobs.ClaimReport(ctx)
	if err != nil || claimedReport == nil {
		t.Fatal(err)
	}
	packData, input, err := jobs.ReportInput(ctx, *claimedReport)
	if err != nil {
		t.Fatal(err)
	}
	report := compliance.Build(packData, input)
	if report.STIG == nil || report.STIG.Rules != 4 {
		t.Fatalf("stig report %+v", report.STIG)
	}
	file, err := compliance.Render(report, "pdf")
	if err != nil {
		t.Fatal(err)
	}
	reportKey := "reports/" + assessments.Hash(file) + ".pdf"
	artifacts[reportKey] = file
	if err := jobs.FinishReport(ctx, *claimedReport, reportKey, assessments.Hash(file), int64(len(file)), input.DataAsOf, "test", report.Feeds, map[string]int{"gaps": len(report.Gaps)}); err != nil {
		t.Fatal(err)
	}
	download := must(call("GET", "/reports/"+job.ID.String()+"/download", reader, "", nil), 200)
	if download.Header().Get("Content-Type") != "application/pdf" || !strings.HasPrefix(download.Body.String(), "%PDF-1.4") || !strings.HasSuffix(download.Header().Get("Content-Disposition"), `.pdf"`) {
		t.Fatalf("pdf download %v", download.Header())
	}
}
