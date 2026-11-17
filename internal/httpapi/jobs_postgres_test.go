package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
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

// The unified job view over every queue: normalised statuses, filters,
// cursor paging, lookup by id and cancelling the kinds that can be stopped.
func TestPostgresJobsAPI(t *testing.T) {
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
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Artifacts: memoryArtifacts{}, Notify: events, Live: &notify.Hub{MaxStreams: 10, PerToken: 2}})
	issue := func(scope string) string {
		_, secret, err := store.CreateToken(ctx, connections.Token{Name: "jobs-" + scope, Scopes: []string{scope}}, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	call := func(method, path, token string, body []byte, contentType string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, bytes.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	expect := func(w *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
		t.Helper()
		if w.Code != status {
			t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
		}
		return w
	}
	upload := func(name string, content string) (asset uuid.UUID, assessment uuid.UUID) {
		var buf bytes.Buffer
		m := multipart.NewWriter(&buf)
		_ = m.WriteField("name", name)
		part, _ := m.CreateFormFile("file", "src.tar.gz")
		_, _ = part.Write(sourceArchive(t, map[string]string{"f": content}))
		_ = m.Close()
		var out struct {
			Asset      connections.Asset `json:"asset"`
			Assessment struct {
				ID uuid.UUID `json:"id"`
			} `json:"assessment"`
		}
		if err := json.Unmarshal(expect(call("POST", "/uploads", admin, buf.Bytes(), m.FormDataContentType()), 201).Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Asset.ID, out.Assessment.ID
	}
	assetA, assessA := upload("job-a", "a")
	_, assessB := upload("job-b", "b")

	// One job of every other kind, inserted directly: the queues that make them need a model host,
	// a runner or a Dependency-Track server.
	qaRun, summary, report, mirror, dtrack := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, sql := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO " + schema + ".qa_runs(id,asset_id,kind,trigger,requested_by,status) VALUES($1,$2,'functional','manual','tester','passed')", []any{qaRun, assetA}},
		{"INSERT INTO " + schema + ".ai_summaries(id,asset_id,assessment_id,requested_by,status) VALUES($1,$2,$3,'tester','queued')", []any{summary, assetA, assessA}},
		{"INSERT INTO " + schema + ".reports(id,framework,scope,format,status) VALUES($1,'owasp-top10-2025','{\"kind\":\"portfolio\"}','json','failed')", []any{report}},
		{"INSERT INTO " + schema + ".asset_mirrors(id,asset_id,requested_by,status) VALUES($1,$2,'tester','pruned')", []any{mirror, assetA}},
		{"INSERT INTO " + schema + ".dtrack_uploads(id,assessment_id,asset_id,project_name,project_version,sbom_key,status) VALUES($1,$2,$3,'p','v','sbom/x','sending')", []any{dtrack, assessB, assetA}},
	} {
		if _, err := pool.Exec(ctx, sql.query, sql.args...); err != nil {
			t.Fatal(err)
		}
	}

	type page struct {
		Items      []assessments.Job `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	list := func(query string) page {
		var p page
		if err := json.Unmarshal(expect(call("GET", "/jobs"+query, admin, nil, ""), 200).Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	all := list("")
	if len(all.Items) != 7 || all.NextCursor != "" {
		t.Fatalf("expected 7 jobs, got %d: %+v", len(all.Items), all.Items)
	}
	byID := map[uuid.UUID]assessments.Job{}
	for _, j := range all.Items {
		byID[j.ID] = j
		if j.Resource == "" {
			t.Errorf("job %s has no resource", j.ID)
		}
	}
	for id, want := range map[uuid.UUID][3]string{
		assessA: {"assessment", "queued", "queued"},
		qaRun:   {"qa_run", "succeeded", "passed"},
		summary: {"ai_summary", "queued", "queued"},
		report:  {"report", "failed", "failed"},
		mirror:  {"mirror", "succeeded", "pruned"},
		dtrack:  {"dependency_track_upload", "running", "sending"},
	} {
		if j := byID[id]; j.Kind != want[0] || j.Status != want[1] || j.State != want[2] {
			t.Errorf("job %s: %+v, want %v", id, j, want)
		}
	}
	if byID[report].AssetID != nil || byID[mirror].AssetID == nil {
		t.Errorf("asset ids: report %v mirror %v", byID[report].AssetID, byID[mirror].AssetID)
	}
	if len(list("?kind=assessment").Items) != 2 || len(list("?status=queued").Items) != 3 || len(list("?kind=qa_run&status=succeeded").Items) != 1 {
		t.Fatal("kind and status filters")
	}
	if got := list("?asset_id=" + assetA.String()); len(got.Items) != 5 {
		t.Fatalf("asset filter: %d", len(got.Items))
	}
	if len(list("?since="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)).Items) != 0 {
		t.Fatal("since filter")
	}
	// Paging reaches every job once.
	seen := map[uuid.UUID]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		p := list("?limit=3&cursor=" + cursor)
		if len(p.Items) > 3 {
			t.Fatalf("page of %d", len(p.Items))
		}
		for _, j := range p.Items {
			if seen[j.ID] {
				t.Fatalf("job %s listed twice", j.ID)
			}
			seen[j.ID] = true
		}
		if cursor = p.NextCursor; cursor == "" {
			break
		}
	}
	if len(seen) != 7 {
		t.Fatalf("paging saw %d jobs", len(seen))
	}
	for _, bad := range []string{"?kind=nope", "?status=nope", "?limit=0", "?limit=500", "?asset_id=x", "?since=yesterday", "?cursor=!!"} {
		expect(call("GET", "/jobs"+bad, admin, nil, ""), 400)
	}

	// Lookup by id, whatever the kind.
	for id := range byID {
		expect(call("GET", "/jobs/"+id.String(), admin, nil, ""), 200)
	}
	expect(call("GET", "/jobs/"+uuid.NewString(), admin, nil, ""), 404)
	expect(call("GET", "/jobs/not-a-uuid", admin, nil, ""), 404)

	// Scopes: read lists but cannot cancel; trigger sees nothing.
	read, write, trigger := issue("read"), issue("write"), issue("trigger")
	expect(call("GET", "/jobs", read, nil, ""), 200)
	expect(call("GET", "/jobs", trigger, nil, ""), 403)
	expect(call("POST", "/jobs/"+assessA.String()+":cancel", read, nil, ""), 403)
	expect(call("POST", "/jobs/"+assessA.String()+":cancel", write, nil, ""), 403)

	// Cancelling: assessments and QA runs only, and only while unfinished.
	var cancelled assessments.Job
	if err := json.Unmarshal(expect(call("POST", "/jobs/"+assessA.String()+":cancel", admin, nil, ""), 200).Body.Bytes(), &cancelled); err != nil || cancelled.Status != "cancelled" {
		t.Fatalf("cancel: %+v %v", cancelled, err)
	}
	expect(call("POST", "/jobs/"+assessA.String()+":cancel", admin, nil, ""), 409)
	queuedRun := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO "+schema+".qa_runs(id,asset_id,kind,trigger,requested_by,status) VALUES($1,$2,'functional','manual','tester','queued')", queuedRun, assetA); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expect(call("POST", "/jobs/"+queuedRun.String()+":cancel", admin, nil, ""), 200).Body.Bytes(), &cancelled); err != nil || cancelled.Kind != "qa_run" || cancelled.Status != "cancelled" {
		t.Fatalf("cancel QA run: %+v %v", cancelled, err)
	}
	expect(call("POST", "/jobs/"+qaRun.String()+":cancel", admin, nil, ""), 409)
	expect(call("POST", "/jobs/"+summary.String()+":cancel", admin, nil, ""), 409)
	expect(call("POST", "/jobs/"+uuid.NewString()+":cancel", admin, nil, ""), 404)
	expect(call("GET", "/jobs/"+assessA.String()+":cancel", admin, nil, ""), 405)
}
