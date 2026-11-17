package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func sourceArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// Uploaded source archives through the real router: the built-in connection
// stays out of sight and cannot be edited, an archive becomes an `uploaded`
// asset with a revision and a queued assessment, and bad input is refused.
func TestPostgresUploadedAssetsAPI(t *testing.T) {
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
	artifacts := memoryArtifacts{}
	jobs.UseObjects(artifacts)
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Redis: rdb, Assessments: jobs, Artifacts: artifacts, Notify: events, Live: &notify.Hub{MaxStreams: 10, PerToken: 2}})

	do := func(method, path, contentType string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, bytes.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+admin)
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	form := func(fields map[string]string, file []byte) (string, []byte) {
		var buf bytes.Buffer
		m := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = m.WriteField(k, v)
		}
		if file != nil {
			part, _ := m.CreateFormFile("file", "src.tar.gz")
			_, _ = part.Write(file)
		}
		_ = m.Close()
		return m.FormDataContentType(), buf.Bytes()
	}
	expect := func(w *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
		t.Helper()
		if w.Code != status {
			t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
		}
		return w
	}

	one := sourceArchive(t, map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{}}`})
	contentType, body := form(map[string]string{"name": "Demo-App", "ref": "v1"}, one)
	var created struct {
		Asset      connections.Asset  `json:"asset"`
		Upload     assessments.Upload `json:"upload"`
		Assessment *struct {
			ID     uuid.UUID `json:"id"`
			Status string    `json:"status"`
		} `json:"assessment"`
		Error string `json:"assessment_error"`
	}
	w := expect(do("POST", "/uploads", contentType, body), 201)
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Asset.Type != "uploaded" || created.Asset.Locator != "upload/demo-app" || len(created.Upload.Commit) != 40 || created.Upload.Size != int64(len(one)) || created.Assessment == nil || created.Assessment.Status != "queued" || created.Error != "" {
		t.Fatalf("unexpected upload result: %s", w.Body.String())
	}
	if !strings.Contains(string(created.Asset.Flags), `"in_scope":true`) || !strings.Contains(string(created.Asset.Flags), `"upload":true`) {
		t.Fatalf("flags: %s", created.Asset.Flags)
	}
	if len(artifacts) != 1 {
		t.Fatalf("archive was not stored once: %d objects", len(artifacts))
	}
	// The assessment targets the archive's revision.
	got, err := jobs.Get(ctx, created.Assessment.ID)
	if err != nil || got.Request.Target.Type != "upload" || got.Request.Target.Commit != created.Upload.Commit || got.Request.Target.Repository != "upload/demo-app" || got.Request.Target.Ref != "v1" {
		t.Fatalf("assessment target: %+v %v", got.Request.Target, err)
	}
	key, err := jobs.UploadObjectKey(ctx, created.Asset.ID, created.Upload.Commit)
	if err != nil || artifacts[key] == nil {
		t.Fatalf("worker lookup: %q %v", key, err)
	}

	// The same archive again keeps the asset and the upload; it is not a new revision.
	// The first assessment still holds the asset, so queueing another is reported, not fatal.
	contentType, body = form(map[string]string{"name": "demo-app", "ref": "v1"}, one)
	var again struct {
		Asset  connections.Asset  `json:"asset"`
		Upload assessments.Upload `json:"upload"`
		Error  string             `json:"assessment_error"`
	}
	if err := json.Unmarshal(expect(do("POST", "/uploads", contentType, body), 200).Body.Bytes(), &again); err != nil {
		t.Fatal(err)
	}
	if again.Asset.ID != created.Asset.ID || again.Upload.ID != created.Upload.ID {
		t.Fatalf("a repeated archive must reuse asset and upload: %+v", again)
	}

	// A different archive under the same name is a second revision.
	two := sourceArchive(t, map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`})
	contentType, body = form(map[string]string{"name": "demo-app", "assess": "false"}, two)
	var second struct {
		Upload     assessments.Upload `json:"upload"`
		Assessment any                `json:"assessment"`
	}
	if err := json.Unmarshal(expect(do("POST", "/uploads", contentType, body), 201).Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if second.Upload.Commit == created.Upload.Commit || second.Assessment != nil {
		t.Fatalf("second revision: %+v", second)
	}
	var listed struct {
		Items []assessments.Upload `json:"items"`
	}
	if err := json.Unmarshal(expect(do("GET", "/assets/"+created.Asset.ID.String()+"/uploads", "", nil), 200).Body.Bytes(), &listed); err != nil || len(listed.Items) != 2 || listed.Items[0].Commit != second.Upload.Commit {
		t.Fatalf("upload list: %+v %v", listed, err)
	}
	expect(do("GET", "/assets/"+uuid.NewString()+"/uploads", "", nil), 404)

	// Input checks.
	contentType, body = form(map[string]string{"name": "x"}, []byte("not gzip"))
	expect(do("POST", "/uploads", contentType, body), 422)
	contentType, body = form(map[string]string{"name": "Bad Name!"}, one)
	expect(do("POST", "/uploads", contentType, body), 400)
	contentType, body = form(map[string]string{}, one)
	expect(do("POST", "/uploads", contentType, body), 400)
	contentType, body = form(map[string]string{"name": "x", "colour": "red"}, one)
	expect(do("POST", "/uploads", contentType, body), 400)
	expect(do("POST", "/uploads", "application/json", []byte(`{"name":"x"}`)), 415)

	// The built-in connection is not listed and cannot be changed or discovered.
	var list []connections.Connection
	if err := json.Unmarshal(expect(do("GET", "/connections", "", nil), 200).Body.Bytes(), &list); err != nil || len(list) != 0 {
		t.Fatalf("connection list should hide the built-in connection: %+v %v", list, err)
	}
	id := created.Asset.ConnectionID.String()
	expect(do("PATCH", "/connections/"+id, "application/json", []byte(`{"enabled":false}`)), 409)
	expect(do("POST", "/connections/"+id+":discover", "", nil), 409)
	expect(do("POST", "/connections/"+id+":rotate-credential", "application/json", []byte(`{"credential":{}}`)), 409)
	expect(do("POST", "/connections", "application/json", []byte(`{"provider":"upload","name":"mine","config":{},"scope":{"include":["*"]},"credential":{}}`)), 400)
	// Manual registration cannot create uploaded assets, and delete never removes one.
	var imported struct {
		Items []struct{ Status, Error string } `json:"items"`
	}
	if err := json.Unmarshal(expect(do("POST", "/assets:import", "application/json", []byte(`{"connection":"scrs-uploads","items":[{"locator":"upload/x"}]}`)), 207).Body.Bytes(), &imported); err != nil || imported.Items[0].Status != "invalid" {
		t.Fatalf("manual import into uploads: %+v %v", imported, err)
	}
	expect(do("DELETE", "/assets/"+created.Asset.ID.String(), "", nil), 409)

	// Revisions and the SBOM diff see the upload target like any other once assessed.
	expect(do("GET", "/assets/"+created.Asset.ID.String()+"/revisions", "", nil), 200)

	// Deleting an upload: not while an assessment of it is queued, not for a stranger's id.
	assetPath := "/assets/" + created.Asset.ID.String()
	expect(do("DELETE", assetPath+"/uploads/"+created.Upload.ID.String(), "", nil), 409)
	expect(do("DELETE", assetPath+"/uploads/"+uuid.NewString(), "", nil), 404)
	expect(do("DELETE", "/assets/"+uuid.NewString()+"/uploads/"+second.Upload.ID.String(), "", nil), 404)
	expect(do("DELETE", assetPath+"/uploads/"+second.Upload.ID.String(), "", nil), 204)
	secondKey := "uploads/" + second.Upload.SHA256 + ".tar.gz"
	if _, ok := artifacts[secondKey]; ok {
		t.Fatal("the archive object was not deleted with its upload")
	}
	if _, ok := artifacts[key]; !ok {
		t.Fatal("deleting one upload removed another's archive")
	}
	expect(do("DELETE", assetPath+"/uploads/"+second.Upload.ID.String(), "", nil), 404)
	if err := json.Unmarshal(expect(do("GET", assetPath+"/uploads", "", nil), 200).Body.Bytes(), &listed); err != nil || len(listed.Items) != 1 {
		t.Fatalf("after delete: %+v %v", listed, err)
	}
	// An assessed asset keeps its history, so it cannot be deleted; an unassessed one can.
	expect(do("DELETE", assetPath, "", nil), 409)
	contentType, body = form(map[string]string{"name": "scratch", "assess": "false"}, two)
	var scratch struct {
		Asset connections.Asset `json:"asset"`
	}
	if err := json.Unmarshal(expect(do("POST", "/uploads", contentType, body), 201).Body.Bytes(), &scratch); err != nil {
		t.Fatal(err)
	}
	if _, ok := artifacts[secondKey]; !ok {
		t.Fatal("the scratch archive was not stored")
	}
	expect(do("DELETE", "/assets/"+scratch.Asset.ID.String(), "", nil), 204)
	expect(do("GET", "/assets/"+scratch.Asset.ID.String(), "", nil), 404)
	if _, ok := artifacts[secondKey]; ok {
		t.Fatal("deleting an uploaded asset left its archive behind")
	}

	// Retention: archives a newer upload with the same label replaced go after
	// their time; the newest per label, held assets and queued work stay.
	var retained connections.Asset
	var shas []string
	for i, label := range []string{"r", "r", "r", "other"} {
		archive := sourceArchive(t, map[string]string{"f": strings.Repeat("x", i+1)})
		contentType, body = form(map[string]string{"name": "retained", "ref": label, "assess": "false"}, archive)
		var r struct {
			Asset  connections.Asset  `json:"asset"`
			Upload assessments.Upload `json:"upload"`
		}
		if err := json.Unmarshal(expect(do("POST", "/uploads", contentType, body), 201).Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		retained = r.Asset
		shas = append(shas, r.Upload.SHA256)
		// Oldest first, all well past the retention period.
		if _, err := pool.Exec(ctx, "UPDATE "+schema+".uploads SET created_at=now()-($2*interval '1 day') WHERE id=$1", r.Upload.ID, 100-i*10); err != nil {
			t.Fatal(err)
		}
	}
	// Within the period an archive is kept even when replaced: only the 100-day-old one is older than 95 days.
	young := 1
	if n, err := jobs.PreviewRetentionClasses(ctx, map[string]*int{"uploaded_archives": &young}); err != nil || n["uploaded_archives"] != 2 {
		t.Fatalf("preview with 1 day: %v %v", n, err)
	}
	long := 95
	if n, err := jobs.PreviewRetentionClasses(ctx, map[string]*int{"uploaded_archives": &long}); err != nil || n["uploaded_archives"] != 1 {
		t.Fatalf("preview with 95 days: %v %v", n, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".assets SET legal_hold=true WHERE id=$1", retained.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := jobs.PreviewRetentionClasses(ctx, map[string]*int{"uploaded_archives": &young}); err != nil || n["uploaded_archives"] != 0 {
		t.Fatalf("a legal hold must protect archives: %v %v", n, err)
	}
	expect(do("DELETE", "/assets/"+retained.ID.String()+"/uploads/"+uuid.NewString(), "", nil), 404)
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".assets SET legal_hold=false WHERE id=$1", retained.ID); err != nil {
		t.Fatal(err)
	}
	policy, err := jobs.Retention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.SetRetentionClasses(ctx, uuid.Nil, policy.Revision, map[string]*int{"uploaded_archives": &young}); err != nil {
		t.Fatal(err)
	}
	policy, _ = jobs.Retention(ctx)
	purged, err := jobs.PurgeRetention(ctx, uuid.Nil, policy.Revision)
	if err != nil || purged["uploaded_archives"] != 2 {
		t.Fatalf("purged %v %v", purged, err)
	}
	if err := json.Unmarshal(expect(do("GET", "/assets/"+retained.ID.String()+"/uploads", "", nil), 200).Body.Bytes(), &listed); err != nil || len(listed.Items) != 2 {
		t.Fatalf("after retention: %+v %v", listed, err)
	}
	for i, sha := range shas {
		_, present := artifacts["uploads/"+sha+".tar.gz"]
		if present != (i >= 2) {
			t.Fatalf("archive %d present=%v after retention", i, present)
		}
	}
}
