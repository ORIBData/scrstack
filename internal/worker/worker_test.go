package worker

import (
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
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type syntheticSource struct{}

func (syntheticSource) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return []connections.Resource{{Type: "github_repo", Locator: "org/repo"}}, nil
}
func (syntheticSource) Snapshot(_ context.Context, _ connections.Connection, _ json.RawMessage, _, _, _ string) ([]byte, string, bool, error) {
	return []byte("synthetic archive"), strings.Repeat("a", 40), false, nil
}

// recordingSource captures the ref the worker asks the provider to resolve.
type recordingSource struct {
	syntheticSource
	refs []string
}

func (r *recordingSource) Snapshot(ctx context.Context, c connections.Connection, s json.RawMessage, repo, ref, commit string) ([]byte, string, bool, error) {
	r.refs = append(r.refs, ref)
	return r.syntheticSource.Snapshot(ctx, c, s, repo, ref, commit)
}

type snapshotSink struct{ keys int }

func (s *snapshotSink) PutSnapshot(context.Context, []byte) (string, error) {
	s.keys++
	return "snapshots/" + strings.Repeat("b", 64) + ".tar.gz", nil
}

type artifactSink struct{ saved []byte }

func (s *artifactSink) PutSBOM(_ context.Context, b []byte) (string, string, error) {
	s.saved = append([]byte{}, b...)
	digest := assessments.Hash(b)
	return "sbom/" + digest + ".cdx.json", digest, nil
}
func (s *artifactSink) PutPlan(_ context.Context, b []byte) (string, string, error) {
	s.saved = append([]byte{}, b...)
	digest := assessments.Hash(b)
	return "remediation/" + digest + ".json", digest, nil
}
func TestPostgresWorkerPublishesAndRejectsRevokedScope(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic-secret-must-not-reach-scanner"}`), false); err != nil {
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
	actor := uuid.New()
	req := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
	if _, _, err := jobs.Enqueue(ctx, req, actor, "tester", "assessment"); err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != "synthetic archive" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("scanner boundary violated")
		}
		_ = json.NewEncoder(w).Encode(scanner.Output{Components: []assessments.Component{{Name: "pkg", Version: "1", Ecosystem: "npm", PURL: "pkg:npm/pkg@1", Path: "package-lock.json"}}, SBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), Stages: []assessments.Stage{{Name: "malware", Status: "skipped"}}})
	}))
	defer server.Close()
	sink := &artifactSink{}
	w := Worker{Store: jobs, Connections: providers, Source: syntheticSource{}, Artifacts: sink, ScannerURL: server.URL + "/scan", ScannerToken: token, Logger: slog.Default()}
	if err := w.run(ctx, &job); err != nil {
		t.Fatal(err)
	}
	result, err := jobs.Get(ctx, job.ID)
	if err != nil || result.Status != "succeeded" || result.Verdict != "incomplete" || result.Commit != strings.Repeat("a", 40) || len(sink.saved) == 0 {
		t.Fatal("worker result not persisted", result, err)
	}
	// A PR assessment pins the head commit and must not resolve its "pull/N" label as a ref.
	prReq := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Commit: strings.Repeat("a", 40), PullRequest: &assessments.PullRequest{Number: 9, BaseRef: "main"}}}
	if _, _, err := jobs.Enqueue(ctx, prReq, actor, "tester", "pull-request"); err != nil {
		t.Fatal(err)
	}
	prJob, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recorder, snaps := &recordingSource{}, &snapshotSink{}
	prWorker := w
	prWorker.Source, prWorker.Snapshots = recorder, snaps
	if err := prWorker.run(ctx, &prJob); err != nil {
		t.Fatal(err)
	}
	if len(recorder.refs) != 1 || recorder.refs[0] != "" || snaps.keys != 1 {
		t.Fatal("PR label resolved as a ref or snapshot not stored", recorder.refs, snaps.keys)
	}
	if saved, err := jobs.Get(ctx, prJob.ID); err != nil || saved.SnapshotKey == "" || saved.Request.Target.Ref != "pull/9" {
		t.Fatal("PR assessment or snapshot link not persisted", saved, err)
	}
	if _, _, err := jobs.Enqueue(ctx, req, actor, "tester", "revocation"); err != nil {
		t.Fatal(err)
	}
	revoked, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a scope/credential revision after admission; no scanner result may publish.
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".connections SET configuration_revision=configuration_revision+1 WHERE id=$1", revoked.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx, &revoked); err != assessments.ErrScope {
		t.Fatal("revoked configuration accepted", err)
	}
}

type imageInventory struct{}

func (imageInventory) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return []connections.Resource{{Type: "container_image", Locator: "docker.io/library/app"}}, nil
}

// fakeRegistry streams a synthetic archive and reports a platform digest.
type fakeRegistry struct{ digest string }

func (f fakeRegistry) ImageArchive(_ context.Context, _ connections.Connection, _ json.RawMessage, locator, tag, digest, platform string, _ int64, w io.Writer) (string, error) {
	if locator != "docker.io/library/app" || platform != "linux/amd64" || (tag != "1.2" && digest != f.digest) {
		return "", errors.New("unexpected image request")
	}
	_, err := io.WriteString(w, "synthetic image archive")
	return f.digest, err
}

func TestPostgresWorkerAssessesImageByDigest(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	hub := connections.Connection{Name: "hub", Provider: "dockerhub", Config: json.RawMessage(`{"namespace":"library","identifier":"bot"}`), Scope: connections.Scope{Include: []string{"docker.io/library/*"}}}
	if _, err := providers.Put(ctx, hub, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, "hub", imageInventory{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	actor := uuid.New()
	for _, bad := range []assessments.Target{{Type: "image", Repository: "docker.io/library/app", Ref: "bad tag!"}, {Type: "image", Repository: "docker.io/library/app", Platform: "windows/amd64"}, {Type: "image", Repository: "docker.io/library/app", Commit: strings.Repeat("a", 40)}} {
		if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: bad}, actor, "tester", ""); !errors.Is(err, assessments.ErrInput) {
			t.Fatal("invalid image target accepted", bad, err)
		}
	}
	if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "image", Repository: "docker.io/library/other"}}, actor, "tester", ""); !errors.Is(err, assessments.ErrScope) {
		t.Fatal("undiscovered image admitted", err)
	}
	if _, _, err := jobs.Enqueue(ctx, assessments.Request{Target: assessments.Target{Type: "image", Repository: "docker.io/library/app", Ref: "1.2"}}, actor, "tester", "image"); err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 40)
	// Enabled rulesets travel ahead of the image, which streams as the last part.
	if _, err := jobs.CreateRuleSet(ctx, assessments.RuleSetRecord{Name: "team_hunt", Kind: "custom", Mode: "hunt", Severity: "low", Enabled: true, Rules: "rule A { condition: true }"}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var parts []string
		image := ""
		if reader, err := r.MultipartReader(); err == nil {
			for {
				part, err := reader.NextPart()
				if err != nil {
					break
				}
				body, _ := io.ReadAll(part)
				parts = append(parts, part.FormName())
				if part.FormName() == "image" {
					image = string(body)
				}
			}
		}
		if r.URL.Path != "/scan-image" || image != "synthetic image archive" || strings.Join(parts, ",") != "rules,image" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("image not streamed to the scanner image endpoint after its rules", parts)
		}
		_ = json.NewEncoder(w).Encode(scanner.Output{Components: []assessments.Component{{Name: "busybox", Version: "1.36.1-r15", Ecosystem: "Alpine:v3.19", PURL: "pkg:apk/alpine/busybox@1.36.1-r15", Path: "lib/apk/db/installed"}}, SBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), Stages: []assessments.Stage{{Name: "inventory", Status: "ok"}, {Name: "malware", Status: "skipped"}}})
	}))
	defer server.Close()
	digest := "sha256:" + strings.Repeat("d", 64)
	w := Worker{Store: jobs, Connections: providers, Images: fakeRegistry{digest}, Artifacts: &artifactSink{}, ScannerURL: server.URL + "/scan", ScannerToken: token, Logger: slog.Default()}
	if err := w.run(ctx, &job); err != nil {
		t.Fatal(err)
	}
	saved, err := jobs.Get(ctx, job.ID)
	if err != nil || saved.Status != "succeeded" || saved.Commit != digest || saved.Verdict != "incomplete" || saved.Request.Target.Platform != "linux/amd64" {
		t.Fatal("image assessment not published by digest", saved, err)
	}
	latest, err := jobs.Latest(ctx, uuid.Nil, "docker.io/library/app", digest, uuid.Nil)
	if err != nil || latest.ID != job.ID {
		t.Fatal("latest-by-digest lookup failed", err)
	}
}

type fakeMirrorSource struct{ fail bool }

func (f fakeMirrorSource) Mirror(_ context.Context, _ connections.Connection, _ json.RawMessage, repo string, _ int64, w io.Writer) (connections.MirrorInfo, error) {
	if _, err := io.WriteString(w, "# v2 git bundle\n"+repo+"\n"); err != nil {
		return connections.MirrorInfo{}, err
	}
	if f.fail {
		return connections.MirrorInfo{}, errors.New("git fetch failed")
	}
	return connections.MirrorInfo{Refs: 2, Head: strings.Repeat("a", 40)}, nil
}

type mirrorSink struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (m *mirrorSink) PutMirror(_ context.Context, id string, r io.Reader) (string, int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects["mirrors/"+id+".bundle"] = data
	return "mirrors/" + id + ".bundle", int64(len(data)), nil
}
func (m *mirrorSink) DeleteMirror(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

// Mirror jobs stream source -> hash -> object store, record the digest, and
// remove partial uploads when the fetch fails.
func TestPostgresWorkerMirrors(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: db, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, db)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, "gh", syntheticSource{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	var asset uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM "+schema+".assets LIMIT 1").Scan(&asset); err != nil {
		t.Fatal(err)
	}
	sink := &mirrorSink{objects: map[string][]byte{}}
	for _, fail := range []bool{false, true} {
		m, _, err := jobs.RequestMirror(ctx, asset, "test")
		if err != nil {
			t.Fatal(err)
		}
		w := Worker{Store: jobs, Connections: providers, Mirrors: sink, MirrorSource: fakeMirrorSource{fail: fail}, KeepMirrors: 5, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		loop, stop := context.WithCancel(ctx)
		go w.RunMirrors(loop)
		deadline := time.Now().Add(20 * time.Second)
		for {
			got, err := jobs.GetMirror(ctx, asset, m.ID)
			if err == nil && (got.Status == "succeeded" || got.Status == "failed") {
				m = got
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("mirror not processed", got, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		stop()
		sink.mu.Lock()
		data := sink.objects["mirrors/"+m.ID.String()+".bundle"]
		sink.mu.Unlock()
		if !fail && (m.Status != "succeeded" || m.SHA256 != assessments.Hash(data) || m.SizeBytes != int64(len(data)) || m.Refs != 2) {
			t.Fatal("mirror record does not match stored bundle", m)
		}
		if fail && (m.Status != "failed" || data != nil) {
			t.Fatal("failed mirror left a partial bundle", m, len(data))
		}
	}
}

func TestFailurePolicy(t *testing.T) {
	cases := []struct {
		err   error
		retry bool
	}{
		{errors.New("scanner unavailable"), true},
		{assessments.ErrScope, false},
		{fmt.Errorf("%w: archive exceeded 64 MiB download limit", connections.ErrTooLarge), false},
		{errScannerRejected, false},
	}
	for _, c := range cases {
		if retry, message := failurePolicy(c.err); retry != c.retry || message == "" {
			t.Error("failure policy", c.err, retry, message)
		}
	}
}

// oversizeSource reports an archive above the download limit.
type oversizeSource struct{ syntheticSource }

func (oversizeSource) Snapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error) {
	return nil, "", false, fmt.Errorf("%w: archive exceeded 64 MiB download limit", connections.ErrTooLarge)
}

// A busy scanner requeues the job without spending an attempt; size-limit
// rejections surface as non-retryable; the multipart body streams intact.
func TestPostgresWorkerScannerBackPressureAndLimits(t *testing.T) {
	db := os.Getenv("SCRS_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
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
	if _, err := jobs.ImportIndicators(ctx, uuid.Nil, []byte(`{"version":"w-v1","indicators":[{"id":"ioc-1","type":"domain","value":"bad.example","valid_until":"2099-01-01T00:00:00Z"}]}`)); err != nil {
		t.Fatal(err)
	}
	req := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
	if _, _, err := jobs.Enqueue(ctx, req, uuid.New(), "tester", "busy"); err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx)
	if err != nil || job.Attempts != 1 {
		t.Fatal(job.Attempts, err)
	}
	token := strings.Repeat("x", 40)
	status := http.StatusTooManyRequests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The streamed multipart body must still carry the archive and bundle.
		if err := r.ParseMultipartForm(1 << 20); err != nil || r.FormValue("indicators") == "" {
			t.Error("multipart scan request malformed", err)
		} else if f, _, err := r.FormFile("archive"); err != nil {
			t.Error("archive part missing", err)
		} else if b, _ := io.ReadAll(f); string(b) != "synthetic archive" {
			t.Error("archive part altered", string(b))
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	w := Worker{Store: jobs, Connections: providers, Source: syntheticSource{}, Artifacts: &artifactSink{}, ScannerURL: server.URL + "/scan", ScannerToken: token, Logger: slog.Default()}
	if err := w.run(ctx, &job); !errors.Is(err, errScannerBusy) {
		t.Fatal("429 not reported as back-pressure", err)
	}
	if err := jobs.Release(ctx, job, 0); err != nil {
		t.Fatal(err)
	}
	if released, err := jobs.Get(ctx, job.ID); err != nil || released.Status != "queued" || released.Attempts != 0 {
		t.Fatal("busy scanner spent an attempt", released.Status, released.Attempts, err)
	}
	if err := jobs.Release(ctx, job, 0); !errors.Is(err, assessments.ErrLease) {
		t.Fatal("stale lease released twice", err)
	}
	job, err = jobs.Claim(ctx)
	if err != nil || job.Attempts != 1 {
		t.Fatal("requeued job not claimable", job.Attempts, err)
	}
	status = http.StatusRequestEntityTooLarge
	if err := w.run(ctx, &job); !errors.Is(err, errScannerRejected) {
		t.Fatal("413 not reported as a size rejection", err)
	}
	oversize := w
	oversize.Source = oversizeSource{}
	if err := oversize.run(ctx, &job); !errors.Is(err, connections.ErrTooLarge) {
		t.Fatal("oversize archive not classified", err)
	}
}
