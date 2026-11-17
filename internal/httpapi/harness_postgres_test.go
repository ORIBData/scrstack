package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
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

// harness is a router over a disposable schema, with the bootstrap admin
// token and helpers for requests and for creating assets and findings.
type harness struct {
	t         *testing.T
	ctx       context.Context
	pool      *pgxpool.Pool
	schema    string
	store     *connections.Store
	jobs      *assessments.Store
	artifacts memoryArtifacts
	handler   http.Handler
	admin     string
	// webhookSecret signs the GitHub webhooks the router accepts directly.
	webhookSecret string
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

// newHarnessWith builds the harness after letting the test adjust the
// router's security settings.
func newHarnessWith(t *testing.T, adjust func(*Security)) *harness {
	t.Helper()
	databaseURL, redisURL := os.Getenv("SCRS_TEST_DATABASE_URL"), os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		pool.Close()
	})
	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	h := &harness{t: t, ctx: ctx, pool: pool, schema: schema, store: store, artifacts: memoryArtifacts{}, admin: strings.Repeat("a", 40), webhookSecret: strings.Repeat("h", 40)}
	if _, err := store.SyncBootstrap(ctx, h.admin); err != nil {
		t.Fatal(err)
	}
	if h.jobs, err = assessments.Open(ctx, databaseURL, schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.jobs.Close)
	h.jobs.UseObjects(h.artifacts)
	events, err := notify.Open(ctx, databaseURL, schema, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(events.Close)
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	security := Security{Store: store, Redis: rdb, Assessments: h.jobs, Artifacts: h.artifacts, Notify: events, GitHubWebhookSecret: h.webhookSecret, Live: &notify.Hub{MaxStreams: 10, PerToken: 2}}
	if adjust != nil {
		adjust(&security)
	}
	h.handler = HandlerWithSecurity(nil, store, security)
	return h
}

// issue creates a token with one scope and returns its secret.
func (h *harness) issue(name, scope string) string {
	h.t.Helper()
	_, secret, err := h.store.CreateToken(h.ctx, connections.Token{Name: name, Scopes: []string{scope}}, uuid.Nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return secret
}

func (h *harness) call(method, path, token string, body []byte, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, BasePath+path, bytes.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

func (h *harness) expect(w *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
	h.t.Helper()
	if w.Code != status {
		h.t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
	}
	return w
}

// upload creates an uploaded asset with one assessment and returns both ids.
func (h *harness) upload(name, content string) (asset, assessment uuid.UUID) {
	h.t.Helper()
	var buf bytes.Buffer
	m := multipart.NewWriter(&buf)
	_ = m.WriteField("name", name)
	part, _ := m.CreateFormFile("file", "src.tar.gz")
	_, _ = part.Write(sourceArchive(h.t, map[string]string{"f": content}))
	_ = m.Close()
	var out struct {
		Asset      connections.Asset `json:"asset"`
		Assessment struct {
			ID uuid.UUID `json:"id"`
		} `json:"assessment"`
	}
	if err := json.Unmarshal(h.expect(h.call("POST", "/uploads", h.admin, buf.Bytes(), m.FormDataContentType()), 201).Body.Bytes(), &out); err != nil {
		h.t.Fatal(err)
	}
	return out.Asset.ID, out.Assessment.ID
}

// finding inserts a register entry for an asset, attached to an assessment.
func (h *harness) finding(asset, assessment uuid.UUID, advisory, severity string) uuid.UUID {
	h.t.Helper()
	id := uuid.New()
	_, err := h.pool.Exec(h.ctx, "INSERT INTO "+h.schema+".findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,'main','vulnerability',$4,$4,$5,50,'{\"name\":\"lodash\",\"version\":\"4.17.20\",\"ecosystem\":\"npm\"}','{}','{}',$6)",
		id, asset, "fp-"+id.String(), advisory, severity, assessment)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}
