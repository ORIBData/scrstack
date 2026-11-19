package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/mailer"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type recordingMail struct {
	mu   sync.Mutex
	sent []mailer.Message
	fail bool
}

func (r *recordingMail) Send(_ context.Context, m mailer.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return io.ErrUnexpectedEOF
	}
	r.sent = append(r.sent, m)
	return nil
}

func TestPostgresEmailSubscriptionsDeliverFailureEvents(t *testing.T) {
	databaseURL := os.Getenv("SCRS_TEST_DATABASE_URL")
	redisURL := os.Getenv("SCRS_TEST_REDIS_URL")
	if databaseURL == "" || redisURL == "" {
		t.Skip("requires disposable PostgreSQL and Redis")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	store, err := connections.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := strings.Repeat("a", 40)
	if _, err := store.SyncBootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	events, err := notify.Open(ctx, databaseURL, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	handler := HandlerWithSecurity(nil, store, Security{Store: store, Notify: events, Redis: rdb})
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, BasePath+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+admin)
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
	const body = `{"name":"oncall","url":"mailto:oncall@example.com,sec@example.com","events":["assessment.failed","qa.failed","ping"]}`

	// Email is off until SMTP is configured.
	must(call("POST", "/webhooks", body), 400)
	events.MailEnabled = true
	// Only the summary profile, no headers in the url, and valid addresses.
	must(call("POST", "/webhooks", strings.Replace(body, `]}`, `],"profile":"full"}`, 1)), 400)
	must(call("POST", "/webhooks", strings.Replace(body, "example.com,", "example.com?subject=x,", 1)), 400)
	must(call("POST", "/webhooks", strings.Replace(body, "oncall@", "not-an-address", 1)), 400)
	w := must(call("POST", "/webhooks", body), 201)
	var created struct {
		Subscription notify.Subscription `json:"subscription"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	assessment := map[string]any{"assessment": map[string]any{"id": uuid.NewString(), "status": "failed", "repository": "org/api", "ref": "main", "error": "scanner unavailable"}, "links": map[string]string{"self": "https://scrs.example/scrs/v1/assessments/x"}}
	qa := map[string]any{"qa_run": map[string]any{"id": uuid.NewString(), "kind": "functional", "status": "failed", "asset_id": uuid.NewString(), "error": "karate exited 1"}, "links": map[string]string{}}
	if err := events.EmitNow(ctx, "assessment.failed", assessment); err != nil {
		t.Fatal(err)
	}
	if err := events.EmitNow(ctx, "qa.failed", qa); err != nil {
		t.Fatal(err)
	}
	if _, err := events.Ping(ctx, created.Subscription.ID); err != nil {
		t.Fatal(err)
	}

	sender := &recordingMail{}
	d := &notify.Dispatcher{Store: events, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Mail: sender}
	if err := d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 3 {
		t.Fatalf("expected 3 emails, got %d", len(sender.sent))
	}
	var subjects []string
	for _, m := range sender.sent {
		subjects = append(subjects, m.Subject)
		if len(m.To) != 2 || m.To[0] != "oncall@example.com" {
			t.Fatal("recipients wrong", m.To)
		}
	}
	all := strings.Join(subjects, "|")
	if !strings.Contains(all, "[SCRS] Assessment failed: org/api@main") || !strings.Contains(all, "[SCRS] QA run failed: functional") {
		t.Fatal("subjects wrong", subjects)
	}
	for _, m := range sender.sent {
		if strings.Contains(m.Subject, "Assessment") && !strings.Contains(m.Text, "scanner unavailable") {
			t.Fatal("assessment error missing from body", m.Text)
		}
	}

	// A provider outage retries and then dead-letters; the stored reason never
	// carries the SMTP error.
	sender.fail = true
	if err := events.EmitNow(ctx, "qa.failed", qa); err != nil {
		t.Fatal(err)
	}
	if err := d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err := pool.QueryRow(ctx, "SELECT status,last_error FROM "+schema+".webhook_deliveries WHERE status<>'delivered'").Scan(&status, &lastError); err != nil || status != "pending" || lastError != "email delivery failed" {
		t.Fatal("failed email not retried", err, status, lastError)
	}

	// With SMTP unset, a stored email subscription fails with a clear reason.
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".webhook_deliveries SET next_attempt_at=now() WHERE status='pending'"); err != nil {
		t.Fatal(err)
	}
	if err := (&notify.Dispatcher{Store: events, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT last_error FROM "+schema+".webhook_deliveries WHERE status='pending'").Scan(&lastError); err != nil || lastError != "email is not configured" {
		t.Fatal("unconfigured email not reported", err, lastError)
	}
}
