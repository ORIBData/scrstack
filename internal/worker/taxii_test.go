package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/ORIBData/scrstack/internal/taxii"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeTAXII serves one collection in two pages, then nothing new, or fails.
type fakeTAXII struct {
	mu      sync.Mutex
	failing bool
	queries []string
}

func stixObject(n int, patternType, pattern string) string {
	body, _ := json.Marshal(pattern)
	return fmt.Sprintf(`{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-%012d","modified":"2026-11-01T00:00:00Z","pattern":%s,"pattern_type":%q}`, n, body, patternType)
}

func (f *fakeTAXII) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-API-Key") != "vendor-key" {
		w.WriteHeader(401)
		return
	}
	if f.failing {
		w.WriteHeader(503)
		return
	}
	f.queries = append(f.queries, r.URL.RawQuery)
	q := r.URL.Query()
	switch {
	case q.Get("added_after") == "2026-11-14T11:00:00Z":
		fmt.Fprint(w, `{"more":false}`)
	case q.Get("next") == "":
		w.Header().Set("X-TAXII-Date-Added-Last", "2026-11-14T10:00:00Z")
		fmt.Fprintf(w, `{"more":true,"next":"p2","objects":[%s,%s,%s]}`, stixObject(1, "stix", `[domain-name:value = 'c2.example']`), stixObject(2, "yara", `rule Vendor_Loader { condition: true }`), stixObject(3, "yara", `rule Broken { BROKEN }`))
	default:
		w.Header().Set("X-TAXII-Date-Added-Last", "2026-11-14T11:00:00Z")
		fmt.Fprintf(w, `{"more":false,"objects":[%s]}`, stixObject(4, "stix", `[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']`))
	}
}

func TestPostgresWorkerPollsTAXII(t *testing.T) {
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
	providers, err := connections.Open(ctx, db, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	jobs, err := assessments.Open(ctx, db, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()

	fake := &fakeTAXII{}
	server := httptest.NewTLSServer(fake)
	defer server.Close()
	feed := assessments.TAXIIFeed{APIRoot: server.URL + "/taxii2/vendor/", Collection: "iocs", AuthType: "api_key", AuthHeader: "X-API-Key", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), IntervalMinutes: 60, PageSize: 2, ValidDays: 30}
	plain, _ := json.Marshal(taxii.Secret{APIKey: "vendor-key"})
	source, _, err := jobs.CreateTAXIISource(ctx, assessments.IndicatorSource{Name: "vendor_feed", Mode: "hunt", Severity: "high", Enabled: true}, feed, uuid.Nil, func(id uuid.UUID) ([]byte, error) {
		return providers.Seal(plain, assessments.TAXIIAAD(id))
	})
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := pool.QueryRow(ctx, `SELECT credential FROM `+schema+`.taxii_feeds WHERE source_id=$1`, source.ID).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("vendor-key")) {
		t.Fatal("credential stored in clear", err)
	}

	compile := func(_ context.Context, rules string) error {
		if strings.Contains(rules, "BROKEN") {
			return &intelligence.RuleError{Diagnostics: []intelligence.Diagnostic{{Level: "error", Message: "syntax error", Line: 1}}}
		}
		return nil
	}
	w := Worker{Store: jobs, Connections: providers, Logger: slog.Default(), TAXIIPrivateHosts: map[string]bool{"127.0.0.1": true}, ValidateRules: compile}

	// First poll: two pages, each merged; the cursor ends at the last page.
	if polled, err := w.PollTAXIIOnce(ctx); err != nil || !polled {
		t.Fatal("feed not polled", polled, err)
	}
	state, err := jobs.TAXIIFeedFor(ctx, source.ID)
	if err != nil || state.Cursor != "2026-11-14T11:00:00Z" || state.Failures != 0 || state.LastError != "" || state.ObjectsPolled != 4 || state.LastSuccessAt == nil || time.Until(state.NextPollAt) < 59*time.Minute {
		t.Fatalf("poll state %+v %v", state, err)
	}
	queries := func() []string {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return append([]string{}, fake.queries...)
	}
	if q := queries(); len(q) != 2 || strings.Contains(q[0], "added_after") || !strings.Contains(q[1], "next=p2") {
		t.Fatal("paging", q)
	}
	got, err := jobs.IndicatorSourceByID(ctx, source.ID)
	if err != nil || got.IndicatorCount != 2 || got.YaraRulesetID == nil || got.Version != "taxii:2026-11-14T11:00:00Z" {
		t.Fatalf("imported source %+v %v", got, err)
	}
	rules, err := jobs.RuleSet(ctx, *got.YaraRulesetID)
	if err != nil || !strings.Contains(rules.Rules, "Vendor_Loader") || strings.Contains(rules.Rules, "BROKEN") || rules.Mode != "hunt" {
		t.Fatal("feed YARA patterns", rules.Rules, err)
	}
	// Nothing else is due; leased or scheduled feeds are not claimed.
	if polled, err := w.PollTAXIIOnce(ctx); err != nil || polled {
		t.Fatal("a scheduled feed was polled early", polled, err)
	}

	// Second poll resumes from the cursor and keeps earlier indicators.
	if err := jobs.PollTAXIINow(ctx, source.ID); err != nil {
		t.Fatal(err)
	}
	if polled, err := w.PollTAXIIOnce(ctx); err != nil || !polled {
		t.Fatal(polled, err)
	}
	if q := queries(); !strings.Contains(q[2], "added_after=2026-11-14T11%3A00%3A00Z") {
		t.Fatal("cursor not used", q)
	}
	if got, _ = jobs.IndicatorSourceByID(ctx, source.ID); got.IndicatorCount != 2 {
		t.Fatal("an empty page removed indicators", got.IndicatorCount)
	}

	// Failures back off and are recorded; the cursor is kept.
	fake.mu.Lock()
	fake.failing = true
	fake.mu.Unlock()
	for attempt := 1; attempt <= 2; attempt++ {
		if err := jobs.PollTAXIINow(ctx, source.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := w.PollTAXIIOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	state, _ = jobs.TAXIIFeedFor(ctx, source.ID)
	if state.Failures != 2 || !strings.Contains(state.LastError, "HTTP 503") || state.Cursor != "2026-11-14T11:00:00Z" || time.Until(state.NextPollAt) < 119*time.Minute {
		t.Fatalf("failure state %+v", state)
	}
	// Disabled sources are not polled.
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.indicator_sources SET enabled=false WHERE id=$1`, source.ID); err != nil {
		t.Fatal(err)
	}
	if err := jobs.PollTAXIINow(ctx, source.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.ClaimTAXII(ctx); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("disabled source claimed", err)
	}
}
