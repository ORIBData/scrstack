package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The platform status is recorded once and announced once, even when several
// API instances observe the same change at the same moment.
func TestPostgresPlatformTransition(t *testing.T) {
	databaseURL := os.Getenv("SCRS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	for range 2 { // migrations rerun on every start
		if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
			t.Fatal(err)
		}
	}
	pool, _ := pgxpool.New(ctx, databaseURL)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	events, err := notify.Open(ctx, databaseURL, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	step := func(status string, want bool) {
		t.Helper()
		got, err := events.PlatformTransition(ctx, status, []map[string]any{{"name": "redis", "status": "down", "detail": "unavailable"}})
		if err != nil || got != want {
			t.Fatalf("%s: emitted %v err %v, want %v", status, got, err, want)
		}
	}
	step("ok", false)      // the initial state is ok
	step("down", true)     // ok to down announces
	step("down", false)    // repeats stay quiet
	step("degraded", true) // a change of severity announces
	step("ok", true)       // recovery announces
	if _, err := events.PlatformTransition(ctx, "bogus", nil); err == nil {
		t.Fatal("unknown status accepted")
	}
	// Eight instances see the same change together: exactly one announces.
	var wg sync.WaitGroup
	var mu sync.Mutex
	emitted := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := events.PlatformTransition(ctx, "down", nil); err == nil && got {
				mu.Lock()
				emitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if emitted != 1 {
		t.Fatal("announced", emitted, "times")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.platform_state`).Scan(&count); err != nil || count != 1 {
		t.Fatal("state rows", count, err)
	}
}
