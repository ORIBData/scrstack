package assessments_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fleet struct{ n int }

func (f fleet) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	out := make([]connections.Resource, f.n)
	for i := range out {
		out[i] = connections.Resource{Type: "github_repo", Locator: fmt.Sprintf("org/repo-%02d", i)}
	}
	return out, nil
}

// Load and resilience (M7): concurrent admission with duplicate keys,
// competing workers and simulated crashes recovered through lease expiry.
// Every admitted assessment must complete exactly once, with one outbox
// event each and no duplicated findings.
func TestPostgresLoadAndResilience(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: url, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	providers, err := connections.Open(ctx, url, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
		t.Fatal(err)
	}
	const assets, clients, perClient = 20, 16, 15
	if _, err := providers.Discover(ctx, "gh", fleet{assets}); err != nil {
		t.Fatal(err)
	}
	events, err := notify.Open(ctx, url, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	events.PrivateHosts = map[string]bool{"collector.internal": true}
	if _, _, err := events.Create(ctx, notify.Subscription{Name: "load", URL: "http://collector.internal/hook", Events: []string{"assessment.completed"}}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	s, err := assessments.Open(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Admission: each client submits its jobs twice under the same keys.
	var latencies []time.Duration
	var mu sync.Mutex
	admitted := map[uuid.UUID]bool{}
	var wg sync.WaitGroup
	errs := make(chan error, clients*perClient*2)
	start := time.Now()
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			actor := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprint("client", c)))
			for round := 0; round < 2; round++ {
				for j := 0; j < perClient; j++ {
					req := assessments.Request{Target: assessments.Target{Type: "git", Repository: fmt.Sprintf("org/repo-%02d", (c*perClient+j)%assets), Ref: "main"}}
					t0 := time.Now()
					a, _, err := s.Enqueue(ctx, req, actor, "load", fmt.Sprintf("job-%d", j))
					elapsed := time.Since(t0)
					if err != nil {
						errs <- err
						continue
					}
					mu.Lock()
					latencies = append(latencies, elapsed)
					admitted[a.ID] = true
					mu.Unlock()
				}
			}
		}(c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal("admission failed under load", err)
	}
	admission := time.Since(start)
	if len(admitted) != clients*perClient {
		t.Fatalf("idempotency under load: %d distinct jobs, want %d", len(admitted), clients*perClient)
	}

	// Workers: claim and complete concurrently; every 10th claim "crashes".
	var claims, crashes, completed atomic.Int64
	result := assessments.Result{Commit: strings.Repeat("a", 40), Complete: true, Findings: []assessments.Finding{{Type: "vulnerability", AdvisoryID: "LOAD-1", Title: "Synthetic", Severity: "medium", Score: 25, Component: assessments.Component{PURL: "pkg:npm/x@1"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)}}}
	work := time.Now()
	deadline := time.Now().Add(2 * time.Minute)
	var workers sync.WaitGroup
	for w := 0; w < 6; w++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for time.Now().Before(deadline) {
				a, err := s.Claim(ctx)
				if err != nil {
					if !errors.Is(err, assessments.ErrNotFound) {
						t.Error("claim failed", err)
						return
					}
					// Recover crashed leases quickly instead of waiting ten minutes.
					var remaining int
					_ = pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".assessments WHERE status IN ('queued','running')").Scan(&remaining)
					if remaining == 0 {
						return
					}
					_, _ = pool.Exec(ctx, "UPDATE "+schema+".assessments SET lease_until=now()-interval '1 second',run_after=now() WHERE status='running' AND error='simulated crash'")
					_, _ = pool.Exec(ctx, "UPDATE "+schema+".assessments SET run_after=now() WHERE status='queued'")
					time.Sleep(20 * time.Millisecond)
					continue
				}
				if claims.Add(1)%10 == 0 && a.Attempts == 1 {
					crashes.Add(1)
					_, _ = pool.Exec(ctx, "UPDATE "+schema+".assessments SET error='simulated crash' WHERE id=$1", a.ID)
					continue // abandon the lease like a killed worker
				}
				if err := s.Complete(ctx, a, result); err != nil {
					t.Error("completion failed", a.ID, err)
					return
				}
				completed.Add(1)
			}
		}()
	}
	workers.Wait()
	processing := time.Since(work)

	var succeeded, other, outbox, duplicateLinks int
	if err := pool.QueryRow(ctx, "SELECT count(*) FILTER (WHERE status='succeeded'),count(*) FILTER (WHERE status<>'succeeded') FROM "+schema+".assessments").Scan(&succeeded, &other); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".webhook_deliveries WHERE event_type='assessment.completed'").Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM (SELECT assessment_id FROM "+schema+".assessment_findings GROUP BY assessment_id HAVING count(*)>1) d").Scan(&duplicateLinks); err != nil {
		t.Fatal(err)
	}
	if succeeded != clients*perClient || other != 0 || int(completed.Load()) != succeeded || outbox != succeeded || duplicateLinks != 0 {
		t.Fatalf("exactly-once violated: succeeded=%d other=%d completed=%d outbox=%d duplicates=%d crashes=%d", succeeded, other, completed.Load(), outbox, duplicateLinks, crashes.Load())
	}
	slices.Sort(latencies)
	p95 := latencies[len(latencies)*95/100]
	t.Logf("admission: %d requests in %s (p95 %s); processing: %d jobs, %d crash recoveries, in %s (%.1f jobs/s)",
		len(latencies), admission.Round(time.Millisecond), p95.Round(time.Millisecond), succeeded, crashes.Load(), processing.Round(time.Millisecond), float64(succeeded)/processing.Seconds())
	if p95 > 500*time.Millisecond {
		t.Errorf("admission p95 %s exceeds the 500 ms acknowledgement budget (AT-12)", p95)
	}
}
