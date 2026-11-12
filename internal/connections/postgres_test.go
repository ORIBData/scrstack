package connections

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
)

type adapterFunc func(context.Context, Connection, json.RawMessage) ([]Resource, error)

func (f adapterFunc) List(ctx context.Context, c Connection, s json.RawMessage) ([]Resource, error) {
	return f(ctx, c, s)
}

func TestPostgresReconciliationAndConcurrentRotation(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable SCRS_TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.New().String()[:8]
	cfg := storage.Config{DatabaseURL: url, DatabaseSchema: schema}
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- storage.BootstrapDatabase(ctx, cfg) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	s, err := Open(ctx, url, schema, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() { _, _ = s.pool.Exec(context.Background(), "DROP SCHEMA "+s.schema+" CASCADE") }()
	// Parallel first starts must generate exactly one initial admin secret.
	secrets := make(chan string, 4)
	bootErrors := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); secret, err := s.SyncBootstrap(ctx, ""); secrets <- secret; bootErrors <- err }()
	}
	wg.Wait()
	close(secrets)
	close(bootErrors)
	for err := range bootErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	issued := 0
	for secret := range secrets {
		if secret != "" {
			issued++
			if _, err := s.Authenticate(ctx, secret, netip.MustParseAddr("127.0.0.1")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if issued != 1 {
		t.Fatalf("generated %d bootstrap secrets, want 1", issued)
	}
	c := Connection{Name: "qa", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: Scope{Include: []string{"org/*"}}}
	secret := json.RawMessage(`{"token":"synthetic-secret"}`)
	if _, err := s.Put(ctx, c, secret, false); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err := s.pool.QueryRow(ctx, "SELECT credential_ciphertext FROM "+s.schema+".connections WHERE name='qa'").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("synthetic-secret")) {
		t.Fatal("credential stored as plaintext")
	}
	inventory := []Resource{{Type: "github_repo", Locator: "org/a"}, {Type: "github_repo", Locator: "org/b"}}
	adapter := adapterFunc(func(context.Context, Connection, json.RawMessage) ([]Resource, error) { return inventory, nil })
	if _, err := s.Discover(ctx, "qa", adapter); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE "+s.schema+`.assets SET flags=flags || '{"custom":true}' WHERE locator='org/a'`); err != nil {
		t.Fatal(err)
	}
	inventory = inventory[:1]
	if _, err := s.Discover(ctx, "qa", adapter); err != nil {
		t.Fatal(err)
	}
	var retained, withdrawn bool
	if err := s.pool.QueryRow(ctx, "SELECT (flags->>'custom')::boolean FROM "+s.schema+".assets WHERE locator='org/a'").Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, "SELECT NOT (flags->>'in_scope')::boolean FROM "+s.schema+".assets WHERE locator='org/b'").Scan(&withdrawn); err != nil {
		t.Fatal(err)
	}
	if !retained || !withdrawn {
		t.Fatal("reconciliation lost flags or retained stale eligibility")
	}
	inventory = []Resource{{Type: "invalid", Locator: "org/c"}}
	if _, err := s.Discover(ctx, "qa", adapter); err == nil {
		t.Fatal("invalid inventory accepted")
	}
	var eligible bool
	if err := s.pool.QueryRow(ctx, "SELECT (flags->>'in_scope')::boolean FROM "+s.schema+".assets WHERE locator='org/a'").Scan(&eligible); err != nil || !eligible {
		t.Fatal("failed inventory did not roll back", err)
	}
	rotating := adapterFunc(func(_ context.Context, snapshot Connection, _ json.RawMessage) ([]Resource, error) {
		if _, err := s.Put(ctx, c, json.RawMessage(`{"token":"rotated-secret"}`), true); err != nil {
			return nil, err
		}
		// Simulate equal timestamps: correctness must rely on monotonic revisions.
		_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.connections SET updated_at=$1 WHERE name=$2`, snapshot.UpdatedAt, snapshot.Name)
		return nil, err
	})
	if _, err := s.Test(ctx, "qa", rotating); err == nil {
		t.Fatal("stale status write accepted after rotation")
	}
	if _, err := s.Discover(ctx, "qa", rotating); err == nil {
		t.Fatal("stale discovery accepted after rotation")
	}
}
