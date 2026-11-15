package assessments_test

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type listedObjects struct {
	keys    map[string][]string
	deleted []string
}

func (l *listedObjects) ListObjects(_ context.Context, prefix string, _ time.Time, _ int) ([]string, error) {
	return l.keys[prefix], nil
}
func (l *listedObjects) DeleteObject(_ context.Context, key string) error {
	l.deleted = append(l.deleted, key)
	return nil
}

// D7: an artifact uploaded before a completion that never committed is
// unreferenced; the sweep deletes it and keeps referenced ones, at most
// once a day unless forced.
func TestPostgresOrphanSweep(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: url, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, url)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	store, err := assessments.Open(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	referenced := "reports/" + strings.Repeat("a", 64) + ".json"
	orphan := "reports/" + strings.Repeat("b", 64) + ".json"
	sbomOrphan := "sbom/" + strings.Repeat("c", 64) + ".cdx.json"
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.reports(id,framework,scope,format,status,s3_key) VALUES($1,'owasp-top10-2025','{"kind":"portfolio"}','json','succeeded',$2)`, uuid.New(), referenced); err != nil {
		t.Fatal(err)
	}
	objects := &listedObjects{keys: map[string][]string{"reports/": {referenced, orphan}, "sbom/": {sbomOrphan}}}
	store.UseObjects(objects)
	n, err := store.SweepOrphans(ctx, false)
	sort.Strings(objects.deleted)
	if err != nil || n != 2 || len(objects.deleted) != 2 || objects.deleted[0] != orphan || objects.deleted[1] != sbomOrphan {
		t.Fatalf("sweep %d %v %v", n, objects.deleted, err)
	}
	// Not due again for a day.
	if n, err := store.SweepOrphans(ctx, false); err != nil || n != 0 {
		t.Fatalf("second sweep ran: %d %v", n, err)
	}
	var audits int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.audit_log WHERE action='retention.orphans_deleted'`).Scan(&audits)
	if audits != 1 {
		t.Fatalf("audit %d", audits)
	}
}
