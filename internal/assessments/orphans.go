package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Orphan objects (D7 of the design): artifacts are uploaded before the
// database records them, so a crash or a refused completion (a lost lease)
// leaves an object nothing references. The sweep deletes such objects once
// they are older than any job could still be (a day), at most once a day.

// ObjectLister lists stored objects; the S3 artifact store implements it.
type ObjectLister interface {
	ListObjects(ctx context.Context, prefix string, before time.Time, limit int) ([]string, error)
}

// orphanPrefixes maps each content-addressed prefix to the query that finds
// a reference to a key. Mirrors are managed by their own retention.
var orphanPrefixes = map[string]string{
	"sbom/":        `SELECT 1 FROM %s.assessments WHERE sbom_key=$1`,
	"snapshots/":   `SELECT 1 FROM %s.assessments WHERE snapshot_key=$1`,
	"remediation/": `SELECT 1 FROM %s.remediation_results WHERE artifact_key=$1`,
	"qa/":          `SELECT 1 FROM %s.qa_runs WHERE report_key=$1`,
	"reports/":     `SELECT 1 FROM %s.reports WHERE s3_key=$1`,
}

// OrphanGrace is how old an unreferenced object must be before deletion.
const OrphanGrace = 24 * time.Hour

const orphanBatch = 1000

// SweepOrphans deletes unreferenced artifacts older than OrphanGrace when
// the last sweep is a day old (or force). It returns the deleted count.
func (s *Store) SweepOrphans(ctx context.Context, force bool) (int, error) {
	lister, ok := s.objects.(ObjectLister)
	if !ok || s.objects == nil {
		return 0, nil
	}
	if !force {
		var due bool
		if err := s.pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM `+s.schema+`.scheduler_runs WHERE job='orphan_sweep' AND last_status='ok' AND last_finished_at>clock_timestamp()-interval '23 hours')`).Scan(&due); err != nil || !due {
			return 0, err
		}
	}
	started := time.Now()
	deleted, failed := 0, 0
	var sweepErr error
	for prefix, query := range orphanPrefixes {
		keys, err := lister.ListObjects(ctx, prefix, time.Now().Add(-OrphanGrace), orphanBatch)
		if err != nil {
			sweepErr = errors.Join(sweepErr, err)
			continue
		}
		for _, key := range keys {
			var used bool
			if err := s.pool.QueryRow(ctx, `SELECT EXISTS(`+sprintfSchema(query, s.schema)+`)`, key).Scan(&used); err != nil {
				sweepErr = errors.Join(sweepErr, err)
				break
			}
			if used {
				continue
			}
			if err := s.objects.DeleteObject(ctx, key); err != nil {
				failed++
				continue
			}
			deleted++
		}
	}
	if deleted > 0 {
		details, _ := json.Marshal(map[string]any{"deleted": deleted, "failed": failed, "grace_hours": int(OrphanGrace.Hours())})
		if _, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('retention.orphans_deleted',$1)`, details); err != nil {
			sweepErr = errors.Join(sweepErr, err)
		}
	}
	_ = s.RecordJob(context.WithoutCancel(ctx), "orphan_sweep", 24*time.Hour, started, sweepErr, map[string]int{"deleted": deleted, "failed": failed})
	return deleted, sweepErr
}

func sprintfSchema(query, schema string) string { return strings.ReplaceAll(query, "%s", schema) }
