package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Maintenance actions (MNT-001 to MNT-003, MNT-006): scoped resets, a
// rebuild of derived results and a sensor update. Each is audited with the
// actor, parameters and counts.

// ResetScopes are the resets MNT-001 allows.
var ResetScopes = map[string]string{
	"feed_state":     "clear TAXII cursors and advisory-source sync state so the next runs resync from scratch",
	"indicators":     "delete every indicator of one indicator source (source_id)",
	"asset_findings": "delete one asset's register entries and their history (asset_id); not for assets on legal hold",
}

// ErrLegalHold means the asset is on legal hold.
var ErrLegalHold = errors.New("the asset is on legal hold")

// Reset performs one scoped reset and returns what it removed.
func (s *Store) Reset(ctx context.Context, scope string, target uuid.UUID, actor uuid.UUID) (map[string]int64, error) {
	if _, ok := ResetScopes[scope]; !ok {
		return nil, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	out := map[string]int64{}
	count := func(name, sql string, args ...any) error {
		tag, err := tx.Exec(ctx, sql, args...)
		out[name] = tag.RowsAffected()
		return err
	}
	switch scope {
	case "feed_state":
		if err := count("taxii_feeds", `UPDATE `+s.schema+`.taxii_feeds SET cursor='',next_poll_at=clock_timestamp(),failures=0,last_error=''`); err != nil {
			return nil, err
		}
		if err := count("vulnerability_sources", `UPDATE `+s.schema+`.vulnerability_sources SET state='{}',next_sync_at=clock_timestamp(),failures=0,last_error='' WHERE managed_by='worker'`); err != nil {
			return nil, err
		}
	case "indicators":
		if target == uuid.Nil {
			return nil, ErrInput
		}
		if err := count("indicators", `DELETE FROM `+s.schema+`.indicators WHERE source_id=$1`, target); err != nil {
			return nil, err
		}
		tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.indicator_sources SET indicator_count=0,version='',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1`, target)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, ErrNotFound
		}
	case "asset_findings":
		var hold bool
		if err := tx.QueryRow(ctx, `SELECT legal_hold FROM `+s.schema+`.assets WHERE id=$1 FOR UPDATE`, target).Scan(&hold); err != nil {
			return nil, ErrNotFound
		}
		if hold {
			return nil, ErrLegalHold
		}
		if err := count("findings", `WITH doomed AS (SELECT id FROM `+s.schema+`.findings WHERE asset_id=$1), i AS (UPDATE `+s.schema+`.integrity_events SET finding_id=NULL WHERE finding_id IN (SELECT id FROM doomed) RETURNING 1), e AS (DELETE FROM `+s.schema+`.finding_events WHERE finding_id IN (SELECT id FROM doomed) RETURNING 1), af AS (DELETE FROM `+s.schema+`.assessment_findings WHERE finding_id IN (SELECT id FROM doomed) RETURNING 1) DELETE FROM `+s.schema+`.findings WHERE id IN (SELECT id FROM doomed)`, target); err != nil {
			return nil, err
		}
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "scope": scope, "target_id": target, "removed": out})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('maintenance.reset',$1,$2)`, target, details); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// Rebuild re-assesses the current revision of every tracked ref (MNT-002):
// the newest successful repository or image assessment of each asset and
// ref in the last 180 days is queued again, so findings, scores, KEV/EPSS,
// indicator and rule matches are recomputed against current feeds.
func (s *Store) Rebuild(ctx context.Context, actor uuid.UUID, limit int) (int, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (x.asset_id,x.request->'target'->>'ref') x.request,c.name FROM `+s.schema+`.assessments x JOIN `+s.schema+`.assets a ON a.id=x.asset_id JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE x.status='succeeded' AND x.request->'remediation' IS NULL AND x.request->'import' IS NULL AND x.created_at>clock_timestamp()-interval '180 days' AND c.enabled AND a.flags->>'in_scope'='true' AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments q WHERE q.asset_id=x.asset_id AND q.status IN ('queued','running')) ORDER BY x.asset_id,x.request->'target'->>'ref',x.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	type item struct {
		request    Request
		connection string
	}
	var items []item
	for rows.Next() {
		var raw []byte
		var it item
		if err := rows.Scan(&raw, &it.connection); err != nil {
			rows.Close()
			return 0, err
		}
		if json.Unmarshal(raw, &it.request) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	window := strconv.FormatInt(time.Now().Unix(), 10)
	queued := 0
	for _, it := range items {
		// The ref is re-resolved: a rebuild assesses its current head.
		t := it.request.Target
		request := Request{Target: Target{Type: t.Type, Repository: t.Repository, Ref: t.Ref, Platform: t.Platform, Provider: t.Provider}, Connection: it.connection}
		if t.PullRequest != nil {
			continue // a pull request's head is assessed by its own events
		}
		request.Trigger.Origin = "rebuild"
		_, replayed, err := s.Enqueue(ctx, request, SchedulerActor, "rebuild", "rebuild-"+window+"-"+Hash([]byte(it.connection + t.Repository + t.Ref))[:16])
		if errors.Is(err, ErrCapacity) {
			break
		}
		if err == nil && !replayed {
			queued++
		}
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "queued": queued, "candidates": len(items)})
	if _, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('maintenance.rebuild',$1)`, details); err != nil {
		return queued, err
	}
	return queued, nil
}

// UpdateSensors makes every TAXII feed and worker-synced advisory source due
// now (MNT-003). OSV, KEV, EPSS and ClamAV signatures refresh on their own
// schedules in scrs-feed-sync and scrs-clamav; their freshness is reported
// in the vulnerability-source registry.
func (s *Store) UpdateSensors(ctx context.Context, actor uuid.UUID) (map[string]int64, error) {
	out := map[string]int64{}
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.taxii_feeds f SET next_poll_at=clock_timestamp() FROM `+s.schema+`.indicator_sources src WHERE src.id=f.source_id AND src.enabled`)
	if err != nil {
		return nil, err
	}
	out["taxii_feeds"] = tag.RowsAffected()
	if tag, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET next_sync_at=clock_timestamp() WHERE managed_by='worker' AND enabled`); err != nil {
		return nil, err
	}
	out["advisory_sources"] = tag.RowsAffected()
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "due_now": out})
	_, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('maintenance.update_sensors',$1)`, details)
	return out, err
}
