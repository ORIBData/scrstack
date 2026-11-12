package assessments

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
)

// Raw ingress retention is independent of assessment, finding and audit evidence.
// Zero retains forever; no purge of assessed artifacts or risk history is exposed.
type Retention struct {
	Revision         int64 `json:"revision"`
	InboundEventDays int   `json:"inbound_event_days"`
}

func (s *Store) Retention(ctx context.Context) (Retention, error) {
	var p Retention
	err := s.pool.QueryRow(ctx, `SELECT revision,inbound_event_days FROM `+s.schema+`.retention_policy WHERE singleton`).Scan(&p.Revision, &p.InboundEventDays)
	return p, err
}
func (s *Store) SetRetention(ctx context.Context, actor uuid.UUID, expected int64, days int) (Retention, error) {
	if days < 0 || days > 36500 {
		return Retention{}, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Retention{}, err
	}
	defer tx.Rollback(ctx)
	var old int
	if err = tx.QueryRow(ctx, `SELECT inbound_event_days FROM `+s.schema+`.retention_policy WHERE singleton FOR UPDATE`).Scan(&old); err != nil {
		return Retention{}, err
	}
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.retention_policy SET inbound_event_days=$1,revision=revision+1 WHERE singleton AND revision=$2`, days, expected)
	if err != nil {
		return Retention{}, err
	}
	if tag.RowsAffected() != 1 {
		return Retention{}, ErrConflict
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "old_days": old, "new_days": days, "revision": expected + 1})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('retention.policy_changed',$1)`, details); err != nil {
		return Retention{}, err
	}
	return Retention{Revision: expected + 1, InboundEventDays: days}, tx.Commit(ctx)
}
func (s *Store) PreviewRetention(ctx context.Context, days int) (map[string]int64, error) {
	if days < 0 || days > 36500 {
		return nil, ErrInput
	}
	result := map[string]int64{"rows": 0, "bytes": 0}
	if days == 0 {
		return result, nil
	}
	var rows, size int64
	err := s.pool.QueryRow(ctx, `SELECT count(*),COALESCE(sum(pg_column_size(e.body)),0) FROM `+s.schema+`.inbound_events e WHERE e.created_at<clock_timestamp()-($1*interval '1 day') AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments a WHERE a.id=e.assessment_id AND a.status IN ('queued','running'))`, days).Scan(&rows, &size)
	result["rows"] = rows
	result["bytes"] = size
	return result, err
}
func (s *Store) PurgeEvents(ctx context.Context, actor uuid.UUID, expected int64) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var p Retention
	if err = tx.QueryRow(ctx, `SELECT revision,inbound_event_days FROM `+s.schema+`.retention_policy WHERE singleton FOR SHARE`).Scan(&p.Revision, &p.InboundEventDays); err != nil {
		return 0, err
	}
	if p.Revision != expected {
		return 0, ErrConflict
	}
	if p.InboundEventDays == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.inbound_events WHERE id IN (SELECT e.id FROM `+s.schema+`.inbound_events e WHERE e.created_at<clock_timestamp()-($1*interval '1 day') AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments a WHERE a.id=e.assessment_id AND a.status IN ('queued','running')) ORDER BY e.created_at LIMIT 1000 FOR UPDATE OF e SKIP LOCKED)`, p.InboundEventDays)
	if err != nil {
		return 0, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "rows": tag.RowsAffected(), "days": p.InboundEventDays, "revision": p.Revision})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('retention.events_purged',$1)`, details); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}
