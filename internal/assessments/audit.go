package assessments

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuditEntry is one audit record (OBS-001).
type AuditEntry struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Action     string          `json:"action"`
	TargetID   *uuid.UUID      `json:"target_id"`
	Details    json.RawMessage `json:"details"`
}

// AuditFilter selects audit records (OBS-002). Action matches exactly, or
// as a prefix when it ends in "*" ("connection.*"). Before is the cursor:
// records with a smaller id.
type AuditFilter struct {
	Action string
	Target uuid.UUID
	Actor  uuid.UUID
	Since  *time.Time
	Until  *time.Time
	Before int64
	Limit  int
}

// Audit lists audit records newest first.
func (s *Store) Audit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if len(f.Action) > 128 {
		return nil, ErrInput
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	exact, prefix := f.Action, ""
	if p, ok := strings.CutSuffix(f.Action, "*"); ok {
		exact, prefix = "", p
	}
	actor := ""
	if f.Actor != uuid.Nil {
		actor = f.Actor.String()
	}
	rows, err := s.pool.Query(ctx, `SELECT id,occurred_at,action,target_id,details FROM `+s.schema+`.audit_log WHERE ($1='' OR action=$1) AND ($2='' OR starts_with(action,$2)) AND ($3='00000000-0000-0000-0000-000000000000'::uuid OR target_id=$3) AND ($4='' OR details->>'actor_id'=$4) AND ($5::timestamptz IS NULL OR occurred_at>=$5) AND ($6::timestamptz IS NULL OR occurred_at<$6) AND ($7=0 OR id<$7) ORDER BY id DESC LIMIT $8`, exact, prefix, f.Target, actor, f.Since, f.Until, f.Before, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Action, &e.TargetID, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
