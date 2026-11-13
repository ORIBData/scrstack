package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SchedulerActor owns scheduled work in audit records and idempotency keys.
var SchedulerActor = uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:scheduler"))

// MaintenanceReport counts what one maintenance pass removed or queued.
type MaintenanceReport struct {
	InboundEvents     int64 `json:"inbound_events_purged"`
	WebhookDeliveries int64 `json:"webhook_deliveries_purged"`
	IdempotencyKeys   int64 `json:"idempotency_keys_expired"`
	Rescans           int   `json:"rescans_queued"`
	Skipped           bool  `json:"skipped_concurrent_run"`
}

// Maintain applies the retention policy and expires idempotency keys (M13,
// M14). Assessments, findings, audit history and object storage are never
// deleted. A transaction advisory lock lets one replica run at a time.
func (s *Store) Maintain(ctx context.Context, actor uuid.UUID, trigger string) (MaintenanceReport, error) {
	var report MaintenanceReport
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return report, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, s.schema+".maintenance").Scan(&locked); err != nil {
		return report, err
	}
	if !locked {
		report.Skipped = true
		return report, nil
	}
	var p struct{ events, deliveries int }
	if err := tx.QueryRow(ctx, `SELECT inbound_event_days,webhook_delivery_days FROM `+s.schema+`.retention_policy WHERE singleton`).Scan(&p.events, &p.deliveries); err != nil {
		return report, err
	}
	if p.events > 0 {
		// Bounded batches keep each statement short; queued and running jobs keep their events.
		for {
			tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.inbound_events WHERE id IN (SELECT e.id FROM `+s.schema+`.inbound_events e WHERE e.created_at<clock_timestamp()-($1*interval '1 day') AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments a WHERE a.id=e.assessment_id AND a.status IN ('queued','running')) ORDER BY e.created_at LIMIT 1000 FOR UPDATE OF e SKIP LOCKED)`, p.events)
			if err != nil {
				return report, err
			}
			report.InboundEvents += tag.RowsAffected()
			if tag.RowsAffected() < 1000 || report.InboundEvents >= 100000 {
				break
			}
		}
	}
	if p.deliveries > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.webhook_deliveries WHERE id IN (SELECT id FROM `+s.schema+`.webhook_deliveries WHERE status IN ('delivered','dead') AND created_at<clock_timestamp()-($1*interval '1 day') LIMIT 50000)`, p.deliveries)
		if err != nil {
			return report, err
		}
		report.WebhookDeliveries = tag.RowsAffected()
	}
	tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.assessment_idempotency WHERE expires_at<clock_timestamp()`)
	if err != nil {
		return report, err
	}
	report.IdempotencyKeys = tag.RowsAffected()
	if report.InboundEvents+report.WebhookDeliveries > 0 || trigger == "manual" {
		details, _ := json.Marshal(map[string]any{"actor_id": actor, "trigger": trigger, "report": report})
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('maintenance.completed',$1)`, details); err != nil {
			return report, err
		}
		if _, err := notify.Emit(ctx, tx, s.schema, "maintenance.completed", map[string]any{"trigger": trigger, "report": report}, nil); err != nil {
			return report, err
		}
	}
	return report, tx.Commit(ctx)
}

// EnqueueRescans queues the default branch of in-scope repositories whose
// newest scan of that branch is older than interval (ING-007). A zero
// interval rescans everything (manual maintenance). Idempotency keys per
// interval window make concurrent or repeated runs harmless.
func (s *Store) EnqueueRescans(ctx context.Context, interval time.Duration, limit int) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.locator,c.id::text,COALESCE(NULLIF(a.metadata->>'default_branch',''),'HEAD') FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.type IN ('github_repo','gitlab_repo') AND c.enabled AND a.flags->>'in_scope'='true' AND a.flags->>'accessible'='true' AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments x WHERE x.asset_id=a.id AND x.request->'target'->>'ref'=COALESCE(NULLIF(a.metadata->>'default_branch',''),'HEAD') AND x.request->'remediation' IS NULL AND x.request->'import' IS NULL AND (x.status IN ('queued','running') OR x.created_at>clock_timestamp()-($1*interval '1 second'))) ORDER BY a.locator LIMIT $2`, int64(interval.Seconds()), limit)
	if err != nil {
		return 0, err
	}
	type target struct{ repository, connection, ref string }
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.repository, &t.connection, &t.ref); err != nil {
			rows.Close()
			return 0, err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	window := "manual-" + strconv.FormatInt(time.Now().Unix(), 10)
	if interval > 0 {
		window = strconv.FormatInt(time.Now().Unix()/int64(interval.Seconds()), 10)
	}
	queued := 0
	for _, t := range targets {
		request := Request{Target: Target{Type: "git", Repository: t.repository, Ref: t.ref}, Connection: t.connection}
		request.Trigger.Origin = "scheduler"
		_, replayed, err := s.Enqueue(ctx, request, SchedulerActor, "scheduler", "rescan-"+window+"-"+Hash([]byte(t.connection + t.repository))[:16])
		if errors.Is(err, ErrCapacity) {
			break
		}
		if err != nil {
			continue // asset changed since selection; next run retries
		}
		if !replayed {
			queued++
		}
	}
	return queued, nil
}

// InboundEvent is a stored raw delivery (ING-008). Provider headers are not stored.
type InboundEvent struct {
	ID           uuid.UUID       `json:"id"`
	AssessmentID *uuid.UUID      `json:"assessment_id"`
	Mode         string          `json:"mode"`
	EventType    string          `json:"event_type"`
	CreatedAt    time.Time       `json:"created_at"`
	Body         json.RawMessage `json:"body,omitempty"`
}

// InboundEvents lists stored deliveries, optionally by claimed actor (INT-016).
func (s *Store) InboundEvents(ctx context.Context, after uuid.UUID, actor, eventType string) ([]InboundEvent, error) {
	if len(actor) > 100 || len(eventType) > 64 {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT id,assessment_id,mode,event_type,created_at FROM `+s.schema+`.inbound_events WHERE id>$1 AND ($2='' OR body->'sender'->>'login'=$2 OR body->'pusher'->>'name'=$2 OR body->'trigger'->>'actor'=$2) AND ($3='' OR event_type=$3) ORDER BY id LIMIT 101`, after, actor, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InboundEvent{}
	for rows.Next() {
		var e InboundEvent
		if err := rows.Scan(&e.ID, &e.AssessmentID, &e.Mode, &e.EventType, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) InboundEvent(ctx context.Context, id uuid.UUID) (InboundEvent, error) {
	var e InboundEvent
	err := s.pool.QueryRow(ctx, `SELECT id,assessment_id,mode,event_type,created_at,body FROM `+s.schema+`.inbound_events WHERE id=$1`, id).Scan(&e.ID, &e.AssessmentID, &e.Mode, &e.EventType, &e.CreatedAt, &e.Body)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// Replay re-assesses the revision an inbound event produced, as a new
// assessment owned by the replaying admin. The original stays unchanged.
func (s *Store) Replay(ctx context.Context, id, actor uuid.UUID, actorName string) (Assessment, error) {
	e, err := s.InboundEvent(ctx, id)
	if err != nil {
		return Assessment{}, err
	}
	if e.AssessmentID == nil {
		return Assessment{}, ErrConflict
	}
	original, err := s.Get(ctx, *e.AssessmentID)
	if err != nil {
		return Assessment{}, err
	}
	request := original.Request
	request.Connection = original.ConnectionID.String()
	request.Trigger.Origin = "replay"
	request.Trigger.DeliveryID = ""
	if request.Target.Commit == "" && original.Commit != "" {
		request.Target.Commit = original.Commit
	}
	a, _, err := s.Enqueue(ctx, request, actor, actorName, "replay-"+id.String()+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	return a, err
}
