package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Mirror is one git history bundle of a repository asset (INT-006). Bundles
// are stored in S3 and restore with `git clone <file>.bundle`.
type Mirror struct {
	ID          uuid.UUID  `json:"id"`
	AssetID     uuid.UUID  `json:"asset_id"`
	Status      string     `json:"status"`
	SHA256      string     `json:"sha256,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
	Refs        int        `json:"refs"`
	Head        string     `json:"head,omitempty"`
	Error       string     `json:"error,omitempty"`
	RequestedBy string     `json:"requested_by"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ObjectKey   string     `json:"-"`
	Lease       uuid.UUID  `json:"-"`
	// Locator and ConnectionID are set on claim for the worker.
	Locator      string    `json:"-"`
	ConnectionID uuid.UUID `json:"-"`
}

func mirrorSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.asset_mirrors(id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','pruned')),object_key text NOT NULL DEFAULT '',sha256 text NOT NULL DEFAULT '',size_bytes bigint NOT NULL DEFAULT 0,refs integer NOT NULL DEFAULT 0,head text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',requested_by text NOT NULL,lease uuid,lease_until timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS asset_mirrors_active_uq ON ` + s + `.asset_mirrors(asset_id) WHERE status IN ('queued','running')`,
		`CREATE INDEX IF NOT EXISTS asset_mirrors_asset_idx ON ` + s + `.asset_mirrors(asset_id,created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS asset_mirrors_queue_idx ON ` + s + `.asset_mirrors(created_at) WHERE status='queued'`,
	}
}

const mirrorColumns = `id,asset_id,status,sha256,size_bytes,refs,head,error,requested_by,created_at,completed_at,object_key`

func scanMirror(row pgx.Row) (Mirror, error) {
	var m Mirror
	err := row.Scan(&m.ID, &m.AssetID, &m.Status, &m.SHA256, &m.SizeBytes, &m.Refs, &m.Head, &m.Error, &m.RequestedBy, &m.CreatedAt, &m.CompletedAt, &m.ObjectKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// RequestMirror queues a mirror of an in-scope git asset. An already queued
// or running mirror is returned instead of a duplicate (created=false).
func (s *Store) RequestMirror(ctx context.Context, asset uuid.UUID, by string) (Mirror, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Mirror{}, false, err
	}
	defer tx.Rollback(ctx)
	var eligible bool
	err = tx.QueryRow(ctx, `SELECT a.type IN ('github_repo','gitlab_repo') AND a.flags->>'in_scope'='true' AND a.flags->>'accessible'='true' AND c.enabled FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.id=$1 FOR SHARE OF a`, asset).Scan(&eligible)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !eligible) {
		return Mirror{}, false, ErrScope
	}
	if err != nil {
		return Mirror{}, false, err
	}
	m, err := scanMirror(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.asset_mirrors(id,asset_id,requested_by) VALUES($1,$2,$3) ON CONFLICT (asset_id) WHERE status IN ('queued','running') DO NOTHING RETURNING `+mirrorColumns, uuid.New(), asset, by))
	if errors.Is(err, ErrNotFound) {
		m, err = scanMirror(tx.QueryRow(ctx, `SELECT `+mirrorColumns+` FROM `+s.schema+`.asset_mirrors WHERE asset_id=$1 AND status IN ('queued','running')`, asset))
		if err != nil {
			return m, false, err
		}
		return m, false, tx.Commit(ctx)
	}
	if err != nil {
		return m, false, err
	}
	details, _ := json.Marshal(map[string]any{"asset_id": asset, "requested_by": by})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('mirror.requested',$1,$2)`, m.ID, details); err != nil {
		return m, false, err
	}
	return m, true, tx.Commit(ctx)
}

// ScheduleMirrors queues assets labelled mirror=true whose newest successful
// mirror is older than the interval.
func (s *Store) ScheduleMirrors(ctx context.Context, interval time.Duration) (int, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.asset_mirrors(id,asset_id,requested_by) SELECT gen_random_uuid(),a.id,'scheduler' FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.type IN ('github_repo','gitlab_repo') AND a.labels->>'mirror'='true' AND c.enabled AND a.flags->>'in_scope'='true' AND a.flags->>'accessible'='true' AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.asset_mirrors m WHERE m.asset_id=a.id AND (m.status IN ('queued','running') OR (m.status='succeeded' AND m.created_at>clock_timestamp()-($1*interval '1 second')))) ON CONFLICT DO NOTHING`, int64(interval.Seconds()))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ClaimMirror leases the oldest queued mirror for 30 minutes. Mirrors whose
// worker vanished fail rather than retry: the next request or schedule
// starts a fresh one.
func (s *Store) ClaimMirror(ctx context.Context) (Mirror, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Mirror{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.asset_mirrors SET status='failed',error='worker lease expired',lease=NULL,lease_until=NULL,completed_at=clock_timestamp() WHERE status='running' AND lease_until<clock_timestamp()`); err != nil {
		return Mirror{}, err
	}
	m, err := scanMirror(tx.QueryRow(ctx, `UPDATE `+s.schema+`.asset_mirrors SET status='running',lease=$1,lease_until=clock_timestamp()+interval '30 minutes' WHERE id=(SELECT id FROM `+s.schema+`.asset_mirrors WHERE status='queued' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+mirrorColumns, uuid.New()))
	if errors.Is(err, ErrNotFound) {
		// Commit the expiry above even when nothing is queued; otherwise a
		// mirror whose worker died would stay running and block its asset.
		if err := tx.Commit(ctx); err != nil {
			return m, err
		}
		return m, ErrNotFound
	}
	if err != nil {
		return m, err
	}
	if err := tx.QueryRow(ctx, `SELECT a.locator,a.connection_id,m.lease FROM `+s.schema+`.assets a JOIN `+s.schema+`.asset_mirrors m ON m.asset_id=a.id WHERE m.id=$1`, m.ID).Scan(&m.Locator, &m.ConnectionID, &m.Lease); err != nil {
		return m, err
	}
	return m, tx.Commit(ctx)
}

// FinishMirror records the outcome under the claim's lease. On success it
// returns the object keys of bundles it marked pruned (beyond the newest
// keep and older than minAgeDays), for the caller to delete from S3.
func (s *Store) FinishMirror(ctx context.Context, m Mirror, result *Mirror, failure string, keep, minAgeDays int) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var tag interface{ RowsAffected() int64 }
	if result == nil {
		tag, err = tx.Exec(ctx, `UPDATE `+s.schema+`.asset_mirrors SET status='failed',error=$3,lease=NULL,lease_until=NULL,completed_at=clock_timestamp() WHERE id=$1 AND lease=$2 AND status='running'`, m.ID, m.Lease, clip(failure, 256))
	} else {
		tag, err = tx.Exec(ctx, `UPDATE `+s.schema+`.asset_mirrors SET status='succeeded',object_key=$3,sha256=$4,size_bytes=$5,refs=$6,head=$7,lease=NULL,lease_until=NULL,completed_at=clock_timestamp() WHERE id=$1 AND lease=$2 AND status='running'`, m.ID, m.Lease, result.ObjectKey, result.SHA256, result.SizeBytes, result.Refs, result.Head)
	}
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrLease
	}
	var pruned []string
	if result != nil && keep > 0 {
		// A bundle is pruned only when it is beyond the newest keep AND older
		// than minAgeDays, so mirroring a compromised repository repeatedly
		// cannot push every clean backup out. The newest bundle taken before
		// the asset's earliest open integrity entry is never pruned.
		rows, err := tx.Query(ctx, `UPDATE `+s.schema+`.asset_mirrors SET status='pruned' WHERE id IN (SELECT m.id FROM `+s.schema+`.asset_mirrors m WHERE m.asset_id=$1 AND m.status='succeeded' AND m.created_at<clock_timestamp()-($3*interval '1 day') AND m.id NOT IN (SELECT n.id FROM `+s.schema+`.asset_mirrors n WHERE n.asset_id=$1 AND n.status='succeeded' ORDER BY n.created_at DESC LIMIT $2) AND m.id IS DISTINCT FROM (SELECT g.id FROM `+s.schema+`.asset_mirrors g WHERE g.asset_id=$1 AND g.status='succeeded' AND g.created_at<(SELECT min(f.first_seen) FROM `+s.schema+`.findings f WHERE f.asset_id=$1 AND f.type='integrity' AND f.status IN ('open','triaged','in_progress')) ORDER BY g.created_at DESC LIMIT 1)) RETURNING object_key`, m.AssetID, keep, minAgeDays)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return nil, err
			}
			pruned = append(pruned, key)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	action := "mirror.failed"
	if result != nil {
		action = "mirror.succeeded"
	}
	details, _ := json.Marshal(map[string]any{"asset_id": m.AssetID, "error": failure, "pruned": len(pruned)})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, m.ID, details); err != nil {
		return nil, err
	}
	return pruned, tx.Commit(ctx)
}

// Mirrors lists an asset's 50 newest mirrors.
func (s *Store) Mirrors(ctx context.Context, asset uuid.UUID) ([]Mirror, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+mirrorColumns+` FROM `+s.schema+`.asset_mirrors WHERE asset_id=$1 ORDER BY created_at DESC LIMIT 50`, asset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mirror{}
	for rows.Next() {
		m, err := scanMirror(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetMirror returns one mirror of an asset.
func (s *Store) GetMirror(ctx context.Context, asset, id uuid.UUID) (Mirror, error) {
	return scanMirror(s.pool.QueryRow(ctx, `SELECT `+mirrorColumns+` FROM `+s.schema+`.asset_mirrors WHERE id=$1 AND asset_id=$2`, id, asset))
}
