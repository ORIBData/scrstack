package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool   *pgxpool.Pool
	schema string
}

func Open(ctx context.Context, url, schema string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("assessment database configuration failed")
	}
	if cfg.MaxConns > 8 {
		cfg.MaxConns = 8
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("assessment database configuration failed")
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, errors.New("assessment database unavailable")
	}
	return &Store{p, pgx.Identifier{schema}.Sanitize()}, nil
}
func (s *Store) Close() { s.pool.Close() }

const columns = `actor_id,id,asset_id,connection_id,connection_revision,request,requested_by,status,verdict,resolved_commit,ref_moved,stages,counts,created_at,completed_at,error,attempts,COALESCE(lease,'00000000-0000-0000-0000-000000000000'::uuid),sbom_key,sbom_sha256`

func scan(row pgx.Row) (Assessment, error) {
	var a Assessment
	var req, stages, counts []byte
	err := row.Scan(&a.ActorID, &a.ID, &a.AssetID, &a.ConnectionID, &a.ConnectionRevision, &req, &a.RequestedBy, &a.Status, &a.Verdict, &a.Commit, &a.RefMoved, &stages, &counts, &a.CreatedAt, &a.CompletedAt, &a.Error, &a.Attempts, &a.Lease, &a.SBOMKey, &a.SBOMSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	if json.Unmarshal(req, &a.Request) != nil || json.Unmarshal(stages, &a.Stages) != nil || json.Unmarshal(counts, &a.Counts) != nil {
		return a, errors.New("invalid assessment data")
	}
	return a, nil
}
func (s *Store) Get(ctx context.Context, id uuid.UUID) (Assessment, error) {
	return scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id=$1`, id))
}
func (s *Store) Enqueue(ctx context.Context, request Request, actor uuid.UUID, name, key string) (Assessment, bool, error) {
	if err := request.Validate(); err != nil {
		return Assessment{}, false, err
	}
	if key == "" {
		key = request.Trigger.DeliveryID
	}
	if len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		return Assessment{}, false, ErrInput
	}
	body, _ := json.Marshal(request)
	hash := Hash(body)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Assessment{}, false, err
	}
	defer tx.Rollback(ctx)
	// Serialize short admission transactions to enforce queue capacity and per-token idempotency atomically.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".assessment_admission"); err != nil {
		return Assessment{}, false, err
	}
	if key != "" {
		var id uuid.UUID
		var previous string
		err := tx.QueryRow(ctx, `SELECT assessment_id,body_hash FROM `+s.schema+`.assessment_idempotency WHERE actor_id=$1 AND key=$2 AND expires_at>clock_timestamp()`, actor, key).Scan(&id, &previous)
		if err == nil {
			if previous != hash {
				return Assessment{}, false, ErrConflict
			}
			a, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id=$1`, id))
			return a, true, err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return Assessment{}, false, err
		}
	}
	rows, err := tx.Query(ctx, `SELECT a.id,c.id,c.configuration_revision FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.type='github_repo' AND lower(a.locator)=$1 AND c.enabled AND a.flags->>'in_scope'='true' AND a.flags->>'accessible'='true' AND ($2='' OR c.name=$2 OR c.id::text=$2)`, request.Target.Repository, request.Connection)
	if err != nil {
		return Assessment{}, false, err
	}
	a := Assessment{ID: uuid.New()}
	matches := 0
	for rows.Next() {
		matches++
		if err := rows.Scan(&a.AssetID, &a.ConnectionID, &a.ConnectionRevision); err != nil {
			rows.Close()
			return a, false, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return a, false, err
	}
	if matches == 0 {
		return a, false, ErrScope
	}
	if matches != 1 {
		return a, false, ErrAmbiguous
	}
	var eligible bool
	if err := tx.QueryRow(ctx, `SELECT enabled AND configuration_revision=$2 FROM `+s.schema+`.connections WHERE id=$1 FOR SHARE`, a.ConnectionID, a.ConnectionRevision).Scan(&eligible); err != nil {
		return a, false, err
	}
	if !eligible {
		return a, false, ErrScope
	}
	if err := tx.QueryRow(ctx, `SELECT flags->>'in_scope'='true' AND flags->>'accessible'='true' FROM `+s.schema+`.assets WHERE id=$1 FOR SHARE`, a.AssetID).Scan(&eligible); err != nil {
		return a, false, err
	}
	if !eligible {
		return a, false, ErrScope
	}
	var depth int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+s.schema+`.assessments WHERE status IN ('queued','running')`).Scan(&depth); err != nil {
		return a, false, err
	}
	if depth >= 500 {
		return a, false, ErrCapacity
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.assessments(id,asset_id,connection_id,connection_revision,request,actor_id,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7)`, a.ID, a.AssetID, a.ConnectionID, a.ConnectionRevision, body, actor, name)
	if err != nil {
		return a, false, err
	}
	if key != "" {
		_, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.assessment_idempotency(actor_id,key,body_hash,assessment_id,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '24 hours') ON CONFLICT(actor_id,key) DO UPDATE SET body_hash=EXCLUDED.body_hash,assessment_id=EXCLUDED.assessment_id,expires_at=EXCLUDED.expires_at`, actor, key, hash, a.ID)
		if err != nil {
			return a, false, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.inbound_events(id,assessment_id,actor_id,body) VALUES($1,$2,$3,$4)`, uuid.New(), a.ID, actor, body); err != nil {
		return a, false, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "requested_by": name})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('assessment.queued',$1,$2)`, a.ID, details); err != nil {
		return a, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return a, false, err
	}
	a, err = s.Get(ctx, a.ID)
	return a, false, err
}
func (s *Store) Claim(ctx context.Context) (Assessment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Assessment{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".assessment_claim"); err != nil {
		return Assessment{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END,completed_at=CASE WHEN attempts>=3 THEN clock_timestamp() ELSE NULL END,error='worker lease expired',lease=NULL,lease_until=NULL,run_after=clock_timestamp()+interval '10 seconds' WHERE status='running' AND lease_until<clock_timestamp()`); err != nil {
		return Assessment{}, err
	}
	// FIFO within an asset: a running assessment blocks another claim for that asset.
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT a.id FROM `+s.schema+`.assessments a WHERE a.status='queued' AND a.run_after<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments running WHERE running.asset_id=a.asset_id AND running.status='running') AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.assessments older WHERE older.asset_id=a.asset_id AND older.status='queued' AND (older.created_at,older.id)<(a.created_at,a.id)) ORDER BY a.created_at,a.id LIMIT 1 FOR UPDATE OF a SKIP LOCKED`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return Assessment{}, err
		}
		return Assessment{}, ErrNotFound
	}
	if err != nil {
		return Assessment{}, err
	}
	lease := uuid.New()
	a, err := scan(tx.QueryRow(ctx, `UPDATE `+s.schema+`.assessments SET status='running',attempts=attempts+1,lease=$2,lease_until=clock_timestamp()+interval '10 minutes',error='' WHERE id=$1 RETURNING `+columns, id, lease))
	if err != nil {
		return a, err
	}
	return a, tx.Commit(ctx)
}
func (s *Store) Fail(ctx context.Context, a Assessment, message string, retry bool) error {
	if len(message) > 256 {
		message = message[:256]
	}
	state := "failed"
	if retry && a.Attempts < 3 {
		state = "queued"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET status=$3,error=$4,verdict='incomplete',lease=NULL,lease_until=NULL,run_after=clock_timestamp()+($5*interval '1 second'),completed_at=CASE WHEN $3='failed' THEN clock_timestamp() ELSE NULL END WHERE id=$1 AND lease=$2 AND status='running' AND lease_until>clock_timestamp()`, a.ID, a.Lease, state, message, 5*(1<<a.Attempts))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLease
	}
	details, _ := json.Marshal(map[string]any{"status": state, "attempt": a.Attempts, "error": message})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('assessment.attempt_failed',$1,$2)`, a.ID, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Cancel(ctx context.Context, id, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET status='cancelled',verdict='incomplete',lease=NULL,lease_until=NULL,completed_at=clock_timestamp() WHERE id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('assessment.cancelled',$1,$2)`, id, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) List(ctx context.Context, after uuid.UUID, asset uuid.UUID, status string, actor uuid.UUID) ([]Assessment, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id>$1 AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR asset_id=$2) AND ($3='' OR status=$3) AND ($4='00000000-0000-0000-0000-000000000000'::uuid OR actor_id=$4) ORDER BY id LIMIT 101`, after, asset, status, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Assessment{}
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (s *Store) BindRevision(ctx context.Context, a Assessment, commit string, moved bool) error {
	if !commitPattern.MatchString(commit) {
		return ErrInput
	}
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.assessments SET resolved_commit=$3,ref_moved=$4 WHERE id=$1 AND lease=$2 AND status='running' AND lease_until>clock_timestamp() AND (resolved_commit='' OR resolved_commit=$3)`, a.ID, a.Lease, commit, moved)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLease
	}
	return nil
}
