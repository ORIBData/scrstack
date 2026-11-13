package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

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

const columns = `actor_id,id,asset_id,connection_id,connection_revision,request,requested_by,status,verdict,resolved_commit,ref_moved,stages,counts,created_at,completed_at,error,attempts,COALESCE(lease,'00000000-0000-0000-0000-000000000000'::uuid),sbom_key,sbom_sha256,diff,request_id,snapshot_key`

func scan(row pgx.Row) (Assessment, error) {
	var a Assessment
	var req, stages, counts, diff []byte
	err := row.Scan(&a.ActorID, &a.ID, &a.AssetID, &a.ConnectionID, &a.ConnectionRevision, &req, &a.RequestedBy, &a.Status, &a.Verdict, &a.Commit, &a.RefMoved, &stages, &counts, &a.CreatedAt, &a.CompletedAt, &a.Error, &a.Attempts, &a.Lease, &a.SBOMKey, &a.SBOMSHA256, &diff, &a.RequestID, &a.SnapshotKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	if json.Unmarshal(req, &a.Request) != nil || json.Unmarshal(stages, &a.Stages) != nil || json.Unmarshal(counts, &a.Counts) != nil {
		return a, errors.New("invalid assessment data")
	}
	if string(diff) != "{}" {
		a.Diff = diff
	}
	return a, nil
}
func (s *Store) Get(ctx context.Context, id uuid.UUID) (Assessment, error) {
	return scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id=$1`, id))
}
func (s *Store) Enqueue(ctx context.Context, request Request, actor uuid.UUID, name, key string) (Assessment, bool, error) {
	return s.enqueue(ctx, request, actor, name, key, nil)
}

// EnqueueEvent admits a provider event (direct or relay) and stores its raw body.
func (s *Store) EnqueueEvent(ctx context.Context, request Request, actor uuid.UUID, name, key string, raw []byte, mode, eventType string) (Assessment, bool, error) {
	if !json.Valid(raw) || len(raw) > 1<<20 {
		return Assessment{}, false, ErrInput
	}
	return s.enqueue(withInbound(ctx, mode, eventType), request, actor, name, key, raw)
}

type requestIDKey struct{}
type inboundKey struct{}

// WithRequestID attaches the API request id stored on new assessments (TRG-015).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}
func withInbound(ctx context.Context, mode, eventType string) context.Context {
	return context.WithValue(ctx, inboundKey{}, [2]string{mode, eventType})
}
func (s *Store) enqueue(ctx context.Context, request Request, actor uuid.UUID, name, key string, raw []byte) (Assessment, bool, error) {
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
	if raw != nil {
		hash = Hash(append(append([]byte{}, body...), raw...))
	}
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
	assetType := "github_repo"
	if request.Target.Type == "image" {
		assetType = "container_image"
	}
	rows, err := tx.Query(ctx, `SELECT a.id,c.id,c.configuration_revision FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.type=$3 AND lower(a.locator)=$1 AND c.enabled AND a.flags->>'in_scope'='true' AND a.flags->>'accessible'='true' AND ($2='' OR c.name=$2 OR c.id::text=$2)`, request.Target.Repository, request.Connection, assetType)
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
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	_, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.assessments(id,asset_id,connection_id,connection_revision,request,actor_id,requested_by,request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, a.ID, a.AssetID, a.ConnectionID, a.ConnectionRevision, body, actor, name, requestID)
	if err != nil {
		return a, false, err
	}
	if key != "" {
		_, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.assessment_idempotency(actor_id,key,body_hash,assessment_id,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '24 hours') ON CONFLICT(actor_id,key) DO UPDATE SET body_hash=EXCLUDED.body_hash,assessment_id=EXCLUDED.assessment_id,expires_at=EXCLUDED.expires_at`, actor, key, hash, a.ID)
		if err != nil {
			return a, false, err
		}
	}
	eventBody := body
	if raw != nil {
		eventBody = raw
	}
	inbound, _ := ctx.Value(inboundKey{}).([2]string)
	if inbound[0] == "" {
		inbound[0] = "trigger"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.inbound_events(id,assessment_id,actor_id,body,mode,event_type) VALUES($1,$2,$3,$4,$5,$6)`, uuid.New(), a.ID, actor, eventBody, inbound[0], inbound[1]); err != nil {
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
	expired, err := tx.Query(ctx, `UPDATE `+s.schema+`.assessments SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END,completed_at=CASE WHEN attempts>=3 THEN clock_timestamp() ELSE NULL END,error='worker lease expired',lease=NULL,lease_until=NULL,run_after=clock_timestamp()+interval '10 seconds' WHERE status='running' AND lease_until<clock_timestamp() RETURNING id,status`)
	if err != nil {
		return Assessment{}, err
	}
	var failed []uuid.UUID
	for expired.Next() {
		var id uuid.UUID
		var status string
		if err := expired.Scan(&id, &status); err != nil {
			expired.Close()
			return Assessment{}, err
		}
		if status == "failed" {
			failed = append(failed, id)
		}
	}
	expired.Close()
	if err := expired.Err(); err != nil {
		return Assessment{}, err
	}
	for _, id := range failed {
		if err := s.emitFailed(ctx, tx, id); err != nil {
			return Assessment{}, err
		}
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
	if state == "failed" {
		if err := s.emitFailed(ctx, tx, a.ID); err != nil {
			return err
		}
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

// ListFilter narrows assessment listings (TRG-007, INT-016). Zero values match all.
type ListFilter struct {
	After, Asset, ActorID uuid.UUID
	Status, Verdict       string
	Ref, Commit, Actor    string
	Since, Until          *time.Time
}

func (s *Store) List(ctx context.Context, f ListFilter) ([]Assessment, error) {
	if len(f.Ref) > 255 || len(f.Actor) > 100 || (f.Commit != "" && !validRevision(f.Commit)) {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id>$1 AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR asset_id=$2) AND ($3='' OR status=$3) AND ($4='00000000-0000-0000-0000-000000000000'::uuid OR actor_id=$4) AND ($5='' OR verdict=$5) AND ($6='' OR request->'target'->>'ref'=$6) AND ($7='' OR resolved_commit=$7 OR request->'target'->>'commit'=$7) AND ($8='' OR request->'trigger'->>'actor'=$8) AND ($9::timestamptz IS NULL OR created_at>=$9) AND ($10::timestamptz IS NULL OR created_at<$10) ORDER BY id LIMIT 101`, f.After, f.Asset, f.Status, f.ActorID, f.Verdict, f.Ref, strings.ToLower(f.Commit), f.Actor, f.Since, f.Until)
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

// Latest answers "what was the last result for this exact revision?" (UC13).
// Remediation plans are excluded; actor restricts to one token's own jobs.
func (s *Store) Latest(ctx context.Context, asset uuid.UUID, repository, commit string, actor uuid.UUID) (Assessment, error) {
	if !validRevision(commit) || (asset == uuid.Nil && !repositoryPattern.MatchString(repository) && !imagePattern.MatchString(repository)) {
		return Assessment{}, ErrInput
	}
	return scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments a WHERE (a.resolved_commit=$1 OR a.request->'target'->>'commit'=$1) AND a.request->'remediation' IS NULL AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR a.asset_id=$2) AND ($3='' OR lower(a.request->'target'->>'repository')=$3) AND ($4='00000000-0000-0000-0000-000000000000'::uuid OR a.actor_id=$4) ORDER BY a.created_at DESC,a.id DESC LIMIT 1`, strings.ToLower(commit), asset, strings.ToLower(repository), actor))
}

// LastKnownGood returns the newest passing assessment of an asset and ref
// whose revision has no open integrity entry (INT-017).
func (s *Store) LastKnownGood(ctx context.Context, asset uuid.UUID, ref string) (Assessment, error) {
	if ref == "" || len(ref) > 255 {
		return Assessment{}, ErrInput
	}
	return scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments a WHERE a.asset_id=$1 AND a.request->'target'->>'ref'=$2 AND a.status='succeeded' AND a.verdict='pass' AND a.request->'remediation' IS NULL AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.findings f WHERE f.asset_id=a.asset_id AND f.type='integrity' AND f.status IN ('open','triaged','in_progress') AND (f.last_assessment_id=a.id OR f.evidence->>'commit'=a.resolved_commit)) ORDER BY a.created_at DESC,a.id DESC LIMIT 1`, asset, ref))
}

func (s *Store) BindRevision(ctx context.Context, a Assessment, commit string, moved bool) error {
	if !validRevision(commit) {
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

// Stats summarizes queue and outcome state for metrics (TRG-015).
type Stats struct {
	Queue               map[string]int
	Verdicts            map[string]int
	Durations           map[string][2]float64
	OldestQueuedSeconds float64
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	st := Stats{Queue: map[string]int{}, Verdicts: map[string]int{}, Durations: map[string][2]float64{}}
	rows, err := s.pool.Query(ctx, `SELECT status,count(*) FROM `+s.schema+`.assessments WHERE status IN ('queued','running') GROUP BY status UNION ALL SELECT 'verdict:'||verdict,count(*) FROM `+s.schema+`.assessments WHERE status='succeeded' GROUP BY verdict`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			rows.Close()
			return st, err
		}
		if v, ok := strings.CutPrefix(key, "verdict:"); ok {
			st.Verdicts[v] = n
		} else {
			st.Queue[key] = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return st, err
	}
	rows, err = s.pool.Query(ctx, `SELECT CASE WHEN request->'remediation' IS NULL THEN 'scan' ELSE 'remediation_plan' END,percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM completed_at-created_at)),percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM completed_at-created_at)) FROM `+s.schema+`.assessments WHERE status='succeeded' AND completed_at>clock_timestamp()-interval '24 hours' GROUP BY 1`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var kind string
		var p50, p95 float64
		if err := rows.Scan(&kind, &p50, &p95); err != nil {
			rows.Close()
			return st, err
		}
		st.Durations[kind] = [2]float64{p50, p95}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return st, err
	}
	err = s.pool.QueryRow(ctx, `SELECT COALESCE(extract(epoch FROM clock_timestamp()-min(created_at)),0)::float8 FROM `+s.schema+`.assessments WHERE status='queued'`).Scan(&st.OldestQueuedSeconds)
	return st, err
}

// RecordSnapshot links a stored source archive to a running assessment.
func (s *Store) RecordSnapshot(ctx context.Context, a Assessment, key string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.assessments SET snapshot_key=$3 WHERE id=$1 AND lease=$2 AND status='running' AND lease_until>clock_timestamp()`, a.ID, a.Lease, key)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLease
	}
	return nil
}
