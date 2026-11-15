package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Dependency-Track export (P2, section 15.1). One settings row; each
// completed scan with an SBOM queues an upload in the transaction that
// completes it (an outbox), and the worker pushes queued uploads with a
// lease and backoff. Uploads never change an assessment.

func dtrackSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.dtrack_settings(id integer PRIMARY KEY CHECK(id=1),enabled boolean NOT NULL DEFAULT false,url text NOT NULL DEFAULT '',api_key_ciphertext bytea,parent_uuid uuid,revision bigint NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`INSERT INTO ` + s + `.dtrack_settings(id) VALUES(1) ON CONFLICT DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.dtrack_uploads(id uuid PRIMARY KEY,assessment_id uuid NOT NULL UNIQUE,asset_id uuid,project_name text NOT NULL,project_version text NOT NULL,sbom_key text NOT NULL,status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','sending','uploaded','failed')),attempts integer NOT NULL DEFAULT 0,next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease uuid,lease_until timestamptz,token text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),uploaded_at timestamptz)`,
		`CREATE INDEX IF NOT EXISTS dtrack_uploads_due_idx ON ` + s + `.dtrack_uploads(next_attempt_at) WHERE status IN ('queued','sending')`,
		`CREATE INDEX IF NOT EXISTS dtrack_uploads_created_idx ON ` + s + `.dtrack_uploads(created_at DESC,id DESC)`,
	}
}

// DTrackAAD binds the sealed API key to its use.
func DTrackAAD() []byte { return []byte("dependency-track:api-key") }

// DTrackSettings is the export configuration; the API key is write-only.
type DTrackSettings struct {
	Enabled   bool       `json:"enabled"`
	URL       string     `json:"url"`
	APIKeySet bool       `json:"api_key_set"`
	Parent    *uuid.UUID `json:"parent_uuid,omitempty"`
	Revision  int64      `json:"revision"`
	UpdatedAt time.Time  `json:"updated_at"`
	// Key is the sealed API key (worker only).
	Key []byte `json:"-"`
}

// DTrackChange updates the settings; a nil Key keeps the stored key.
type DTrackChange struct {
	Enabled bool
	URL     string
	Parent  *uuid.UUID
	Key     []byte
}

// DTrackSettings reads the export settings.
func (s *Store) DTrackSettings(ctx context.Context) (DTrackSettings, error) {
	var d DTrackSettings
	err := s.pool.QueryRow(ctx, `SELECT enabled,url,api_key_ciphertext,parent_uuid,revision,updated_at FROM `+s.schema+`.dtrack_settings WHERE id=1`).Scan(&d.Enabled, &d.URL, &d.Key, &d.Parent, &d.Revision, &d.UpdatedAt)
	d.APIKeySet = len(d.Key) > 0
	return d, err
}

// SetDTrackSettings replaces the settings at the expected revision.
func (s *Store) SetDTrackSettings(ctx context.Context, expected int64, c DTrackChange, actor uuid.UUID) (DTrackSettings, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DTrackSettings{}, err
	}
	defer tx.Rollback(ctx)
	var keySet bool
	err = tx.QueryRow(ctx, `UPDATE `+s.schema+`.dtrack_settings SET enabled=$2,url=$3,parent_uuid=$4,api_key_ciphertext=COALESCE($5,api_key_ciphertext),revision=revision+1,updated_at=clock_timestamp() WHERE id=1 AND revision=$1 RETURNING api_key_ciphertext IS NOT NULL`, expected, c.Enabled, c.URL, c.Parent, c.Key).Scan(&keySet)
	if errors.Is(err, pgx.ErrNoRows) {
		return DTrackSettings{}, ErrConflict
	}
	if err != nil {
		return DTrackSettings{}, err
	}
	if c.Enabled && (!keySet || c.URL == "") {
		return DTrackSettings{}, ErrInput
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "enabled": c.Enabled, "url": c.URL, "parent_uuid": c.Parent, "api_key_replaced": c.Key != nil})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('dependency_track.updated',NULL,$1)`, details); err != nil {
		return DTrackSettings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return DTrackSettings{}, err
	}
	return s.DTrackSettings(ctx)
}

// queueDTrack queues the SBOM of a completed scan when the export is
// enabled. It runs inside Complete's transaction.
func (s *Store) queueDTrack(ctx context.Context, tx pgx.Tx, a Assessment, sbomKey string) error {
	if sbomKey == "" || a.Request.Import != nil || a.Request.Remediation != nil || a.AssetID == uuid.Nil {
		return nil
	}
	version := a.Request.Target.Ref
	if version == "" {
		version = a.Commit
	}
	if version == "" {
		version = "latest"
	}
	_, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.dtrack_uploads(id,assessment_id,asset_id,project_name,project_version,sbom_key) SELECT $1,$2,a.id,a.locator,left($4,255),$5 FROM `+s.schema+`.assets a,`+s.schema+`.dtrack_settings d WHERE a.id=$3 AND d.id=1 AND d.enabled ON CONFLICT(assessment_id) DO NOTHING`, uuid.New(), a.ID, a.AssetID, version, sbomKey)
	return err
}

// DTrackUpload is one queued or finished upload.
type DTrackUpload struct {
	ID             uuid.UUID  `json:"id"`
	AssessmentID   uuid.UUID  `json:"assessment_id"`
	AssetID        *uuid.UUID `json:"asset_id,omitempty"`
	ProjectName    string     `json:"project_name"`
	ProjectVersion string     `json:"project_version"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
	Token          string     `json:"token,omitempty"`
	Error          string     `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UploadedAt     *time.Time `json:"uploaded_at,omitempty"`
	SBOMKey        string     `json:"-"`
	Lease          uuid.UUID  `json:"-"`
}

const dtrackColumns = `id,assessment_id,asset_id,project_name,project_version,status,attempts,next_attempt_at,token,error,created_at,uploaded_at,sbom_key,COALESCE(lease,'00000000-0000-0000-0000-000000000000'::uuid)`

func scanDTrack(row pgx.Row) (DTrackUpload, error) {
	var u DTrackUpload
	err := row.Scan(&u.ID, &u.AssessmentID, &u.AssetID, &u.ProjectName, &u.ProjectVersion, &u.Status, &u.Attempts, &u.NextAttemptAt, &u.Token, &u.Error, &u.CreatedAt, &u.UploadedAt, &u.SBOMKey, &u.Lease)
	return u, err
}

// DTrackUploads lists uploads, newest first, optionally by status.
func (s *Store) DTrackUploads(ctx context.Context, status string, before uuid.UUID, limit int) ([]DTrackUpload, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+dtrackColumns+` FROM `+s.schema+`.dtrack_uploads WHERE ($1='' OR status=$1) AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR (created_at,id)<(SELECT created_at,id FROM `+s.schema+`.dtrack_uploads WHERE id=$2)) ORDER BY created_at DESC,id DESC LIMIT $3`, status, before, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DTrackUpload{}
	for rows.Next() {
		u, err := scanDTrack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// RetryDTrack requeues a failed upload.
func (s *Store) RetryDTrack(ctx context.Context, id, actor uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='queued',attempts=0,next_attempt_at=clock_timestamp(),error='' WHERE id=$1 AND status='failed'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor})
	_, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('dependency_track.retried',$1,$2)`, id, details)
	return err
}

// DTrackLease bounds one upload attempt.
const DTrackLease = 5 * time.Minute

// ClaimDTrack leases the most overdue upload while the export is enabled;
// ErrNotFound when none is due.
func (s *Store) ClaimDTrack(ctx context.Context) (DTrackUpload, error) {
	u, err := scanDTrack(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='sending',lease=gen_random_uuid(),lease_until=clock_timestamp()+($1*interval '1 second'),attempts=attempts+1 WHERE id=(SELECT u.id FROM `+s.schema+`.dtrack_uploads u,`+s.schema+`.dtrack_settings d WHERE d.id=1 AND d.enabled AND ((u.status='queued' AND u.next_attempt_at<=clock_timestamp()) OR (u.status='sending' AND u.lease_until<clock_timestamp())) ORDER BY u.next_attempt_at LIMIT 1 FOR UPDATE OF u SKIP LOCKED) RETURNING `+dtrackColumns, int64(DTrackLease.Seconds())))
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// dtrackMaxAttempts ends retries of transient failures (about two days
// with the backoff below).
const dtrackMaxAttempts = 12

// FinishDTrack records an attempt under its lease: uploaded, retried later
// (transient), or failed (permanent or out of attempts).
func (s *Store) FinishDTrack(ctx context.Context, u DTrackUpload, token string, uploadErr error, permanent bool) error {
	var err error
	switch {
	case uploadErr == nil:
		_, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='uploaded',token=$3,error='',uploaded_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, u.ID, u.Lease, token)
	case permanent || u.Attempts >= dtrackMaxAttempts:
		_, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='failed',error=left($3,500),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, u.ID, u.Lease, uploadErr.Error())
	default:
		backoff := time.Duration(1<<min(u.Attempts, 9)) * time.Minute
		_, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='queued',error=left($3,500),next_attempt_at=clock_timestamp()+($4*interval '1 second'),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, u.ID, u.Lease, uploadErr.Error(), int64(backoff.Seconds()))
	}
	return err
}

// PruneDTrack deletes finished uploads older than the given age.
func (s *Store) PruneDTrack(ctx context.Context, age time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM `+s.schema+`.dtrack_uploads WHERE status IN ('uploaded','failed') AND created_at<clock_timestamp()-($1*interval '1 second')`, int64(age.Seconds()))
	return tag.RowsAffected(), err
}
