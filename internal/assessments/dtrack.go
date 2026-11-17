package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ORIBData/scrstack/internal/dtrack"
	"github.com/ORIBData/scrstack/internal/notify"
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
		// Processing state: an upload is accepted by Dependency-Track, which
		// then processes the BOM on its own; the worker checks the outcome.
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS processing text NOT NULL DEFAULT 'pending' CHECK(processing IN ('pending','processed','unconfirmed','failed'))`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS processing_attempts integer NOT NULL DEFAULT 0`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS processing_next_at timestamptz NOT NULL DEFAULT clock_timestamp()`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS processing_error text NOT NULL DEFAULT ''`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS processed_at timestamptz`,
		// Uploads from before this check, or still unchecked after a day, are not verified.
		`UPDATE ` + s + `.dtrack_uploads SET processing='unconfirmed' WHERE status='uploaded' AND processing='pending' AND uploaded_at<clock_timestamp()-interval '1 day'`,
		`ALTER TABLE ` + s + `.dtrack_settings ADD COLUMN IF NOT EXISTS import_findings boolean NOT NULL DEFAULT false`,
		`ALTER TABLE ` + s + `.dtrack_settings ADD COLUMN IF NOT EXISTS sync_triage boolean NOT NULL DEFAULT false`,
		`ALTER TABLE ` + s + `.dtrack_settings ADD COLUMN IF NOT EXISTS upload_pull_requests boolean NOT NULL DEFAULT false`,
		`ALTER TABLE ` + s + `.dtrack_settings ADD COLUMN IF NOT EXISTS upload_commit_only boolean NOT NULL DEFAULT false`,
		`ALTER TABLE ` + s + `.dtrack_settings ADD COLUMN IF NOT EXISTS tags jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS target_ref text NOT NULL DEFAULT ''`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS is_latest boolean NOT NULL DEFAULT false`,
		`ALTER TABLE ` + s + `.dtrack_uploads ADD COLUMN IF NOT EXISTS tags jsonb NOT NULL DEFAULT '[]'`,
		`CREATE INDEX IF NOT EXISTS dtrack_uploads_verify_idx ON ` + s + `.dtrack_uploads(processing_next_at) WHERE status='uploaded' AND processing='pending'`,
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
	// ImportFindings pulls Dependency-Track's findings for uploaded projects
	// into the register; SyncTriage shares triage decisions both ways.
	ImportFindings bool `json:"import_findings"`
	SyncTriage     bool `json:"sync_triage"`
	// Pull requests and commit-only git targets are not uploaded unless
	// asked for: each would create another project version.
	UploadPullRequests bool `json:"upload_pull_requests"`
	UploadCommitOnly   bool `json:"upload_commit_only"`
	// Tags replace the tags of every project SCRS uploads to (needs the
	// PORTFOLIO_MANAGEMENT permission).
	Tags      []string  `json:"tags"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
	// Key is the sealed API key (worker only).
	Key []byte `json:"-"`
}

// RequiredPermissions are the Dependency-Track permissions the enabled
// features need.
func (d DTrackSettings) RequiredPermissions() []string {
	out := append([]string{}, dtrack.BasePermissions...)
	if d.ImportFindings {
		out = append(out, dtrack.ImportPermissions...)
	}
	if d.SyncTriage {
		out = append(out, dtrack.TriagePermissions...)
	}
	if len(d.Tags) > 0 {
		out = append(out, dtrack.TaggingPermissions...)
	}
	return out
}

// DTrackChange updates the settings; a nil Key keeps the stored key.
type DTrackChange struct {
	Enabled            bool
	URL                string
	Parent             *uuid.UUID
	Key                []byte
	ImportFindings     bool
	SyncTriage         bool
	UploadPullRequests bool
	UploadCommitOnly   bool
	Tags               []string
}

// DTrackSettings reads the export settings.
func (s *Store) DTrackSettings(ctx context.Context) (DTrackSettings, error) {
	var d DTrackSettings
	var tags []byte
	err := s.pool.QueryRow(ctx, `SELECT enabled,url,api_key_ciphertext,parent_uuid,import_findings,sync_triage,upload_pull_requests,upload_commit_only,tags,revision,updated_at FROM `+s.schema+`.dtrack_settings WHERE id=1`).Scan(&d.Enabled, &d.URL, &d.Key, &d.Parent, &d.ImportFindings, &d.SyncTriage, &d.UploadPullRequests, &d.UploadCommitOnly, &tags, &d.Revision, &d.UpdatedAt)
	d.APIKeySet = len(d.Key) > 0
	d.Tags = []string{}
	if len(tags) > 0 {
		_ = json.Unmarshal(tags, &d.Tags)
	}
	return d, err
}

// SetDTrackSettings replaces the settings at the expected revision.
func (s *Store) SetDTrackSettings(ctx context.Context, expected int64, c DTrackChange, actor uuid.UUID) (DTrackSettings, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DTrackSettings{}, err
	}
	defer tx.Rollback(ctx)
	if c.SyncTriage && !c.ImportFindings {
		return DTrackSettings{}, ErrInput
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	tags, _ := json.Marshal(c.Tags)
	var keySet bool
	err = tx.QueryRow(ctx, `UPDATE `+s.schema+`.dtrack_settings SET enabled=$2,url=$3,parent_uuid=$4,api_key_ciphertext=COALESCE($5,api_key_ciphertext),import_findings=$6,sync_triage=$7,upload_pull_requests=$8,upload_commit_only=$9,tags=$10,revision=revision+1,updated_at=clock_timestamp() WHERE id=1 AND revision=$1 RETURNING api_key_ciphertext IS NOT NULL`, expected, c.Enabled, c.URL, c.Parent, c.Key, c.ImportFindings, c.SyncTriage, c.UploadPullRequests, c.UploadCommitOnly, tags).Scan(&keySet)
	if errors.Is(err, pgx.ErrNoRows) {
		return DTrackSettings{}, ErrConflict
	}
	if err != nil {
		return DTrackSettings{}, err
	}
	if c.Enabled && (!keySet || c.URL == "") {
		return DTrackSettings{}, ErrInput
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "enabled": c.Enabled, "url": c.URL, "parent_uuid": c.Parent, "api_key_replaced": c.Key != nil, "import_findings": c.ImportFindings, "sync_triage": c.SyncTriage, "upload_pull_requests": c.UploadPullRequests, "upload_commit_only": c.UploadCommitOnly, "tags": c.Tags})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('dependency_track.updated',NULL,$1)`, details); err != nil {
		return DTrackSettings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return DTrackSettings{}, err
	}
	return s.DTrackSettings(ctx)
}

// DTrackIdentity is how an assessment appears in Dependency-Track.
type DTrackIdentity struct {
	Project, Version string
	// IsLatest marks the default branch's version as the project's latest.
	IsLatest bool
}

// dtrackIdentity names the Dependency-Track project and version for an
// assessment. The project name carries the provider (github, gitlab, image),
// so two repositories with the same path never share a project. The version
// is the ref; a git target without a ref (a bare commit) and pull request
// scans are skipped unless the settings ask for them, because each would
// create another project version. An image falls back to its digest.
// ok is false when the assessment is not uploaded.
func dtrackIdentity(assetType, locator, defaultBranch string, t Target, commit string, uploadPR, uploadCommitOnly bool) (id DTrackIdentity, ok bool) {
	prefix := map[string]string{"github_repo": "github", "gitlab_repo": "gitlab", "container_image": "image"}[assetType]
	if prefix == "" {
		prefix = assetType
	}
	git := assetType == "github_repo" || assetType == "gitlab_repo"
	if t.PullRequest != nil && !uploadPR {
		return id, false
	}
	if git && t.Ref == "" && !uploadCommitOnly {
		return id, false
	}
	version := t.Ref
	if version == "" {
		version = commit
	}
	if version == "" {
		version = "latest"
	}
	return DTrackIdentity{Project: prefix + "/" + locator, Version: clip(version, 255), IsLatest: git && defaultBranch != "" && t.Ref == defaultBranch && t.PullRequest == nil}, true
}

// queueDTrack queues the SBOM of a completed scan when the export is
// enabled. It runs inside Complete's transaction.
func (s *Store) queueDTrack(ctx context.Context, tx pgx.Tx, a Assessment, sbomKey string) error {
	if sbomKey == "" || a.Request.Import != nil || a.Request.Remediation != nil || a.AssetID == uuid.Nil {
		return nil
	}
	var enabled, uploadPR, uploadCommitOnly bool
	var tags []byte
	var assetType, locator, defaultBranch string
	err := tx.QueryRow(ctx, `SELECT d.enabled,d.upload_pull_requests,d.upload_commit_only,d.tags,a.type,a.locator,COALESCE(a.metadata->>'default_branch','') FROM `+s.schema+`.assets a,`+s.schema+`.dtrack_settings d WHERE a.id=$1 AND d.id=1`, a.AssetID).Scan(&enabled, &uploadPR, &uploadCommitOnly, &tags, &assetType, &locator, &defaultBranch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	id, ok := dtrackIdentity(assetType, locator, defaultBranch, a.Request.Target, a.Commit, uploadPR, uploadCommitOnly)
	if !enabled || !ok {
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.dtrack_uploads(id,assessment_id,asset_id,project_name,project_version,sbom_key,target_ref,is_latest,tags) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(assessment_id) DO NOTHING`, uuid.New(), a.ID, a.AssetID, id.Project, id.Version, sbomKey, a.Request.Target.Ref, id.IsLatest, tags)
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
	// Processing is Dependency-Track's side after the upload was accepted:
	// pending (not yet checked), processed (finished and the project's last
	// BOM import is newer than the upload), unconfirmed (finished, but the
	// key cannot read projects or the check ran out of time) or failed
	// (finished without importing the BOM).
	Processing         string     `json:"processing,omitempty"`
	ProcessingError    string     `json:"processing_error,omitempty"`
	ProcessedAt        *time.Time `json:"processed_at,omitempty"`
	ProcessingAttempts int        `json:"-"`
	SBOMKey            string     `json:"-"`
	Lease              uuid.UUID  `json:"-"`
	TargetRef          string     `json:"-"`
	IsLatest           bool       `json:"-"`
	Tags               []string   `json:"-"`
}

const dtrackColumns = `id,assessment_id,asset_id,project_name,project_version,status,attempts,next_attempt_at,token,error,created_at,uploaded_at,sbom_key,COALESCE(lease,'00000000-0000-0000-0000-000000000000'::uuid),processing,processing_error,processed_at,processing_attempts,target_ref,is_latest,tags`

func scanDTrack(row pgx.Row) (DTrackUpload, error) {
	var u DTrackUpload
	var tags []byte
	err := row.Scan(&u.ID, &u.AssessmentID, &u.AssetID, &u.ProjectName, &u.ProjectVersion, &u.Status, &u.Attempts, &u.NextAttemptAt, &u.Token, &u.Error, &u.CreatedAt, &u.UploadedAt, &u.SBOMKey, &u.Lease, &u.Processing, &u.ProcessingError, &u.ProcessedAt, &u.ProcessingAttempts, &u.TargetRef, &u.IsLatest, &tags)
	if err == nil && len(tags) > 0 {
		_ = json.Unmarshal(tags, &u.Tags)
	}
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

// dtrackVerifyDelay is how long after an accepted upload the first
// processing check runs.
const dtrackVerifyDelay = 15 * time.Second

// FinishDTrack records an attempt under its lease: uploaded, retried later
// (transient), or failed (permanent or out of attempts). A failure that ends
// retries also emits dependency_track.upload_failed.
func (s *Store) FinishDTrack(ctx context.Context, u DTrackUpload, token string, uploadErr error, permanent bool) error {
	switch {
	case uploadErr == nil:
		_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='uploaded',token=$3,error='',uploaded_at=clock_timestamp(),lease=NULL,lease_until=NULL,processing='pending',processing_attempts=0,processing_next_at=clock_timestamp()+($4*interval '1 second') WHERE id=$1 AND lease=$2`, u.ID, u.Lease, token, int64(dtrackVerifyDelay.Seconds()))
		return err
	case permanent || u.Attempts >= dtrackMaxAttempts:
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='failed',error=left($3,500),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, u.ID, u.Lease, uploadErr.Error())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			if err := s.emitDTrackFailed(ctx, tx, u, "upload", uploadErr.Error()); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	default:
		backoff := time.Duration(1<<min(u.Attempts, 9)) * time.Minute
		_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET status='queued',error=left($3,500),next_attempt_at=clock_timestamp()+($4*interval '1 second'),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, u.ID, u.Lease, uploadErr.Error(), int64(backoff.Seconds()))
		return err
	}
}

// emitDTrackFailed announces an upload that will not reach, or was not
// imported by, Dependency-Track. stage is "upload" or "processing".
func (s *Store) emitDTrackFailed(ctx context.Context, tx pgx.Tx, u DTrackUpload, stage, detail string) error {
	if len(detail) > 500 {
		detail = detail[:500]
	}
	data := map[string]any{"upload_id": u.ID, "assessment_id": u.AssessmentID, "project": u.ProjectName, "version": u.ProjectVersion, "stage": stage, "error": detail}
	if u.AssetID != nil {
		data["asset_id"] = *u.AssetID
	}
	_, err := notify.Emit(ctx, tx, s.schema, "dependency_track.upload_failed", data, nil)
	return err
}

// Processing check bounds: a check every 30 s, about ten minutes in all.
const (
	DTrackVerifyEvery    = 30 * time.Second
	DTrackVerifyAttempts = 20
)

// ClaimDTrackVerify picks an accepted upload whose processing is unchecked and
// due, while the export is enabled; ErrNotFound when none is due. The claim
// only pushes the next check back, so a crashed worker is retried and
// DTrackVerifyAttempts bounds the whole thing.
func (s *Store) ClaimDTrackVerify(ctx context.Context) (DTrackUpload, error) {
	u, err := scanDTrack(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET processing_attempts=processing_attempts+1,processing_next_at=clock_timestamp()+($1*interval '1 second') WHERE id=(SELECT u.id FROM `+s.schema+`.dtrack_uploads u,`+s.schema+`.dtrack_settings d WHERE d.id=1 AND d.enabled AND u.status='uploaded' AND u.processing='pending' AND u.processing_next_at<=clock_timestamp() ORDER BY u.processing_next_at LIMIT 1 FOR UPDATE OF u SKIP LOCKED) RETURNING `+dtrackColumns, int64(DTrackVerifyEvery.Seconds())))
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// FinishDTrackVerify records a processing check. outcome is "pending" (still
// running; checked again later), "processed", "unconfirmed" or "failed";
// detail explains the last three. A "failed" outcome emits
// dependency_track.upload_failed.
func (s *Store) FinishDTrackVerify(ctx context.Context, u DTrackUpload, outcome, detail string) error {
	if outcome == "pending" {
		_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET processing_error=left($2,500) WHERE id=$1 AND processing='pending'`, u.ID, detail)
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.dtrack_uploads SET processing=$2,processing_error=left($3,500),processed_at=clock_timestamp() WHERE id=$1 AND processing='pending'`, u.ID, outcome, detail)
	if err != nil {
		return err
	}
	if outcome == "failed" && tag.RowsAffected() == 1 {
		if err := s.emitDTrackFailed(ctx, tx, u, "processing", detail); err != nil {
			return err
		}
	}
	// An imported BOM makes its project one to read findings back from.
	if (outcome == "processed" || outcome == "unconfirmed") && tag.RowsAffected() == 1 && u.AssetID != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.dtrack_projects(project_name,project_version,asset_id,ref,assessment_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(project_name,project_version) DO UPDATE SET asset_id=EXCLUDED.asset_id,ref=EXCLUDED.ref,assessment_id=EXCLUDED.assessment_id,status='pending',attempts=0,next_sync_at=clock_timestamp()`, u.ProjectName, u.ProjectVersion, *u.AssetID, u.TargetRef, u.AssessmentID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DTrackSummary is the state of the export for the status view.
type DTrackSummary struct {
	Queued              int
	FailedLast24h       int
	ProcessingFailed24h int
	Unverified          int
	OldestQueued        *time.Time
	LastUploadedAt      *time.Time
	LastProcessedAt     *time.Time
	// Findings read-back: projects whose last sync failed, the last
	// successful sync, and open entries only Dependency-Track reported.
	SyncErrors     int
	LastSyncedAt   *time.Time
	OnlyDTrackOpen int
}

// DTrackSummary counts the export's backlog and recent failures.
func (s *Store) DTrackSummary(ctx context.Context) (DTrackSummary, error) {
	var d DTrackSummary
	err := s.pool.QueryRow(ctx, `SELECT
 count(*) FILTER (WHERE status IN ('queued','sending')),
 count(*) FILTER (WHERE status='failed' AND created_at>clock_timestamp()-interval '24 hours'),
 count(*) FILTER (WHERE processing='failed' AND processed_at>clock_timestamp()-interval '24 hours'),
 count(*) FILTER (WHERE status='uploaded' AND processing='pending'),
 min(created_at) FILTER (WHERE status IN ('queued','sending')),
 max(uploaded_at),
 max(processed_at) FILTER (WHERE processing='processed')
 FROM `+s.schema+`.dtrack_uploads`).Scan(&d.Queued, &d.FailedLast24h, &d.ProcessingFailed24h, &d.Unverified, &d.OldestQueued, &d.LastUploadedAt, &d.LastProcessedAt)
	if err != nil {
		return d, err
	}
	err = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM `+s.schema+`.dtrack_projects WHERE status='error'),(SELECT max(last_synced_at) FROM `+s.schema+`.dtrack_projects),(SELECT count(*) FROM `+s.schema+`.findings WHERE type='dt_vulnerability' AND status IN ('open','triaged','in_progress'))`).Scan(&d.SyncErrors, &d.LastSyncedAt, &d.OnlyDTrackOpen)
	return d, err
}

// PruneDTrack deletes finished uploads older than the given age.
func (s *Store) PruneDTrack(ctx context.Context, age time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM `+s.schema+`.dtrack_uploads WHERE status IN ('uploaded','failed') AND created_at<clock_timestamp()-($1*interval '1 second')`, int64(age.Seconds()))
	return tag.RowsAffected(), err
}
