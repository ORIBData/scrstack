package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Upload is one source archive submitted for an `uploaded` asset. Its commit
// (the first 40 hex digits of the SHA-256) is the revision that assessments
// of the asset target, the way a commit is for a repository.
type Upload struct {
	ID         uuid.UUID `json:"id"`
	AssetID    uuid.UUID `json:"asset_id"`
	SHA256     string    `json:"sha256"`
	Commit     string    `json:"commit"`
	Size       int64     `json:"size"`
	Filename   string    `json:"filename,omitempty"`
	Label      string    `json:"label,omitempty"`
	UploadedBy string    `json:"uploaded_by"`
	CreatedAt  time.Time `json:"created_at"`
	// ObjectKey is where the archive is stored; it is never returned.
	ObjectKey string `json:"-"`
}

const uploadColumns = `id,asset_id,sha256,size,filename,label,object_key,uploaded_by,created_at`

func scanUpload(row pgx.Row) (Upload, error) {
	var u Upload
	err := row.Scan(&u.ID, &u.AssetID, &u.SHA256, &u.Size, &u.Filename, &u.Label, &u.ObjectKey, &u.UploadedBy, &u.CreatedAt)
	if err == nil {
		u.Commit = u.SHA256[:40]
	}
	return u, err
}

// RecordUpload stores the record of an archive already placed in object
// storage. Uploading the same archive again for the asset returns the
// existing record (created is false).
func (s *Store) RecordUpload(ctx context.Context, u Upload, actor string) (Upload, bool, error) {
	if len(u.SHA256) != 64 || u.Size <= 0 || u.AssetID == uuid.Nil || u.ObjectKey == "" {
		return Upload{}, false, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Upload{}, false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.uploads(`+uploadColumns+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()) ON CONFLICT(asset_id,sha256) DO NOTHING`,
		uuid.New(), u.AssetID, u.SHA256, u.Size, u.Filename, u.Label, u.ObjectKey, actor)
	if err != nil {
		return Upload{}, false, err
	}
	created := tag.RowsAffected() == 1
	stored, err := scanUpload(tx.QueryRow(ctx, `SELECT `+uploadColumns+` FROM `+s.schema+`.uploads WHERE asset_id=$1 AND sha256=$2`, u.AssetID, u.SHA256))
	if err != nil {
		return Upload{}, false, err
	}
	if created {
		details, _ := json.Marshal(map[string]any{"asset_id": u.AssetID, "sha256": u.SHA256, "size": u.Size})
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('upload.created',$1,$2)`, stored.ID, details); err != nil {
			return Upload{}, false, err
		}
	}
	return stored, created, tx.Commit(ctx)
}

// UploadObjectKey finds where the archive of an asset's revision is stored.
func (s *Store) UploadObjectKey(ctx context.Context, asset uuid.UUID, commit string) (string, error) {
	var key string
	err := s.pool.QueryRow(ctx, `SELECT object_key FROM `+s.schema+`.uploads WHERE asset_id=$1 AND left(sha256,40)=$2`, asset, commit).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return key, err
}

// Uploads lists an asset's archives, newest first.
func (s *Store) Uploads(ctx context.Context, asset uuid.UUID, limit int) ([]Upload, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+uploadColumns+` FROM `+s.schema+`.uploads WHERE asset_id=$1 ORDER BY created_at DESC,id LIMIT $2`, asset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Upload{}
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUpload removes one uploaded archive: its record, and its object
// unless another upload still uses the same bytes. Assessments that scanned it
// keep their results; only the archive is gone, so it cannot be scanned again.
// A queued or running assessment of the archive (ErrBusy) or a legal hold on
// the asset (ErrConflict) refuses the delete.
func (s *Store) DeleteUpload(ctx context.Context, asset, upload, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var u Upload
	var hold bool
	err = tx.QueryRow(ctx, `SELECT u.id,u.asset_id,u.sha256,u.object_key,a.legal_hold FROM `+s.schema+`.uploads u JOIN `+s.schema+`.assets a ON a.id=u.asset_id WHERE u.id=$1 AND u.asset_id=$2 FOR UPDATE OF u,a`, upload, asset).Scan(&u.ID, &u.AssetID, &u.SHA256, &u.ObjectKey, &hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if hold {
		return ErrConflict
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.assessments WHERE asset_id=$1 AND status IN ('queued','running') AND request->'target'->>'commit'=$2)`, asset, u.SHA256[:40]).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrBusy
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.uploads WHERE id=$1`, upload); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "asset_id": asset, "sha256": u.SHA256})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('upload.deleted',$1,$2)`, upload, details); err != nil {
		return err
	}
	unused, err := s.unreferenced(ctx, tx, `SELECT 1 FROM `+s.schema+`.uploads WHERE object_key=$1`, []string{u.ObjectKey})
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// A failure here is left to the orphan sweep, which removes unreferenced
	// uploads after a day.
	s.deleteObjects(ctx, unused)
	return nil
}

// DeleteUploadedAsset removes an `uploaded` asset with its archives. An asset
// that has assessments, findings or settings keeps its history and answers
// ErrConflict; delete its uploads, or let retention do it, instead.
func (s *Store) DeleteUploadedAsset(ctx context.Context, asset, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var kind string
	var hold bool
	err = tx.QueryRow(ctx, `SELECT type,legal_hold FROM `+s.schema+`.assets WHERE id=$1 FOR UPDATE`, asset).Scan(&kind, &hold)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "uploaded") {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if hold {
		return ErrConflict
	}
	rows, err := tx.Query(ctx, `DELETE FROM `+s.schema+`.uploads WHERE asset_id=$1 RETURNING object_key`, asset)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.assets WHERE id=$1`, asset); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23503" {
			return ErrConflict
		}
		return err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "uploads": len(keys)})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset.deleted',$1,$2)`, asset, details); err != nil {
		return err
	}
	unused, err := s.unreferenced(ctx, tx, `SELECT 1 FROM `+s.schema+`.uploads WHERE object_key=$1`, keys)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// A failure here is left to the orphan sweep, which removes unreferenced
	// uploads after a day.
	s.deleteObjects(ctx, unused)
	return nil
}
