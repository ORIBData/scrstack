package connections

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UploadProvider is the built-in provider behind uploaded source archives.
// Its single connection exists so that uploaded assets go through the same
// job, scope and audit path as discovered ones; it has no credential, is not
// listed by GET /connections and is never discovered or edited.
const UploadProvider = "upload"

// uploadConnectionName is reserved for that connection.
const uploadConnectionName = "scrs-uploads"

// UploadAssetType is the asset type of an uploaded archive.
const UploadAssetType = "uploaded"

var uploadNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// ErrUploadName means the upload name is not a valid asset name.
var ErrUploadName = errors.New("upload name must be 1 to 100 lowercase letters, digits, dots, underscores or hyphens")

// ErrReservedConnection means another connection already uses the name of the
// built-in upload connection.
var ErrReservedConnection = errors.New("connection name scrs-uploads is reserved for uploads")

// UploadAsset returns the `uploaded` asset named upload/<name>, creating it
// (and the built-in connection) on first use. created tells which happened.
func (s *Store) UploadAsset(ctx context.Context, name string, actor uuid.UUID) (Asset, bool, error) {
	if !uploadNamePattern.MatchString(name) {
		return Asset{}, false, ErrUploadName
	}
	locator := "upload/" + name
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Asset{}, false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".upload_assets"); err != nil {
		return Asset{}, false, err
	}
	var connection uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM `+s.schema+`.connections WHERE name=$1 AND provider=$2`, uploadConnectionName, UploadProvider).Scan(&connection)
	if errors.Is(err, pgx.ErrNoRows) {
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return Asset{}, false, err
		}
		sealed := s.aead.Seal(nonce, nonce, []byte(`{}`), []byte(uploadConnectionName+":"+UploadProvider))
		scope, _ := json.Marshal(Scope{Include: []string{"upload/*"}})
		connection = uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.connections(id,provider,name,config,scope,credential_ciphertext,secret_key_id,status) VALUES($1,$2,$3,'{}',$4,$5,'v1','{"state":"ok"}')`, connection, UploadProvider, uploadConnectionName, scope, sealed); err != nil {
			return Asset{}, false, ErrReservedConnection
		}
	} else if err != nil {
		return Asset{}, false, err
	}
	flags, _ := json.Marshal(map[string]bool{"discovered": false, "manual": false, "upload": true, "accessible": true, "in_scope": true})
	id := uuid.New()
	tag, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.assets(id,type,locator,connection_id,flags,metadata) VALUES($1,$2,$3,$4,$5,'{}') ON CONFLICT(connection_id,type,locator) DO NOTHING`, id, UploadAssetType, locator, connection, flags)
	if err != nil {
		return Asset{}, false, err
	}
	created := tag.RowsAffected() == 1
	asset, err := scanAsset(tx.QueryRow(ctx, `SELECT `+assetColumns+` FROM `+s.schema+`.assets WHERE connection_id=$1 AND type=$2 AND locator=$3`, connection, UploadAssetType, locator))
	if err != nil {
		return Asset{}, false, err
	}
	if created {
		details, _ := json.Marshal(map[string]any{"type": UploadAssetType, "locator": locator})
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset.created',$1,$2)`, asset.ID, auditDetails(WithActor(ctx, actor), details)); err != nil {
			return Asset{}, false, err
		}
	}
	return asset, created, tx.Commit(ctx)
}
