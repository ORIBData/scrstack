package connections

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
)

var ErrConflict = errors.New("connection changed concurrently; retry")
var ErrInvalidChange = errors.New("invalid connection change")

// Change modifies one connection under an optimistic lock. Assets and audit
// history are retained. Eligibility is withdrawn until a fresh discovery.
func (s *Store) Change(ctx context.Context, id uuid.UUID, scope *Scope, enabled *bool, credential json.RawMessage) (Connection, error) {
	name, err := s.NameByID(ctx, id)
	if err != nil {
		return Connection{}, err
	}
	c, secret, err := s.Get(ctx, name)
	if err != nil {
		return c, err
	}
	if scope != nil {
		if err := scope.Validate(); err != nil {
			return c, fmt.Errorf("%w: %s", ErrInvalidChange, err)
		}
		c.Scope = *scope
	}
	if enabled != nil {
		c.Enabled = *enabled
	}
	action := "connection.changed"
	if len(credential) > 0 {
		secret = credential
		action = "connection.credential_rotated"
	}
	if err := ValidateInput(c, secret); err != nil {
		return c, fmt.Errorf("%w: %s", ErrInvalidChange, err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return c, err
	}
	encrypted := s.aead.Seal(nonce, nonce, secret, []byte(c.Name+":"+c.Provider))
	scopeJSON, _ := json.Marshal(c.Scope)
	state := "pending"
	if !c.Enabled {
		state = "disabled"
	}
	status, _ := json.Marshal(map[string]string{"state": state})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return c, errors.New("connection change transaction failed")
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.connections SET scope=$2,enabled=$3,credential_ciphertext=$4,status=$5,updated_at=clock_timestamp(),revision=revision+1,configuration_revision=configuration_revision+1 WHERE id=$1 AND revision=$6`, id, scopeJSON, c.Enabled, encrypted, status, c.Revision)
	if err != nil {
		return c, errors.New("connection change failed")
	}
	if tag.RowsAffected() != 1 {
		return c, ErrConflict
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assets SET flags=flags || '{"in_scope":false}'::jsonb WHERE connection_id=$1`, id); err != nil {
		return c, errors.New("asset scope invalidation failed")
	}
	details, _ := json.Marshal(map[string]any{"enabled": c.Enabled, "scope_changed": scope != nil})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES ($1,$2,$3)`, action, id, auditDetails(ctx, details)); err != nil {
		return c, errors.New("connection change audit failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return c, errors.New("connection change commit failed")
	}
	return s.PublicByID(ctx, id)
}
