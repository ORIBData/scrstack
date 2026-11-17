package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LLM providers (QA module): admin-managed model endpoints used to draft
// tests. The API validates settings with the llm package and seals the API
// key with SCRS_MASTER_KEY before it reaches the store.

// LLMProvider is a provider's settings; the key is never read back.
type LLMProvider struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`
	BaseURL       string     `json:"base_url"`
	Model         string     `json:"model"`
	MaxTokens     int        `json:"max_tokens"`
	Temperature   *float64   `json:"temperature"`
	Enabled       bool       `json:"enabled"`
	HasKey        bool       `json:"has_api_key"`
	Revision      int64      `json:"revision"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastTestAt    *time.Time `json:"last_test_at"`
	LastTestError string     `json:"last_test_error"`
	// Locality is "local" when the provider is a model server the operator
	// runs (its host is in SCRS_LLM_PRIVATE_HOSTS) and "hosted" otherwise. It
	// is computed when the provider is shown, not stored.
	Locality string `json:"locality"`
	// Managed is true for a provider declared in the environment
	// (SCRS_LLM_PROVIDERS): the environment owns its settings and key, so the
	// API only lets an administrator enable or disable it.
	Managed bool `json:"managed_by_environment"`
	// SourceAck* record the administrator's acknowledgement that source code
	// may be sent to this (hosted) provider. It is cleared when the kind or
	// base URL changes. SourceAllowed is computed: whether the provider may
	// receive source code now, which also needs the platform switch.
	SourceAckBy   string     `json:"source_ack_by"`
	SourceAckAt   *time.Time `json:"source_ack_at"`
	SourceAckNote string     `json:"source_ack_note"`
	SourceAllowed bool       `json:"source_allowed"`
}

// LLMAAD binds a sealed key to its provider.
func LLMAAD(id uuid.UUID) []byte { return []byte("llm:" + id.String()) }

var providerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,62}$`)

const llmColumns = `id,name,kind,base_url,model,max_tokens,temperature,enabled,credential IS NOT NULL AND length(credential)>0,revision,created_at,updated_at,last_test_at,last_test_error,managed,source_ack_by,source_ack_at,source_ack_note`

func scanProvider(row pgx.Row, extra ...any) (LLMProvider, error) {
	var p LLMProvider
	targets := append([]any{&p.ID, &p.Name, &p.Kind, &p.BaseURL, &p.Model, &p.MaxTokens, &p.Temperature, &p.Enabled, &p.HasKey, &p.Revision, &p.CreatedAt, &p.UpdatedAt, &p.LastTestAt, &p.LastTestError, &p.Managed, &p.SourceAckBy, &p.SourceAckAt, &p.SourceAckNote}, extra...)
	if err := row.Scan(targets...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return p, ErrNotFound
		}
		return p, err
	}
	return p, nil
}

func providerAudit(ctx context.Context, tx pgx.Tx, schema, action string, p LLMProvider, actor uuid.UUID, keyChanged bool) error {
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": p.Name, "kind": p.Kind, "base_url": p.BaseURL, "model": p.Model, "enabled": p.Enabled, "key_changed": keyChanged})
	_, err := tx.Exec(ctx, `INSERT INTO `+schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, p.ID, details)
	return err
}

// CreateLLMProvider stores a provider; seal encrypts the key once the ID is
// known. Settings must already be validated by the llm package.
func (s *Store) CreateLLMProvider(ctx context.Context, p LLMProvider, actor uuid.UUID, seal func(uuid.UUID) ([]byte, error)) (LLMProvider, error) {
	if !providerName.MatchString(p.Name) {
		return p, ErrInput
	}
	p.ID = uuid.New()
	sealed, err := seal(p.ID)
	if err != nil {
		return p, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	created, err := scanProvider(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.llm_providers(id,name,kind,base_url,model,max_tokens,temperature,enabled,credential) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(name) DO NOTHING RETURNING `+llmColumns, p.ID, p.Name, p.Kind, p.BaseURL, p.Model, p.MaxTokens, p.Temperature, p.Enabled, sealed))
	if errors.Is(err, ErrNotFound) {
		return p, ErrConflict
	}
	if err != nil {
		return p, err
	}
	if err := providerAudit(ctx, tx, s.schema, "llm_provider.created", created, actor, len(sealed) > 0); err != nil {
		return p, err
	}
	return created, tx.Commit(ctx)
}

// LLMProviders lists providers by name.
func (s *Store) LLMProviders(ctx context.Context) ([]LLMProvider, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+llmColumns+` FROM `+s.schema+`.llm_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LLMProvider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// LLMProviderByID returns one provider.
func (s *Store) LLMProviderByID(ctx context.Context, id uuid.UUID) (LLMProvider, error) {
	return scanProvider(s.pool.QueryRow(ctx, `SELECT `+llmColumns+` FROM `+s.schema+`.llm_providers WHERE id=$1`, id))
}

// LLMProviderCredential returns a provider with its sealed key.
func (s *Store) LLMProviderCredential(ctx context.Context, id uuid.UUID) (LLMProvider, []byte, error) {
	var sealed []byte
	p, err := scanProvider(s.pool.QueryRow(ctx, `SELECT `+llmColumns+`,COALESCE(credential,''::bytea) FROM `+s.schema+`.llm_providers WHERE id=$1`, id), &sealed)
	return p, sealed, err
}

// UpdateLLMProvider replaces a provider's settings at the expected revision;
// a nil sealed key keeps the stored one.
func (s *Store) UpdateLLMProvider(ctx context.Context, p LLMProvider, expected int64, sealed []byte, actor uuid.UUID) (LLMProvider, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	updated, err := scanProvider(tx.QueryRow(ctx, `UPDATE `+s.schema+`.llm_providers SET kind=$3,base_url=$4,model=$5,max_tokens=$6,temperature=$7,enabled=$8,credential=COALESCE($9,credential),revision=revision+1,updated_at=clock_timestamp(),last_test_at=NULL,last_test_error='',source_ack_at=CASE WHEN kind=$3 AND base_url=$4 THEN source_ack_at END,source_ack_by=CASE WHEN kind=$3 AND base_url=$4 THEN source_ack_by ELSE '' END,source_ack_note=CASE WHEN kind=$3 AND base_url=$4 THEN source_ack_note ELSE '' END WHERE id=$1 AND revision=$2 RETURNING `+llmColumns, p.ID, expected, p.Kind, p.BaseURL, p.Model, p.MaxTokens, p.Temperature, p.Enabled, sealed))
	if errors.Is(err, ErrNotFound) {
		if _, getErr := s.LLMProviderByID(ctx, p.ID); getErr != nil {
			return p, getErr
		}
		return p, ErrConflict
	}
	if err != nil {
		return p, err
	}
	if err := providerAudit(ctx, tx, s.schema, "llm_provider.changed", updated, actor, sealed != nil); err != nil {
		return p, err
	}
	return updated, tx.Commit(ctx)
}

// DeleteLLMProvider removes a provider; QA profiles using it lose their
// provider, generations keep its name.
func (s *Store) DeleteLLMProvider(ctx context.Context, id, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	p, err := scanProvider(tx.QueryRow(ctx, `DELETE FROM `+s.schema+`.llm_providers WHERE id=$1 RETURNING `+llmColumns, id))
	if err != nil {
		return err
	}
	if err := providerAudit(ctx, tx, s.schema, "llm_provider.deleted", p, actor, false); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordLLMTest stores the outcome of a provider check.
func (s *Store) RecordLLMTest(ctx context.Context, id uuid.UUID, failure string) error {
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.llm_providers SET last_test_at=clock_timestamp(),last_test_error=$2 WHERE id=$1`, id, clip(failure, 1000))
	return err
}

// ErrManaged means the provider is declared in the environment and cannot be
// changed through the API.
var ErrManaged = errors.New("this provider is managed by the environment (SCRS_LLM_PROVIDERS); change its SCRS_LLM_PROVIDER_* variables and redeploy")

// SetLLMSourceAck records (allow) or removes the acknowledgement that source
// code may be sent to a hosted provider. A note is required to record one:
// it is the audit trail for the decision.
func (s *Store) SetLLMSourceAck(ctx context.Context, id uuid.UUID, allow bool, note, by string, actor uuid.UUID) (LLMProvider, error) {
	note = strings.TrimSpace(note)
	if allow && (len(note) < 10 || len(note) > 500) {
		return LLMProvider{}, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LLMProvider{}, err
	}
	defer tx.Rollback(ctx)
	var p LLMProvider
	if allow {
		p, err = scanProvider(tx.QueryRow(ctx, `UPDATE `+s.schema+`.llm_providers SET source_ack_by=$2,source_ack_at=clock_timestamp(),source_ack_note=$3,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+llmColumns, id, clip(by, 100), note))
	} else {
		p, err = scanProvider(tx.QueryRow(ctx, `UPDATE `+s.schema+`.llm_providers SET source_ack_by='',source_ack_at=NULL,source_ack_note='',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+llmColumns, id))
	}
	if err != nil {
		return p, err
	}
	action := "llm_provider.source_revoked"
	if allow {
		action = "llm_provider.source_allowed"
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": p.Name, "base_url": p.BaseURL, "note": note})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, p.ID, details); err != nil {
		return p, err
	}
	return p, tx.Commit(ctx)
}

// BootstrapLLMProvider creates or updates a provider declared in the
// environment and returns what it did: "created", "updated" or "unchanged".
// seal encrypts the declared key once the ID is known; sameKey says whether
// the stored sealed key already holds the declared one, so a restart that
// changes nothing writes nothing. A provider with that name that was created
// through the API is left alone (ErrConflict). Whether the provider is
// enabled is not touched on update, so an administrator can switch it off.
func (s *Store) BootstrapLLMProvider(ctx context.Context, want LLMProvider, allowSource bool, seal func(uuid.UUID) ([]byte, error), sameKey func(id uuid.UUID, sealed []byte) bool) (LLMProvider, string, error) {
	if !providerName.MatchString(want.Name) {
		return want, "", ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return want, "", err
	}
	defer tx.Rollback(ctx)
	var sealed []byte
	have, err := scanProvider(tx.QueryRow(ctx, `SELECT `+llmColumns+`,COALESCE(credential,''::bytea) FROM `+s.schema+`.llm_providers WHERE name=$1 FOR UPDATE`, want.Name), &sealed)
	const envNote = "declared in the environment (SCRS_LLM_PROVIDER_*_ALLOW_SOURCE=true)"
	if errors.Is(err, ErrNotFound) {
		id := uuid.New()
		newKey, err := seal(id)
		if err != nil {
			return want, "", err
		}
		by, note := "", ""
		var at *time.Time
		if allowSource {
			now := time.Now().UTC()
			by, note, at = "environment", envNote, &now
		}
		created, err := scanProvider(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.llm_providers(id,name,kind,base_url,model,max_tokens,temperature,enabled,credential,managed,source_ack_by,source_ack_at,source_ack_note) VALUES($1,$2,$3,$4,$5,$6,$7,true,$8,true,$9,$10,$11) RETURNING `+llmColumns, id, want.Name, want.Kind, want.BaseURL, want.Model, want.MaxTokens, want.Temperature, newKey, by, at, note))
		if err != nil {
			return want, "", err
		}
		if err := providerAudit(ctx, tx, s.schema, "llm_provider.created", created, uuid.Nil, len(newKey) > 0); err != nil {
			return want, "", err
		}
		return created, "created", tx.Commit(ctx)
	}
	if err != nil {
		return want, "", err
	}
	if !have.Managed {
		return have, "", ErrConflict
	}
	endpointChanged := have.Kind != want.Kind || have.BaseURL != want.BaseURL
	by, at, note := have.SourceAckBy, have.SourceAckAt, have.SourceAckNote
	if endpointChanged {
		by, at, note = "", nil, ""
	}
	if allowSource && at == nil {
		now := time.Now().UTC()
		by, at, note = "environment", &now, envNote
	}
	if !allowSource && by == "environment" {
		by, at, note = "", nil, ""
	}
	sameTemp := (have.Temperature == nil) == (want.Temperature == nil) && (have.Temperature == nil || *have.Temperature == *want.Temperature)
	keyOK := sameKey(have.ID, sealed)
	if !endpointChanged && have.Model == want.Model && have.MaxTokens == want.MaxTokens && sameTemp && keyOK && by == have.SourceAckBy && (at == nil) == (have.SourceAckAt == nil) {
		return have, "unchanged", nil
	}
	var newKey []byte
	if !keyOK {
		if newKey, err = seal(have.ID); err != nil {
			return want, "", err
		}
	}
	updated, err := scanProvider(tx.QueryRow(ctx, `UPDATE `+s.schema+`.llm_providers SET kind=$2,base_url=$3,model=$4,max_tokens=$5,temperature=$6,credential=COALESCE($7,credential),source_ack_by=$8,source_ack_at=$9,source_ack_note=$10,revision=revision+1,updated_at=clock_timestamp(),last_test_at=NULL,last_test_error='' WHERE id=$1 RETURNING `+llmColumns, have.ID, want.Kind, want.BaseURL, want.Model, want.MaxTokens, want.Temperature, newKey, by, at, note))
	if err != nil {
		return want, "", err
	}
	if err := providerAudit(ctx, tx, s.schema, "llm_provider.changed", updated, uuid.Nil, newKey != nil); err != nil {
		return want, "", err
	}
	return updated, "updated", tx.Commit(ctx)
}
