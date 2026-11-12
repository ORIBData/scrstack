package connections

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrTokenInput = errors.New("invalid token request")

type Token struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	Networks   []string   `json:"ip_allow_list"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func (t Token) Allows(scope string) bool {
	for _, s := range t.Scopes {
		if s == "admin" || s == scope {
			return true
		}
	}
	return false
}
func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "scrs_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// SyncBootstrap serializes startup across replicas. Only the winning initial
// process receives a generated secret; explicit environment rotation replaces its hash.
func (s *Store) SyncBootstrap(ctx context.Context, supplied string) (string, error) {
	if supplied != "" && (len(supplied) < 32 || len(supplied) > 512 || strings.ContainsAny(supplied, " \t\r\n")) {
		return "", ErrTokenInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".bootstrap_token"); err != nil {
		return "", err
	}
	var existing []byte
	err = tx.QueryRow(ctx, `SELECT secret_hash FROM `+s.schema+`.api_tokens WHERE name='bootstrap'`).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	generated := ""
	if supplied == "" {
		if err == nil {
			return "", tx.Commit(ctx)
		}
		supplied, err = newSecret()
		if err != nil {
			return "", err
		}
		generated = supplied
	}
	hash := sha256.Sum256([]byte(supplied))
	if subtle.ConstantTimeCompare(existing, hash[:]) == 1 {
		return "", tx.Commit(ctx)
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.api_tokens(id,name,prefix,secret_hash,scopes,ip_allow_list) VALUES($1,'bootstrap',$2,$3,'["admin"]','[]') ON CONFLICT(name) DO UPDATE SET prefix=EXCLUDED.prefix,secret_hash=EXCLUDED.secret_hash,revoked_at=NULL RETURNING id`, uuid.New(), supplied[:8], hash[:]).Scan(&id)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id) VALUES('token.bootstrap_rotated',$1)`, id); err != nil {
		return "", err
	}
	return generated, tx.Commit(ctx)
}

func (s *Store) CreateToken(ctx context.Context, input Token, actor uuid.UUID) (Token, string, error) {
	input.Name = strings.TrimSpace(input.Name)
	if len(input.Name) < 1 || len(input.Name) > 100 || input.Name == "bootstrap" || len(input.Scopes) == 0 || len(input.Scopes) > 5 || len(input.Networks) > 32 {
		return Token{}, "", ErrTokenInput
	}
	seen := map[string]bool{}
	for _, scope := range input.Scopes {
		if seen[scope] {
			return Token{}, "", ErrTokenInput
		}
		seen[scope] = true
		switch scope {
		case "admin", "read", "write", "trigger", "ingest:relay":
		default:
			return Token{}, "", ErrTokenInput
		}
	}
	for _, network := range input.Networks {
		if _, err := netip.ParsePrefix(network); err != nil {
			return Token{}, "", ErrTokenInput
		}
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now()) {
		return Token{}, "", ErrTokenInput
	}
	secret, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	hash := sha256.Sum256([]byte(secret))
	input.ID = uuid.New()
	input.Prefix = secret[:12]
	input.LastUsedAt = nil
	input.RevokedAt = nil
	scopes, _ := json.Marshal(input.Scopes)
	if input.Networks == nil {
		input.Networks = []string{}
	}
	networks, _ := json.Marshal(input.Networks)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Token{}, "", err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.api_tokens(id,name,prefix,secret_hash,scopes,ip_allow_list,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(name) DO NOTHING RETURNING created_at`, input.ID, input.Name, input.Prefix, hash[:], scopes, networks, input.ExpiresAt).Scan(&input.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Token{}, "", ErrConflict
	}
	if err != nil {
		return Token{}, "", err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "scopes": input.Scopes})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('token.created',$1,$2)`, input.ID, details); err != nil {
		return Token{}, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return Token{}, "", err
	}
	return input, secret, nil
}

// PostgreSQL remains authoritative on every request so revocation cannot be
// bypassed by a stale process or Redis cache entry. Do not cache positive results.
func (s *Store) Authenticate(ctx context.Context, secret string, remote netip.Addr) (Token, error) {
	if len(secret) < 32 || len(secret) > 512 {
		return Token{}, ErrUnauthorized
	}
	hash := sha256.Sum256([]byte(secret))
	var stored []byte
	var t Token
	var scopes, networks []byte
	err := s.pool.QueryRow(ctx, `SELECT id,name,prefix,secret_hash,scopes,ip_allow_list,expires_at FROM `+s.schema+`.api_tokens WHERE secret_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`, hash[:]).Scan(&t.ID, &t.Name, &t.Prefix, &stored, &scopes, &networks, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrUnauthorized
	}
	if err != nil {
		return t, errors.New("token store unavailable")
	}
	if subtle.ConstantTimeCompare(hash[:], stored) != 1 || json.Unmarshal(scopes, &t.Scopes) != nil || json.Unmarshal(networks, &t.Networks) != nil {
		return t, ErrUnauthorized
	}
	allowed := len(t.Networks) == 0
	for _, network := range t.Networks {
		prefix, err := netip.ParsePrefix(network)
		if err == nil && prefix.Contains(remote.Unmap()) {
			allowed = true
		}
	}
	if !allowed {
		return Token{}, ErrUnauthorized
	}
	// Throttle telemetry writes without delaying revocation checks.
	if _, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.api_tokens SET last_used_at=clock_timestamp() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<clock_timestamp()-interval '1 minute')`, t.ID); err != nil {
		return Token{}, errors.New("token telemetry unavailable")
	}
	return t, nil
}
func (s *Store) Tokens(ctx context.Context, after uuid.UUID, limit int) ([]Token, error) {
	if limit < 1 || limit > 501 {
		return nil, ErrTokenInput
	}
	rows, err := s.pool.Query(ctx, `SELECT id,name,prefix,scopes,ip_allow_list,expires_at,created_at,last_used_at,revoked_at FROM `+s.schema+`.api_tokens WHERE id>$1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Token{}
	for rows.Next() {
		var t Token
		var scopes, networks []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &scopes, &networks, &t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(scopes, &t.Scopes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(networks, &t.Networks); err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	return result, rows.Err()
}
func (s *Store) RevokeToken(ctx context.Context, id, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.api_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1 AND name<>'bootstrap'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrTokenInput
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('token.revoked',$1,$2)`, id, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
