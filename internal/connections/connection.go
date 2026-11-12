package connections

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Connection struct {
	ID        uuid.UUID       `json:"id"`
	Provider  string          `json:"provider"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	Scope     Scope           `json:"scope"`
	Status    json.RawMessage `json:"status"`
	UpdatedAt time.Time       `json:"-"`
	Revision  int64           `json:"-"`
	Enabled   bool            `json:"enabled"`
}

type Scope struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude,omitempty"`
}

func (s Scope) Validate() error {
	if len(s.Include)+len(s.Exclude) > 100 {
		return errors.New("connection scope exceeds 100 patterns")
	}
	for _, pattern := range append(append([]string{}, s.Include...), s.Exclude...) {
		if pattern == "" || len(pattern) > 256 || strings.Contains(pattern, "\\") {
			return errors.New("scope patterns must be nonempty slash-separated locators")
		}
		if _, err := path.Match(strings.ReplaceAll(pattern, "**", "*"), "test"); err != nil {
			return errors.New("invalid scope glob pattern")
		}
	}
	return nil
}

func (s Scope) Matches(locator string) bool {
	selected := false
	for _, pattern := range s.Include {
		if matchPattern(pattern, locator) {
			selected = true
			break
		}
	}
	if !selected {
		return false
	}
	for _, pattern := range s.Exclude {
		if matchPattern(pattern, locator) {
			return false
		}
	}
	return true
}

func matchPattern(pattern, locator string) bool {
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(locator, strings.TrimSuffix(pattern, "**"))
	}
	matched, _ := path.Match(pattern, locator)
	return matched
}

func (s Scope) matchesResource(resource Resource) bool {
	if resource.Type != "github_repo" {
		return s.Matches(resource.Locator)
	}
	lower := Scope{Include: make([]string, len(s.Include)), Exclude: make([]string, len(s.Exclude))}
	for i, pattern := range s.Include {
		lower.Include[i] = strings.ToLower(pattern)
	}
	for i, pattern := range s.Exclude {
		lower.Exclude[i] = strings.ToLower(pattern)
	}
	return lower.Matches(strings.ToLower(resource.Locator))
}

type Resource struct {
	Type     string          `json:"type"`
	Locator  string          `json:"locator"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

type Adapter interface {
	List(context.Context, Connection, json.RawMessage) ([]Resource, error)
}

type Store struct {
	pool   *pgxpool.Pool
	schema string
	aead   cipher.AEAD
}

func Open(ctx context.Context, databaseURL, schema, masterKey string) (*Store, error) {
	key, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("SCRS_MASTER_KEY must be base64 of exactly 32 random bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, errors.New("connection store PostgreSQL configuration failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("connection store PostgreSQL unavailable")
	}
	return &Store{pool: pool, schema: pgx.Identifier{schema}.Sanitize(), aead: aead}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Put writes nonsecret config and scope as JSONB, and the credential as AES-GCM.
// An existing named connection is preserved unless replace is explicitly true.
func (s *Store) Put(ctx context.Context, c Connection, credential json.RawMessage, replace bool) (bool, error) {
	if c.Provider != "github" && c.Provider != "dockerhub" && c.Provider != "gar" {
		return false, errors.New("unsupported provider")
	}
	if c.Name == "" || !json.Valid(c.Config) || !json.Valid(credential) || len(credential) == 0 {
		return false, errors.New("connection requires a name, config and credential")
	}
	if err := c.Scope.Validate(); err != nil {
		return false, err
	}
	if err := ValidateInput(c, credential); err != nil {
		return false, err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	scopeJSON, _ := json.Marshal(c.Scope)
	aad := []byte(c.Name + ":" + c.Provider)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return false, err
	}
	ciphertext := s.aead.Seal(nonce, nonce, credential, aad)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, errors.New("connection save transaction failed")
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	query := `INSERT INTO ` + s.schema + `.connections
		(id, provider, name, config, scope, credential_ciphertext, secret_key_id)
		VALUES ($1,$2,$3,$4,$5,$6,'v1') ON CONFLICT (name) DO `
	if replace {
		query += `UPDATE SET config=EXCLUDED.config,
			scope=EXCLUDED.scope, credential_ciphertext=EXCLUDED.credential_ciphertext,
			status=CASE WHEN connections.enabled THEN '{"state":"pending"}'::jsonb ELSE '{"state":"disabled"}'::jsonb END, updated_at=clock_timestamp(), revision=connections.revision+1 WHERE connections.provider=EXCLUDED.provider RETURNING id`
	} else {
		query += `NOTHING RETURNING id`
	}
	err = tx.QueryRow(ctx, query, c.ID, c.Provider, c.Name, c.Config, scopeJSON, ciphertext).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("connection save failed")
	}
	if replace {
		if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assets SET flags=flags || '{"in_scope":false}'::jsonb WHERE connection_id=$1`, id); err != nil {
			return false, errors.New("asset scope invalidation failed")
		}
	}
	details, _ := json.Marshal(map[string]any{"name": c.Name, "provider": c.Provider})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES ('connection.saved',$1,$2)`, id, auditDetails(ctx, details)); err != nil {
		return false, errors.New("connection audit failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return false, errors.New("connection save commit failed")
	}
	return true, nil
}

func (s *Store) NameByID(ctx context.Context, id uuid.UUID) (string, error) {
	var name string
	if err := s.pool.QueryRow(ctx, `SELECT name FROM `+s.schema+`.connections WHERE id=$1`, id).Scan(&name); err != nil {
		return "", errors.New("connection not found")
	}
	return name, nil
}

func (s *Store) PublicByID(ctx context.Context, id uuid.UUID) (Connection, error) {
	var c Connection
	var rawScope []byte
	if err := s.pool.QueryRow(ctx, `SELECT id,provider,name,config,scope,status,enabled FROM `+s.schema+`.connections WHERE id=$1`, id).
		Scan(&c.ID, &c.Provider, &c.Name, &c.Config, &rawScope, &c.Status, &c.Enabled); err != nil {
		return c, errors.New("connection not found")
	}
	if err := json.Unmarshal(rawScope, &c.Scope); err != nil {
		return c, errors.New("connection scope invalid")
	}
	return c, nil
}

func (s *Store) PublicByName(ctx context.Context, name string) (Connection, error) {
	var id uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT id FROM `+s.schema+`.connections WHERE name=$1`, name).Scan(&id); err != nil {
		return Connection{}, errors.New("connection not found")
	}
	return s.PublicByID(ctx, id)
}

func (s *Store) Has(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+s.schema+`.connections WHERE name=$1)`, name).Scan(&exists)
	return exists, err
}

func (s *Store) List(ctx context.Context) ([]Connection, error) {
	return s.listConnections(ctx, "", 10001)
}

func (s *Store) ListPage(ctx context.Context, after string, limit int) ([]Connection, error) {
	if limit < 1 || limit > 501 || len(after) > 100 {
		return nil, errors.New("invalid connection page")
	}
	return s.listConnections(ctx, after, limit)
}
func (s *Store) listConnections(ctx context.Context, after string, limit int) ([]Connection, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, provider, name, config, scope, status, enabled FROM `+s.schema+`.connections WHERE name>$1 ORDER BY name LIMIT $2`, after, limit)
	if err != nil {
		return nil, errors.New("connection list failed")
	}
	defer rows.Close()
	result := []Connection{}
	for rows.Next() {
		var c Connection
		var rawScope []byte
		if err := rows.Scan(&c.ID, &c.Provider, &c.Name, &c.Config, &rawScope, &c.Status, &c.Enabled); err != nil {
			return nil, errors.New("connection list scan failed")
		}
		if err := json.Unmarshal(rawScope, &c.Scope); err != nil {
			return nil, errors.New("connection scope invalid in database")
		}
		result = append(result, c)
	}
	if len(result) > 10000 {
		return nil, errors.New("too many connections; use pagination")
	}
	return result, rows.Err()
}

func (s *Store) Get(ctx context.Context, name string) (Connection, json.RawMessage, error) {
	var c Connection
	var rawScope, ciphertext []byte
	err := s.pool.QueryRow(ctx, `SELECT id, provider, name, config, scope, status, credential_ciphertext, updated_at, enabled, revision FROM `+s.schema+`.connections WHERE name=$1`, name).
		Scan(&c.ID, &c.Provider, &c.Name, &c.Config, &rawScope, &c.Status, &ciphertext, &c.UpdatedAt, &c.Enabled, &c.Revision)
	if err != nil {
		return c, nil, errors.New("connection not found")
	}
	if err := json.Unmarshal(rawScope, &c.Scope); err != nil {
		return c, nil, errors.New("connection scope invalid")
	}
	if len(ciphertext) < s.aead.NonceSize() {
		return c, nil, errors.New("connection credential invalid")
	}
	plain, err := s.aead.Open(nil, ciphertext[:s.aead.NonceSize()], ciphertext[s.aead.NonceSize():], []byte(c.Name+":"+c.Provider))
	if err != nil {
		return c, nil, errors.New("connection credential decryption failed; check SCRS_MASTER_KEY")
	}
	return c, json.RawMessage(plain), nil
}

type DiscoveryResult struct {
	Connection string `json:"connection"`
	Discovered int    `json:"discovered"`
	InScope    int    `json:"in_scope"`
}

type Asset struct {
	ID           uuid.UUID       `json:"id"`
	Type         string          `json:"type"`
	Locator      string          `json:"locator"`
	ConnectionID uuid.UUID       `json:"connection_id"`
	Flags        json.RawMessage `json:"flags"`
}

func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,type,locator,connection_id,flags FROM `+s.schema+`.assets ORDER BY locator LIMIT 10000`)
	if err != nil {
		return nil, errors.New("asset list failed")
	}
	defer rows.Close()
	assets := []Asset{}
	for rows.Next() {
		var asset Asset
		if err := rows.Scan(&asset.ID, &asset.Type, &asset.Locator, &asset.ConnectionID, &asset.Flags); err != nil {
			return nil, errors.New("asset list scan failed")
		}
		assets = append(assets, asset)
	}
	return assets, rows.Err()
}

func (s *Store) ListAssetsPage(ctx context.Context, limit int, afterLocator string, afterID uuid.UUID) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,type,locator,connection_id,flags FROM `+s.schema+`.assets
		WHERE ($2='' OR (locator,id)>($2,$3)) ORDER BY locator,id LIMIT $1`, limit, afterLocator, afterID)
	if err != nil {
		return nil, errors.New("asset page query failed")
	}
	defer rows.Close()
	assets := []Asset{}
	for rows.Next() {
		var asset Asset
		if err := rows.Scan(&asset.ID, &asset.Type, &asset.Locator, &asset.ConnectionID, &asset.Flags); err != nil {
			return nil, errors.New("asset page scan failed")
		}
		assets = append(assets, asset)
	}
	return assets, rows.Err()
}

func (s *Store) Test(ctx context.Context, name string, adapter Adapter) (int, error) {
	c, secret, err := s.Get(ctx, name)
	if err != nil {
		return 0, err
	}
	if !c.Enabled {
		return 0, errors.New("connection is disabled")
	}
	resources, err := adapter.List(ctx, c, secret)
	state := "ok"
	if err != nil {
		state = "failed"
	}
	status, _ := json.Marshal(map[string]any{"state": state, "checked_at": time.Now().UTC(), "resource_count": len(resources)})
	if recordErr := s.recordCheck(ctx, c, "connection.tested", status); recordErr != nil {
		return 0, recordErr
	}
	return len(resources), err
}

func (s *Store) recordCheck(ctx context.Context, c Connection, action string, status []byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return errors.New("connection audit transaction failed")
	}
	defer tx.Rollback(ctx)
	updated, err := tx.Exec(ctx, `UPDATE `+s.schema+`.connections SET status=$2, updated_at=clock_timestamp(), revision=revision+1 WHERE id=$1 AND revision=$3`, c.ID, status, c.Revision)
	if err != nil {
		return errors.New("connection status update failed")
	}
	if updated.RowsAffected() != 1 {
		return errors.New("connection changed during check; retry")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES ($1,$2,$3)`, action, c.ID, auditDetails(ctx, status)); err != nil {
		return errors.New("connection audit failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("connection audit commit failed")
	}
	return nil
}

func (s *Store) Discover(ctx context.Context, name string, adapter Adapter) (DiscoveryResult, error) {
	c, secret, err := s.Get(ctx, name)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if !c.Enabled {
		return DiscoveryResult{}, errors.New("connection is disabled")
	}
	resources, err := adapter.List(ctx, c, secret)
	if err != nil {
		status, _ := json.Marshal(map[string]any{"state": "failed", "checked_at": time.Now().UTC()})
		if recordErr := s.recordCheck(ctx, c, "connection.discovery_failed", status); recordErr != nil {
			return DiscoveryResult{}, recordErr
		}
		return DiscoveryResult{}, err
	}
	if len(resources) > 10000 {
		return DiscoveryResult{}, errors.New("provider returned too many resources")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DiscoveryResult{}, errors.New("asset discovery transaction failed")
	}
	defer tx.Rollback(ctx)
	// A credential or scope rotation may complete while the provider API call is
	// in flight. Lock and compare the connection before applying that inventory.
	scopeJSON, _ := json.Marshal(c.Scope)
	var current bool
	if err := tx.QueryRow(ctx, `SELECT config=$2::jsonb AND scope=$3::jsonb AND revision=$4 FROM `+s.schema+`.connections WHERE id=$1 FOR UPDATE`, c.ID, c.Config, scopeJSON, c.Revision).Scan(&current); err != nil || !current {
		return DiscoveryResult{}, errors.New("connection changed during discovery; retry")
	}
	result := DiscoveryResult{Connection: name}
	batch := &pgx.Batch{}
	// A complete successful inventory must withdraw eligibility from resources
	// that disappeared or became inaccessible. Preserve their history.
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assets SET flags=flags || '{"in_scope":false,"accessible":false}'::jsonb WHERE connection_id=$1`, c.ID); err != nil {
		return DiscoveryResult{}, errors.New("asset reconciliation failed")
	}
	for _, resource := range resources {
		if resource.Locator == "" || (resource.Type != "github_repo" && resource.Type != "container_image") {
			return DiscoveryResult{}, errors.New("provider returned invalid resource")
		}
		inScope := c.Scope.matchesResource(resource)
		flags, _ := json.Marshal(map[string]any{"discovered": true, "accessible": true, "in_scope": inScope})
		metadata := resource.Metadata
		if len(metadata) == 0 {
			metadata = json.RawMessage(`{}`)
		}
		batch.Queue(`INSERT INTO `+s.schema+`.assets(id,type,locator,connection_id,flags,metadata)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (connection_id,type,locator) DO UPDATE SET flags=assets.flags || EXCLUDED.flags, metadata=EXCLUDED.metadata,
			last_discovered_at=now()`, uuid.New(), resource.Type, resource.Locator, c.ID, flags, metadata)
		result.Discovered++
		if inScope {
			result.InScope++
		}
	}
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return DiscoveryResult{}, errors.New("asset discovery batch failed")
	}
	details, _ := json.Marshal(result)
	status, _ := json.Marshal(map[string]any{"state": "ok", "checked_at": time.Now().UTC(), "resource_count": result.Discovered, "in_scope_count": result.InScope})
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.connections SET status=$2, updated_at=clock_timestamp(), revision=revision+1 WHERE id=$1`, c.ID, status); err != nil {
		return DiscoveryResult{}, errors.New("connection status update failed")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES ('connection.discovered',$1,$2)`, c.ID, auditDetails(ctx, details)); err != nil {
		return DiscoveryResult{}, errors.New("asset discovery audit failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return DiscoveryResult{}, errors.New("asset discovery commit failed")
	}
	return result, nil
}
