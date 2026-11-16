// Package notify implements outbound webhook subscriptions (OUT-001 to OUT-003,
// TRG-008). Events are written to a PostgreSQL outbox inside the transaction
// that produced them, so a committed change always yields its event and a
// rolled-back change never does. A dispatcher delivers them with signatures,
// retries and a dead-letter state.
package notify

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ORIBData/scrstack/internal/netguard"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const SchemaVersion = 1

// Events lists every event type a subscription may select.
var Events = map[string]bool{
	"assessment.completed":          true,
	"assessment.failed":             true,
	"finding.created":               true,
	"finding.status_changed":        true,
	"finding.rescored":              true,
	"malicious_dependency.reported": true,
	"integrity.alert":               true,
	"feed.stale":                    true,
	"connection.degraded":           true,
	"maintenance.completed":         true,
	"qa.completed":                  true,
	"qa.failed":                     true,
	"system.degraded":               true,
	"system.recovered":              true,
	"ping":                          true,
}

var (
	ErrInput    = errors.New("invalid webhook subscription")
	ErrNotFound = errors.New("webhook subscription not found")
	ErrConflict = errors.New("webhook subscription conflict")
)

// Schema is applied under the storage migration lock. No destructive DDL.
func Schema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.webhook_subscriptions(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,url text NOT NULL,secret_ciphertext bytea NOT NULL,events jsonb NOT NULL,profile text NOT NULL DEFAULT 'summary' CHECK(profile IN ('summary','full','agent')),egress_ack boolean NOT NULL DEFAULT false,include_contacts boolean NOT NULL DEFAULT false,enabled boolean NOT NULL DEFAULT true,revision bigint NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.webhook_deliveries(id uuid PRIMARY KEY,subscription_id uuid NOT NULL REFERENCES ` + s + `.webhook_subscriptions(id),event_id uuid NOT NULL,event_type text NOT NULL,payload jsonb NOT NULL,status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sending','delivered','dead')),attempts integer NOT NULL DEFAULT 0,next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,last_status integer NOT NULL DEFAULT 0,last_error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),delivered_at timestamptz,UNIQUE(subscription_id,event_id))`,
		`CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx ON ` + s + `.webhook_deliveries(next_attempt_at) WHERE status IN ('pending','sending')`,
		`CREATE INDEX IF NOT EXISTS webhook_deliveries_subscription_idx ON ` + s + `.webhook_deliveries(subscription_id,id)`,
		`CREATE INDEX IF NOT EXISTS webhook_deliveries_age_idx ON ` + s + `.webhook_deliveries(created_at) WHERE status IN ('delivered','dead')`,
		// Connection scope: a subscription with connection IDs receives only
		// events about those connections (and connection-less platform events).
		`ALTER TABLE ` + s + `.webhook_subscriptions ADD COLUMN IF NOT EXISTS connections jsonb NOT NULL DEFAULT '[]'`,
		// One row: the platform status last announced, so that several API
		// instances announce each change once.
		`CREATE TABLE IF NOT EXISTS ` + s + `.platform_state(id boolean PRIMARY KEY DEFAULT true CHECK(id),status text NOT NULL DEFAULT 'ok' CHECK(status IN ('ok','degraded','down')),changed_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
}

// publicBase prefixes event links so receivers can follow them directly.
var publicBase = strings.TrimSuffix(strings.TrimSuffix(os.Getenv("SCRS_PUBLIC_BASE_URL"), "/"), "/scrs/v1")

// Link returns an absolute link when SCRS_PUBLIC_BASE_URL is set.
func Link(path string) string { return publicBase + "/scrs/v1" + path }

// Scope ties an event to a connection, directly or through an asset, so
// connection-scoped subscriptions receive only their connections' events.
// A zero Scope is a platform event, delivered to every matching subscription.
type Scope struct {
	Connection uuid.UUID
	Asset      uuid.UUID
}

// Emit records an unscoped event for every subscribed endpoint, inside the
// caller's transaction. A non-empty only list restricts delivery to those
// subscription names (TRG-008 notify).
func Emit(ctx context.Context, tx pgx.Tx, schema, eventType string, data any, only []string) (uuid.UUID, error) {
	return EmitScoped(ctx, tx, schema, eventType, data, only, Scope{})
}

// EmitScoped is Emit for an event about one connection or asset.
func EmitScoped(ctx context.Context, tx pgx.Tx, schema, eventType string, data any, only []string, scope Scope) (uuid.UUID, error) {
	if !Events[eventType] {
		return uuid.Nil, ErrInput
	}
	id := uuid.New()
	now := time.Now().UTC()
	payload, err := json.Marshal(map[string]any{
		"event": map[string]any{"id": id, "type": eventType, "version": SchemaVersion, "time": now},
		"data":  data,
	})
	if err != nil {
		return uuid.Nil, err
	}
	if only == nil {
		only = []string{}
	}
	_, err = tx.Exec(ctx, `WITH scope AS (SELECT COALESCE(NULLIF($5::uuid,'00000000-0000-0000-0000-000000000000'),(SELECT a.connection_id FROM `+schema+`.assets a WHERE a.id=NULLIF($6::uuid,'00000000-0000-0000-0000-000000000000')))::text AS connection) INSERT INTO `+schema+`.webhook_deliveries(id,subscription_id,event_id,event_type,payload) SELECT gen_random_uuid(),s.id,$1,$2,$3 FROM `+schema+`.webhook_subscriptions s,scope WHERE s.enabled AND s.events ? $2 AND (cardinality($4::text[])=0 OR s.name=ANY($4::text[])) AND (s.connections='[]'::jsonb OR scope.connection IS NULL OR s.connections ? scope.connection)`, id, eventType, payload, only, scope.Connection, scope.Asset)
	if err != nil {
		return id, err
	}
	live := LiveEvent{ID: id, Type: eventType, Time: now, Refs: refs(data)}
	if scope.Connection != uuid.Nil {
		live.Connection = &scope.Connection
	}
	if scope.Asset != uuid.Nil {
		live.Asset = &scope.Asset
	}
	return id, announce(ctx, tx, schema, live)
}

type Subscription struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	Events          []string  `json:"events"`
	Profile         string    `json:"profile"`
	EgressAck       bool      `json:"egress_ack"`
	IncludeContacts bool      `json:"include_contacts"`
	// Connections limits delivery to events about these connections; empty
	// receives events from every connection.
	Connections []uuid.UUID `json:"connections"`
	Enabled     bool        `json:"enabled"`
	Revision    int64       `json:"revision"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type Delivery struct {
	ID             uuid.UUID       `json:"id"`
	SubscriptionID uuid.UUID       `json:"subscription_id"`
	EventID        uuid.UUID       `json:"event_id"`
	EventType      string          `json:"event_type"`
	Status         string          `json:"status"`
	Attempts       int             `json:"attempts"`
	NextAttemptAt  time.Time       `json:"next_attempt_at"`
	LastStatus     int             `json:"last_status"`
	LastError      string          `json:"last_error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	DeliveredAt    *time.Time      `json:"delivered_at,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

type Store struct {
	pool   *pgxpool.Pool
	schema string
	aead   cipher.AEAD
	// PrivateHosts may use http and resolve to private addresses (for example
	// an n8n container on the same Docker network). Everything else must be
	// https to a public address.
	PrivateHosts map[string]bool
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
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("notification database configuration failed")
	}
	if cfg.MaxConns > 4 {
		cfg.MaxConns = 4
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("notification database configuration failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("notification database unavailable")
	}
	return &Store{pool: pool, schema: pgx.Identifier{schema}.Sanitize(), aead: aead, PrivateHosts: PrivateHostsFromEnv()}, nil
}

func (s *Store) Close() { s.pool.Close() }

// PrivateHostsFromEnv reads SCRS_WEBHOOK_PRIVATE_HOSTS (comma-separated hostnames).
func PrivateHostsFromEnv() map[string]bool {
	hosts := map[string]bool{}
	for _, h := range strings.Split(os.Getenv("SCRS_WEBHOOK_PRIVATE_HOSTS"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts[h] = true
		}
	}
	return hosts
}

func (s *Store) validURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.User != nil || u.Fragment != "" || u.Host == "" || u.Opaque != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	private := s.PrivateHosts[host]
	if u.Scheme != "https" && !(u.Scheme == "http" && private) {
		return false
	}
	// Literal private addresses are only reachable through the explicit allow-list.
	if ip := net.ParseIP(host); ip != nil && !private && !netguard.Public(ip) {
		return false
	}
	return true
}

func validEvents(events []string) bool {
	if len(events) == 0 || len(events) > len(Events) {
		return false
	}
	seen := map[string]bool{}
	for _, e := range events {
		if !Events[e] || seen[e] {
			return false
		}
		seen[e] = true
	}
	return true
}

// validConnections checks a subscription's connection scope: at most 50
// existing connections, no duplicates.
func validConnections(ctx context.Context, tx pgx.Tx, schema string, ids []uuid.UUID) (bool, error) {
	if len(ids) > 50 {
		return false, nil
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if seen[id] {
			return false, nil
		}
		seen[id] = true
	}
	if len(ids) == 0 {
		return true, nil
	}
	var found int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.connections WHERE id=ANY($1)`, ids).Scan(&found)
	return found == len(ids), err
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(b), nil
}

func (s *Store) seal(id uuid.UUID, secret string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, []byte(secret), []byte("webhook:"+id.String())), nil
}

func (s *Store) open(id uuid.UUID, ciphertext []byte) (string, error) {
	if len(ciphertext) < s.aead.NonceSize() {
		return "", errors.New("webhook secret invalid")
	}
	plain, err := s.aead.Open(nil, ciphertext[:s.aead.NonceSize()], ciphertext[s.aead.NonceSize():], []byte("webhook:"+id.String()))
	if err != nil {
		return "", errors.New("webhook secret decryption failed; check SCRS_MASTER_KEY")
	}
	return string(plain), nil
}

func audit(ctx context.Context, tx pgx.Tx, schema, action string, target uuid.UUID, details map[string]any) error {
	raw, _ := json.Marshal(details)
	_, err := tx.Exec(ctx, `INSERT INTO `+schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, target, raw)
	return err
}

// Create stores a subscription and returns its signing secret once.
func (s *Store) Create(ctx context.Context, in Subscription, actor uuid.UUID) (Subscription, string, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Profile == "" {
		in.Profile = "summary"
	}
	if len(in.Name) < 1 || len(in.Name) > 100 || !s.validURL(in.URL) || !validEvents(in.Events) || (in.Profile != "summary" && in.Profile != "full" && in.Profile != "agent") || (in.Profile == "agent" && !in.EgressAck) {
		return Subscription{}, "", ErrInput
	}
	secret, err := newSecret()
	if err != nil {
		return Subscription{}, "", err
	}
	in.ID = uuid.New()
	sealed, err := s.seal(in.ID, secret)
	if err != nil {
		return Subscription{}, "", err
	}
	events, _ := json.Marshal(in.Events)
	if in.Connections == nil {
		in.Connections = []uuid.UUID{}
	}
	scope, _ := json.Marshal(in.Connections)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Subscription{}, "", err
	}
	defer tx.Rollback(ctx)
	if ok, err := validConnections(ctx, tx, s.schema, in.Connections); err != nil || !ok {
		if err == nil {
			err = ErrInput
		}
		return Subscription{}, "", err
	}
	err = tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.webhook_subscriptions(id,name,url,secret_ciphertext,events,profile,egress_ack,include_contacts,connections) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(name) DO NOTHING RETURNING enabled,revision,created_at,updated_at`, in.ID, in.Name, in.URL, sealed, events, in.Profile, in.EgressAck, in.IncludeContacts, scope).Scan(&in.Enabled, &in.Revision, &in.CreatedAt, &in.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, "", ErrConflict
	}
	if err != nil {
		return Subscription{}, "", err
	}
	u, _ := url.Parse(in.URL)
	if err := audit(ctx, tx, s.schema, "webhook.subscription_created", in.ID, map[string]any{"actor_id": actor, "host": u.Hostname(), "events": in.Events, "profile": in.Profile, "connections": in.Connections}); err != nil {
		return Subscription{}, "", err
	}
	return in, secret, tx.Commit(ctx)
}

const subscriptionColumns = `id,name,url,events,profile,egress_ack,include_contacts,enabled,revision,created_at,updated_at,connections`

func scanSubscription(row pgx.Row) (Subscription, error) {
	var sub Subscription
	var events, scope []byte
	err := row.Scan(&sub.ID, &sub.Name, &sub.URL, &events, &sub.Profile, &sub.EgressAck, &sub.IncludeContacts, &sub.Enabled, &sub.Revision, &sub.CreatedAt, &sub.UpdatedAt, &scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return sub, ErrNotFound
	}
	if err != nil {
		return sub, err
	}
	if err := json.Unmarshal(scope, &sub.Connections); err != nil {
		return sub, err
	}
	return sub, json.Unmarshal(events, &sub.Events)
}

func (s *Store) Get(ctx context.Context, id uuid.UUID) (Subscription, error) {
	return scanSubscription(s.pool.QueryRow(ctx, `SELECT `+subscriptionColumns+` FROM `+s.schema+`.webhook_subscriptions WHERE id=$1`, id))
}

func (s *Store) List(ctx context.Context) ([]Subscription, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+subscriptionColumns+` FROM `+s.schema+`.webhook_subscriptions ORDER BY name LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

type Change struct {
	URL             *string   `json:"url"`
	Events          *[]string `json:"events"`
	Profile         *string   `json:"profile"`
	EgressAck       *bool     `json:"egress_ack"`
	IncludeContacts *bool     `json:"include_contacts"`
	Enabled         *bool     `json:"enabled"`
	// Connections replaces the connection scope; an empty list removes it.
	Connections *[]uuid.UUID `json:"connections"`
}

// Update applies a partial change under an optimistic revision check.
func (s *Store) Update(ctx context.Context, id uuid.UUID, expected int64, c Change, actor uuid.UUID) (Subscription, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Subscription{}, err
	}
	defer tx.Rollback(ctx)
	sub, err := scanSubscription(tx.QueryRow(ctx, `SELECT `+subscriptionColumns+` FROM `+s.schema+`.webhook_subscriptions WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return Subscription{}, err
	}
	if sub.Revision != expected {
		return Subscription{}, ErrConflict
	}
	if c.URL != nil {
		sub.URL = *c.URL
	}
	if c.Events != nil {
		sub.Events = *c.Events
	}
	if c.Profile != nil {
		sub.Profile = *c.Profile
	}
	if c.EgressAck != nil {
		sub.EgressAck = *c.EgressAck
	}
	if c.IncludeContacts != nil {
		sub.IncludeContacts = *c.IncludeContacts
	}
	if c.Enabled != nil {
		sub.Enabled = *c.Enabled
	}
	if c.Connections != nil {
		sub.Connections = *c.Connections
		if ok, err := validConnections(ctx, tx, s.schema, sub.Connections); err != nil || !ok {
			if err == nil {
				err = ErrInput
			}
			return Subscription{}, err
		}
	}
	if !s.validURL(sub.URL) || !validEvents(sub.Events) || (sub.Profile != "summary" && sub.Profile != "full" && sub.Profile != "agent") || (sub.Profile == "agent" && !sub.EgressAck) {
		return Subscription{}, ErrInput
	}
	events, _ := json.Marshal(sub.Events)
	scope, _ := json.Marshal(sub.Connections)
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.webhook_subscriptions SET url=$2,events=$3,profile=$4,egress_ack=$5,include_contacts=$6,enabled=$7,connections=$8,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1`, id, sub.URL, events, sub.Profile, sub.EgressAck, sub.IncludeContacts, sub.Enabled, scope); err != nil {
		return Subscription{}, err
	}
	u, _ := url.Parse(sub.URL)
	if err := audit(ctx, tx, s.schema, "webhook.subscription_changed", id, map[string]any{"actor_id": actor, "host": u.Hostname(), "events": sub.Events, "profile": sub.Profile, "enabled": sub.Enabled, "connections": sub.Connections}); err != nil {
		return Subscription{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Subscription{}, err
	}
	return s.Get(ctx, id)
}

// RotateSecret replaces the signing secret and returns the new one once.
func (s *Store) RotateSecret(ctx context.Context, id, actor uuid.UUID) (string, error) {
	secret, err := newSecret()
	if err != nil {
		return "", err
	}
	sealed, err := s.seal(id, secret)
	if err != nil {
		return "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.webhook_subscriptions SET secret_ciphertext=$2,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1`, id, sealed)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", ErrNotFound
	}
	if err := audit(ctx, tx, s.schema, "webhook.secret_rotated", id, map[string]any{"actor_id": actor}); err != nil {
		return "", err
	}
	return secret, tx.Commit(ctx)
}

// Ping queues a test event for one subscription regardless of its event filter.
func (s *Store) Ping(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	sub, err := s.Get(ctx, id)
	if err != nil {
		return uuid.Nil, err
	}
	if !sub.Enabled {
		return uuid.Nil, ErrInput
	}
	eventID := uuid.New()
	payload, _ := json.Marshal(map[string]any{
		"event": map[string]any{"id": eventID, "type": "ping", "version": SchemaVersion, "time": time.Now().UTC()},
		"data":  map[string]any{"subscription": sub.Name},
	})
	_, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.webhook_deliveries(id,subscription_id,event_id,event_type,payload) VALUES($1,$2,$3,'ping',$4)`, uuid.New(), id, eventID, payload)
	return eventID, err
}

// EmitNow emits an event in its own transaction, for producers without one.
func (s *Store) EmitNow(ctx context.Context, eventType string, data any) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := Emit(ctx, tx, s.schema, eventType, data, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PlatformTransition records that the platform status became status and, only
// when that differs from the status last recorded, emits system.degraded
// (degraded or down) or system.recovered (ok) in the same transaction. It
// returns whether it emitted. The row lock makes concurrent API instances agree:
// the first records and emits, the others see no change. components lists
// the components that are not ok, each with name, status and detail.
func (s *Store) PlatformTransition(ctx context.Context, status string, components []map[string]any) (bool, error) {
	if status != "ok" && status != "degraded" && status != "down" {
		return false, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.platform_state(id) VALUES(true) ON CONFLICT DO NOTHING`); err != nil {
		return false, err
	}
	var previous string
	var since time.Time
	if err := tx.QueryRow(ctx, `SELECT status,changed_at FROM `+s.schema+`.platform_state WHERE id FOR UPDATE`).Scan(&previous, &since); err != nil {
		return false, err
	}
	if previous == status {
		return false, nil
	}
	var changedAt time.Time
	if err := tx.QueryRow(ctx, `UPDATE `+s.schema+`.platform_state SET status=$1,changed_at=clock_timestamp() WHERE id RETURNING changed_at`, status).Scan(&changedAt); err != nil {
		return false, err
	}
	if components == nil {
		components = []map[string]any{}
	}
	event, data := "system.degraded", map[string]any{"status": status, "previous_status": previous, "components": components, "since": since.UTC()}
	if status == "ok" {
		event, data = "system.recovered", map[string]any{"status": status, "previous_status": previous, "since": since.UTC(), "duration_seconds": int64(changedAt.Sub(since).Seconds())}
	}
	if _, err := Emit(ctx, tx, s.schema, event, data, nil); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *Store) Deliveries(ctx context.Context, subscription uuid.UUID, status string, after uuid.UUID) ([]Delivery, error) {
	if status != "" && status != "pending" && status != "sending" && status != "delivered" && status != "dead" {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT id,subscription_id,event_id,event_type,status,attempts,next_attempt_at,last_status,last_error,created_at,delivered_at FROM `+s.schema+`.webhook_deliveries WHERE id>$1 AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR subscription_id=$2) AND ($3='' OR status=$3) ORDER BY id LIMIT 101`, after, subscription, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.SubscriptionID, &d.EventID, &d.EventType, &d.Status, &d.Attempts, &d.NextAttemptAt, &d.LastStatus, &d.LastError, &d.CreatedAt, &d.DeliveredAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) Delivery(ctx context.Context, id uuid.UUID) (Delivery, error) {
	var d Delivery
	err := s.pool.QueryRow(ctx, `SELECT id,subscription_id,event_id,event_type,status,attempts,next_attempt_at,last_status,last_error,created_at,delivered_at,payload FROM `+s.schema+`.webhook_deliveries WHERE id=$1`, id).Scan(&d.ID, &d.SubscriptionID, &d.EventID, &d.EventType, &d.Status, &d.Attempts, &d.NextAttemptAt, &d.LastStatus, &d.LastError, &d.CreatedAt, &d.DeliveredAt, &d.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// Redeliver resets a delivered or dead-lettered delivery. The event id is
// unchanged, so receivers can de-duplicate on Idempotency-Key.
func (s *Store) Redeliver(ctx context.Context, id, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.webhook_deliveries SET status='pending',attempts=0,next_attempt_at=clock_timestamp(),lease_until=NULL,last_error='' WHERE id=$1 AND status IN ('delivered','dead')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := audit(ctx, tx, s.schema, "webhook.redelivered", id, map[string]any{"actor_id": actor}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RedeliverDead requeues every dead-lettered delivery (maintenance action).
func (s *Store) RedeliverDead(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.webhook_deliveries SET status='pending',attempts=0,next_attempt_at=clock_timestamp(),lease_until=NULL,last_error='' WHERE status='dead'`)
	return tag.RowsAffected(), err
}

// Stats counts deliveries that are not yet delivered, by status.
func (s *Store) Stats(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	rows, err := s.pool.Query(ctx, `SELECT status,count(*) FROM `+s.schema+`.webhook_deliveries WHERE status IN ('pending','sending','dead') GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}
