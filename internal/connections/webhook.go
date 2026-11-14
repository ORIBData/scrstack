package connections

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Inbound webhooks belong to their connection: every GitHub, GitLab and
// registry connection has its own webhook secret and receiver path, so
// organizations and registries added at runtime need no deployment change,
// and rotating one connection's secret leaves the others untouched. The
// secret is sealed with SCRS_MASTER_KEY apart from the provider credential:
// rotating it does not re-scope assets or invalidate running assessments.

// WebhookProviders are the providers that send SCRS webhooks.
var WebhookProviders = map[string]bool{"github": true, "gitlab": true, "harbor": true, "dockerhub": true, "gar": true, "oci": true}

// ErrWebhookInput rejects a webhook secret or hook URL.
var ErrWebhookInput = errors.New("invalid webhook settings")

// Webhook is a connection's inbound webhook state; the secret is never read back.
type Webhook struct {
	Configured bool   `json:"configured"`
	Path       string `json:"path"`
	// HookURL is the public URL configured at GitHub when it is not Path on
	// this deployment (a relay); the delivery check matches hooks by it.
	HookURL   string     `json:"hook_url,omitempty"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

// WebhookPath is a connection's receiver path.
func WebhookPath(provider, name string) string {
	if provider == "github" || provider == "gitlab" {
		return "/scrs/v1/ingest/" + provider + "/" + name
	}
	return "/scrs/v1/ingest/registry/" + provider + "/" + name
}

func webhookAAD(id uuid.UUID) []byte { return []byte("connection-webhook:" + id.String()) }

// NewWebhookSecret returns 32 random bytes as hex.
func NewWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidWebhookSecret accepts 32 to 256 printable ASCII characters without
// spaces, which every supported provider can store and send.
func ValidWebhookSecret(secret string) bool {
	if len(secret) < 32 || len(secret) > 256 {
		return false
	}
	for _, r := range secret {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

func webhookView(provider, name string, configured bool, hookURL string, rotated *time.Time) *Webhook {
	if !WebhookProviders[provider] {
		return nil
	}
	return &Webhook{Configured: configured, Path: WebhookPath(provider, name), HookURL: hookURL, RotatedAt: rotated}
}

// SetWebhook stores a connection's webhook secret (nil keeps it) and, for
// GitHub, the hook URL (nil keeps it; "" clears it).
func (s *Store) SetWebhook(ctx context.Context, id uuid.UUID, secret *string, hookURL *string) (Connection, error) {
	c, err := s.PublicByID(ctx, id)
	if err != nil {
		return c, err
	}
	if !WebhookProviders[c.Provider] {
		return c, errors.Join(ErrWebhookInput, errors.New(c.Provider+" connections do not receive webhooks"))
	}
	if secret != nil && !ValidWebhookSecret(*secret) {
		return c, errors.Join(ErrWebhookInput, errors.New("secret must be 32 to 256 printable characters without spaces"))
	}
	if hookURL != nil && *hookURL != "" {
		u, err := url.Parse(*hookURL)
		if c.Provider != "github" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(*hookURL) > 2048 {
			return c, errors.Join(ErrWebhookInput, errors.New("hook_url is an https URL, for GitHub connections only"))
		}
	}
	var sealed []byte
	if secret != nil {
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return c, err
		}
		sealed = s.aead.Seal(nonce, nonce, []byte(*secret), webhookAAD(id))
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return c, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.connections SET webhook_secret_ciphertext=COALESCE($2,webhook_secret_ciphertext),webhook_rotated_at=CASE WHEN $2::bytea IS NULL THEN webhook_rotated_at ELSE clock_timestamp() END,webhook_url=COALESCE($3,webhook_url),revision=revision+1,updated_at=clock_timestamp() WHERE id=$1`, id, sealed, hookURL)
	if err != nil {
		return c, errors.New("webhook update failed")
	}
	if tag.RowsAffected() != 1 {
		return c, ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"secret_rotated": secret != nil, "hook_url_changed": hookURL != nil})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('connection.webhook_changed',$1,$2)`, id, auditDetails(ctx, details)); err != nil {
		return c, errors.New("webhook audit failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return c, err
	}
	return s.PublicByID(ctx, id)
}

// WebhookSecret returns an enabled connection of the provider and its
// webhook secret. A GitHub App connection seeded before per-connection
// secrets falls back to the webhook_secret in its credential.
func (s *Store) WebhookSecret(ctx context.Context, provider, name string) (Connection, string, error) {
	var c Connection
	var sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT id,provider,name,enabled,webhook_secret_ciphertext FROM `+s.schema+`.connections WHERE name=$1 AND provider=$2`, name, provider).Scan(&c.ID, &c.Provider, &c.Name, &c.Enabled, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, "", ErrNotFound
	}
	if err != nil {
		return c, "", err
	}
	if !c.Enabled {
		return c, "", ErrNotFound
	}
	if len(sealed) >= s.aead.NonceSize() {
		plain, err := s.aead.Open(nil, sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():], webhookAAD(c.ID))
		if err != nil {
			return c, "", errors.New("webhook secret decryption failed; check SCRS_MASTER_KEY")
		}
		return c, string(plain), nil
	}
	if provider == "github" {
		if _, credential, err := s.Get(ctx, name); err == nil {
			var legacy struct {
				WebhookSecret string `json:"webhook_secret"`
			}
			if json.Unmarshal(credential, &legacy) == nil && ValidWebhookSecret(strings.TrimSpace(legacy.WebhookSecret)) {
				return c, strings.TrimSpace(legacy.WebhookSecret), nil
			}
		}
	}
	return c, "", ErrNotFound
}
