package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// GitHub does not retry a failed webhook delivery, so an SCRS outage or a
// rejected request silently loses force-push and other integrity events.
// These calls let SCRS read its own hook's delivery log and request
// redelivery (INT-001 backstop). GitHub keeps deliveries for three days.

// HookDelivery is one attempt from a GitHub hook delivery log.
type HookDelivery struct {
	ID          int64     `json:"id"`
	GUID        string    `json:"guid"`
	DeliveredAt time.Time `json:"delivered_at"`
	Redelivery  bool      `json:"redelivery"`
	StatusCode  int       `json:"status_code"`
	Event       string    `json:"event"`
}

// GitHubHook is one webhook that points at SCRS, with configuration problems
// and the deliveries newer than the requested time (newest first).
type GitHubHook struct {
	Source     string         `json:"source"` // "app" or "org"
	ID         int64          `json:"id"`
	Problems   []string       `json:"problems"`
	Deliveries []HookDelivery `json:"-"`
	// Truncated means the page limit stopped the walk before the window ended.
	Truncated bool `json:"truncated"`
}

// HookDeliveryRetention is how long GitHub keeps deliveries for redelivery.
const HookDeliveryRetention = 72 * time.Hour

const maxDeliveryPages = 20

type githubAccess struct {
	Organization   string `json:"organization"`
	AuthType       string `json:"auth_type"`
	AppID          string `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	WebhookSource  string `json:"webhook_source"`
	key, token     string
}

func parseGitHub(c Connection, secret json.RawMessage) (githubAccess, error) {
	var cfg githubAccess
	var cred struct {
		PrivateKeyPEM string `json:"private_key_pem"`
		Token         string `json:"token"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !providerSegment.MatchString(cfg.Organization) {
		return cfg, errors.New("GitHub connection configuration invalid")
	}
	if cfg.AuthType == "" {
		cfg.AuthType = "github_app"
	}
	if cfg.WebhookSource == "" {
		cfg.WebhookSource = "org"
		if cfg.AuthType == "github_app" {
			cfg.WebhookSource = "app"
		}
	}
	cfg.key, cfg.token = cred.PrivateKeyPEM, cred.Token
	return cfg, nil
}

// accessToken returns a bearer for org endpoints: the user token, or an
// installation token for a GitHub App.
func (a NativeAdapters) accessToken(ctx context.Context, cfg githubAccess) (string, error) {
	if cfg.AuthType != "github_app" {
		if strings.TrimSpace(cfg.token) == "" {
			return "", errors.New("GitHub token is required for selected auth type")
		}
		return cfg.token, nil
	}
	if cfg.AppID == "" || cfg.InstallationID <= 0 || cfg.key == "" {
		return "", errors.New("GitHub App connection configuration invalid")
	}
	jwt, err := githubJWT(cfg.AppID, []byte(cfg.key))
	if err != nil {
		return "", err
	}
	data, err := a.request(ctx, http.MethodPost, strings.TrimSuffix(a.GitHubAPI, "/")+"/app/installations/"+strconv.FormatInt(cfg.InstallationID, 10)+"/access_tokens", jwt, []byte(`{}`))
	if err != nil {
		return "", err
	}
	var token struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &token) != nil || token.Token == "" {
		return "", errors.New("GitHub installation token response invalid")
	}
	return token.Token, nil
}

// hookBearer authenticates hook calls: the app JWT for an app webhook,
// otherwise an org-scoped token.
func (a NativeAdapters) hookBearer(ctx context.Context, cfg githubAccess) (string, error) {
	if cfg.WebhookSource == "app" {
		if cfg.AuthType != "github_app" || cfg.AppID == "" || cfg.key == "" {
			return "", errors.New("app webhook source requires GitHub App authentication")
		}
		return githubJWT(cfg.AppID, []byte(cfg.key))
	}
	return a.accessToken(ctx, cfg)
}

// pointsAtSCRS matches the configured public hook URL exactly or, when none
// is configured, either SCRS GitHub receiver path.
func pointsAtSCRS(raw, expected string) bool {
	if expected != "" {
		return strings.TrimSuffix(raw, "/") == strings.TrimSuffix(expected, "/")
	}
	u, err := url.Parse(raw)
	return err == nil && (strings.HasSuffix(u.Path, "/scrs/v1/webhooks/github") || strings.HasSuffix(u.Path, "/scrs/v1/ingest/github"))
}

type hookConfig struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	InsecureSSL any    `json:"insecure_ssl"` // GitHub returns "0"/"1", sometimes a number
}

func (h hookConfig) problems(events []string, active bool) []string {
	problems := []string{}
	if !active {
		problems = append(problems, "webhook is inactive")
	}
	if !slices.Contains(events, "push") && !slices.Contains(events, "*") {
		problems = append(problems, "webhook does not send push events, so force pushes are not seen")
	}
	if h.ContentType != "json" {
		problems = append(problems, "webhook content type must be application/json")
	}
	if fmt.Sprint(h.InsecureSSL) != "0" {
		problems = append(problems, "webhook TLS verification is disabled")
	}
	return problems
}

// GitHubHooks finds the hooks pointing at SCRS (hookURL, or the SCRS paths when
// empty) and reads their deliveries back to since. An org with no such hook
// returns one hook with ID 0 and a problem, so the caller can alert.
func (a NativeAdapters) GitHubHooks(ctx context.Context, c Connection, secret json.RawMessage, hookURL string, since time.Time) ([]GitHubHook, error) {
	cfg, err := parseGitHub(c, secret)
	if err != nil {
		return nil, err
	}
	bearer, err := a.hookBearer(ctx, cfg)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(a.GitHubAPI, "/")
	var hooks []GitHubHook
	if cfg.WebhookSource == "app" {
		data, err := a.request(ctx, http.MethodGet, base+"/app/hook/config", bearer, nil)
		if err != nil {
			return nil, err
		}
		var config hookConfig
		var app struct {
			Events []string `json:"events"`
		}
		if json.Unmarshal(data, &config) != nil {
			return nil, errors.New("GitHub App hook configuration invalid")
		}
		if data, err = a.request(ctx, http.MethodGet, base+"/app", bearer, nil); err != nil || json.Unmarshal(data, &app) != nil {
			return nil, errors.New("GitHub App events unavailable")
		}
		if !pointsAtSCRS(config.URL, hookURL) {
			return []GitHubHook{{Source: "app", Problems: []string{"GitHub App webhook URL does not point at SCRS"}}}, nil
		}
		hooks = append(hooks, GitHubHook{Source: "app", ID: 1, Problems: config.problems(app.Events, true)})
	} else {
		data, err := a.request(ctx, http.MethodGet, base+"/orgs/"+cfg.Organization+"/hooks?per_page=100", bearer, nil)
		if err != nil {
			return nil, fmt.Errorf("organization webhooks unavailable (needs the organization webhooks permission): %w", err)
		}
		var listed []struct {
			ID     int64      `json:"id"`
			Active bool       `json:"active"`
			Events []string   `json:"events"`
			Config hookConfig `json:"config"`
		}
		if json.Unmarshal(data, &listed) != nil {
			return nil, errors.New("organization webhooks response invalid")
		}
		for _, h := range listed {
			if h.ID > 0 && pointsAtSCRS(h.Config.URL, hookURL) {
				hooks = append(hooks, GitHubHook{Source: "org", ID: h.ID, Problems: h.Config.problems(h.Events, h.Active)})
			}
		}
		if len(hooks) == 0 {
			return []GitHubHook{{Source: "org", Problems: []string{"no organization webhook points at SCRS"}}}, nil
		}
	}
	for i := range hooks {
		if hooks[i].Deliveries, hooks[i].Truncated, err = a.hookDeliveries(ctx, a.deliveriesPath(cfg, hooks[i]), bearer, since); err != nil {
			return nil, err
		}
	}
	return hooks, nil
}

func (a NativeAdapters) deliveriesPath(cfg githubAccess, h GitHubHook) string {
	base := strings.TrimSuffix(a.GitHubAPI, "/")
	if h.Source == "app" {
		return base + "/app/hook/deliveries"
	}
	return base + "/orgs/" + cfg.Organization + "/hooks/" + strconv.FormatInt(h.ID, 10) + "/deliveries"
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// hookDeliveries walks the cursor-paginated log (newest first) until since.
func (a NativeAdapters) hookDeliveries(ctx context.Context, target, bearer string, since time.Time) ([]HookDelivery, bool, error) {
	var out []HookDelivery
	next := target + "?per_page=100"
	for page := 0; page < maxDeliveryPages; page++ {
		data, header, err := a.exchange(ctx, http.MethodGet, next, bearerAuth(bearer), nil)
		if err != nil {
			return nil, false, fmt.Errorf("webhook deliveries unavailable: %w", err)
		}
		var batch []HookDelivery
		if json.Unmarshal(data, &batch) != nil {
			return nil, false, errors.New("webhook deliveries response invalid")
		}
		for _, d := range batch {
			if d.DeliveredAt.Before(since) {
				return out, false, nil
			}
			out = append(out, d)
		}
		match := nextLink.FindStringSubmatch(header.Get("Link"))
		// Follow only links back to the same endpoint, never elsewhere.
		if len(batch) == 0 || match == nil || !strings.HasPrefix(match[1], target+"?") {
			return out, false, nil
		}
		next = match[1]
	}
	return out, true, nil
}

// RedeliverGitHub asks GitHub to send one delivery again. GitHub reuses the
// delivery GUID, so SCRS's replay protection makes this idempotent.
func (a NativeAdapters) RedeliverGitHub(ctx context.Context, c Connection, secret json.RawMessage, hook GitHubHook, delivery int64) error {
	cfg, err := parseGitHub(c, secret)
	if err != nil {
		return err
	}
	bearer, err := a.hookBearer(ctx, cfg)
	if err != nil {
		return err
	}
	_, err = a.request(ctx, http.MethodPost, a.deliveriesPath(cfg, hook)+"/"+strconv.FormatInt(delivery, 10)+"/attempts", bearer, []byte(`{}`))
	return err
}

func bearerAuth(token string) func(*http.Request) {
	return func(r *http.Request) {
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
	}
}

// exchange is do with the response headers, for paginated APIs.
func (a NativeAdapters) exchange(ctx context.Context, method, target string, auth func(*http.Request), body []byte) ([]byte, http.Header, error) {
	var header http.Header
	data, err := a.send(ctx, method, target, auth, body, func(r *http.Response) { header = r.Header })
	return data, header, err
}
