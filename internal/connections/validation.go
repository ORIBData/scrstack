package connections

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func decodeStrict(raw json.RawMessage, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("invalid connection fields")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing connection data")
	}
	return nil
}

// ValidateInput is called before storage, so secrets cannot accidentally land
// in the public JSONB config. This validates shape, not provider approval.
func ValidateInput(c Connection, credential json.RawMessage) error {
	if len(c.Name) > 100 || len(c.Config) > 8192 || len(credential) > 65536 {
		return errors.New("connection input exceeds size limit")
	}
	if !providerSegment.MatchString(c.Name) {
		return errors.New("connection name invalid")
	}
	switch c.Provider {
	case "github":
		var cfg struct {
			Organization   string `json:"organization"`
			AuthType       string `json:"auth_type"`
			AppID          string `json:"app_id"`
			InstallationID int64  `json:"installation_id"`
		}
		var cred struct {
			PrivateKeyPEM string `json:"private_key_pem"`
			WebhookSecret string `json:"webhook_secret"`
			Token         string `json:"token"`
		}
		if decodeStrict(c.Config, &cfg) != nil || decodeStrict(credential, &cred) != nil || !providerSegment.MatchString(cfg.Organization) {
			return errors.New("GitHub connection fields invalid")
		}
		if cfg.AuthType == "" {
			cfg.AuthType = "github_app"
		}
		switch cfg.AuthType {
		case "github_app":
			if cfg.AppID == "" || cfg.InstallationID <= 0 || cred.PrivateKeyPEM == "" || cred.Token != "" {
				return errors.New("GitHub App fields invalid")
			}
		case "fine_grained_pat", "oauth_app_token":
			if strings.TrimSpace(cred.Token) == "" || cfg.AppID != "" || cfg.InstallationID != 0 || cred.PrivateKeyPEM != "" || cred.WebhookSecret != "" {
				return errors.New("GitHub user token fields invalid")
			}
		default:
			return errors.New("GitHub auth type invalid")
		}
	case "dockerhub":
		var cfg struct {
			Namespace  string `json:"namespace"`
			Identifier string `json:"identifier"`
		}
		var cred struct {
			Token string `json:"token"`
		}
		if decodeStrict(c.Config, &cfg) != nil || decodeStrict(credential, &cred) != nil || !providerSegment.MatchString(cfg.Namespace) || cfg.Identifier == "" || cred.Token == "" {
			return errors.New("Docker Hub connection fields invalid")
		}
	case "gar":
		var cfg struct {
			Project  string `json:"project"`
			Location string `json:"location"`
		}
		var cred struct {
			ServiceAccountJSON json.RawMessage `json:"service_account_json"`
		}
		if decodeStrict(c.Config, &cfg) != nil || decodeStrict(credential, &cred) != nil || !providerSegment.MatchString(cfg.Project) || !providerSegment.MatchString(cfg.Location) || len(cred.ServiceAccountJSON) == 0 {
			return errors.New("GAR connection fields invalid")
		}
		var keyInfo struct {
			Type     string `json:"type"`
			TokenURI string `json:"token_uri"`
		}
		if json.Unmarshal(cred.ServiceAccountJSON, &keyInfo) != nil || keyInfo.Type != "service_account" || keyInfo.TokenURI != "https://oauth2.googleapis.com/token" {
			return errors.New("GAR credential must be a Google service account key")
		}
	default:
		return fmt.Errorf("unsupported provider %q", c.Provider)
	}
	return nil
}
