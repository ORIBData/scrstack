package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
)

// SeedFromEnv imports only explicitly configured provider credentials.
// Postgres stays authoritative after first seed unless override is enabled.
func (s *Store) SeedFromEnv(ctx context.Context) (int, error) {
	replace := os.Getenv("SCRS_CONNECTIONS_FROM_ENV") == "true"
	count := 0
	for _, item := range []struct {
		name       string
		configured bool
		build      func() (Connection, json.RawMessage, error)
	}{
		{"github-primary", os.Getenv("SCRS_GITHUB_AUTH_TYPE") != "" || os.Getenv("SCRS_GITHUB_APP_ID") != "" || os.Getenv("SCRS_GITHUB_TOKEN") != "", githubFromEnv},
		{"dockerhub-primary", os.Getenv("SCRS_DOCKERHUB_NAMESPACE") != "", dockerFromEnv},
		{"gar-primary", os.Getenv("SCRS_GAR_PROJECT") != "", garFromEnv},
	} {
		if !item.configured {
			continue
		}
		var modeVar string
		switch item.name {
		case "github-primary":
			modeVar = "SCRS_GITHUB_REPOSITORY_MODE"
		case "dockerhub-primary":
			modeVar = "SCRS_DOCKERHUB_IMAGE_MODE"
		case "gar-primary":
			modeVar = "SCRS_GAR_IMAGE_MODE"
		}
		if mode := os.Getenv(modeVar); mode != "" && mode != "all" && mode != "selected" {
			return count, errors.New(modeVar + " must be all or selected")
		}
		if !replace {
			exists, err := s.Has(ctx, item.name)
			if err != nil {
				return count, errors.New("connection lookup failed")
			}
			if exists {
				continue
			}
		}
		c, credential, err := item.build()
		if err != nil {
			return count, err
		}
		c.Name = item.name
		written, err := s.Put(ctx, c, credential, replace)
		if err != nil {
			return count, err
		}
		if written {
			count++
		}
	}
	return count, nil
}

func githubFromEnv() (Connection, json.RawMessage, error) {
	org := os.Getenv("SCRS_GITHUB_ORGANIZATION")
	if !providerSegment.MatchString(org) {
		return Connection{}, nil, errors.New("SCRS_GITHUB_ORGANIZATION must be a valid organization name")
	}
	authType := os.Getenv("SCRS_GITHUB_AUTH_TYPE")
	if authType == "" {
		authType = "github_app"
	}
	if authType == "fine_grained_pat" || authType == "oauth_app_token" {
		token := strings.TrimSpace(os.Getenv("SCRS_GITHUB_TOKEN"))
		if token == "" {
			return Connection{}, nil, errors.New("SCRS_GITHUB_TOKEN is required for GitHub token auth")
		}
		config, _ := json.Marshal(map[string]string{"organization": org, "auth_type": authType})
		credential, _ := json.Marshal(map[string]string{"token": token})
		return Connection{Provider: "github", Config: config, Scope: scopeFromEnv("SCRS_GITHUB_REPOSITORY", org+"/*")}, credential, nil
	}
	if authType != "github_app" {
		return Connection{}, nil, errors.New("SCRS_GITHUB_AUTH_TYPE must be github_app, fine_grained_pat or oauth_app_token")
	}
	app := os.Getenv("SCRS_GITHUB_APP_ID")
	installation := os.Getenv("SCRS_GITHUB_INSTALLATION_ID")
	privateB64 := os.Getenv("SCRS_GITHUB_APP_PRIVATE_KEY_B64")
	if org == "" || app == "" || installation == "" || privateB64 == "" {
		return Connection{}, nil, errors.New("GitHub connection needs organization, app id, installation id and base64 private key")
	}
	installationID, err := strconv.ParseInt(installation, 10, 64)
	if err != nil || installationID <= 0 {
		return Connection{}, nil, errors.New("SCRS_GITHUB_INSTALLATION_ID must be a positive integer")
	}
	private, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return Connection{}, nil, errors.New("SCRS_GITHUB_APP_PRIVATE_KEY_B64 is invalid base64")
	}
	config, _ := json.Marshal(map[string]any{"organization": org, "auth_type": authType, "app_id": app, "installation_id": installationID})
	credential, _ := json.Marshal(map[string]string{"private_key_pem": string(private), "webhook_secret": os.Getenv("SCRS_GITHUB_WEBHOOK_SECRET")})
	return Connection{Provider: "github", Config: config, Scope: scopeFromEnv("SCRS_GITHUB_REPOSITORY", org+"/*")}, credential, nil
}

func dockerFromEnv() (Connection, json.RawMessage, error) {
	namespace := os.Getenv("SCRS_DOCKERHUB_NAMESPACE")
	identifier := os.Getenv("SCRS_DOCKERHUB_IDENTIFIER")
	token := os.Getenv("SCRS_DOCKERHUB_TOKEN")
	if namespace == "" || identifier == "" || token == "" {
		return Connection{}, nil, errors.New("Docker Hub connection needs namespace, identifier and token")
	}
	config, _ := json.Marshal(map[string]string{"namespace": namespace, "identifier": identifier})
	credential, _ := json.Marshal(map[string]string{"token": token})
	return Connection{Provider: "dockerhub", Config: config, Scope: scopeFromEnv("SCRS_DOCKERHUB_IMAGE", "docker.io/"+namespace+"/*")}, credential, nil
}

func garFromEnv() (Connection, json.RawMessage, error) {
	project := os.Getenv("SCRS_GAR_PROJECT")
	location := os.Getenv("SCRS_GAR_LOCATION")
	keyB64 := os.Getenv("SCRS_GAR_SERVICE_ACCOUNT_JSON_B64")
	if project == "" || location == "" || keyB64 == "" {
		return Connection{}, nil, errors.New("GAR connection needs project, location and base64 service account JSON")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || !json.Valid(key) {
		return Connection{}, nil, errors.New("SCRS_GAR_SERVICE_ACCOUNT_JSON_B64 must contain JSON")
	}
	config, _ := json.Marshal(map[string]string{"project": project, "location": location})
	credential, _ := json.Marshal(map[string]json.RawMessage{"service_account_json": key})
	return Connection{Provider: "gar", Config: config, Scope: scopeFromEnv("SCRS_GAR_IMAGE", location+"-docker.pkg.dev/"+project+"/**")}, credential, nil
}

func scopeFromEnv(prefix, allPattern string) Scope {
	var s Scope
	if os.Getenv(prefix+"_MODE") == "all" {
		s.Include = []string{allPattern}
	} else {
		s.Include = splitCSV(os.Getenv(prefix + "_INCLUDE"))
	}
	s.Exclude = splitCSV(os.Getenv(prefix + "_EXCLUDE"))
	return s
}

func splitCSV(raw string) []string {
	var values []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}
