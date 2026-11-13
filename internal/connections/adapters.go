package connections

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

type NativeAdapters struct {
	Client    *http.Client
	GitHubAPI string // overridden only by tests
	DockerAPI string // overridden only by tests
	GoogleAPI string // overridden only by tests
	// RegistryHost pins image pulls to one plain-HTTP registry; tests only.
	RegistryHost string
}

var providerSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func NewNativeAdapters() NativeAdapters {
	return NativeAdapters{Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		GitHubAPI: "https://api.github.com", DockerAPI: "https://hub.docker.com", GoogleAPI: "https://artifactregistry.googleapis.com"}
}

func (a NativeAdapters) List(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	switch c.Provider {
	case "github":
		return a.github(ctx, c, secret)
	case "dockerhub":
		return a.dockerHub(ctx, c, secret)
	case "gar":
		return a.gar(ctx, c, secret)
	default:
		return nil, errors.New("no native adapter for provider")
	}
}

func (a NativeAdapters) request(ctx context.Context, method, target, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("provider request invalid")
	}
	req.Header.Set("Accept", "application/json")
	if strings.HasPrefix(target, strings.TrimSuffix(a.GitHubAPI, "/")+"/") {
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := a.Client
	if client == nil {
		client = NewNativeAdapters().Client
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("provider request failed; check network, TLS and credential")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return nil, errors.New("provider response failed or exceeded 4 MiB")
	}
	return data, nil
}

func (a NativeAdapters) github(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	var cfg struct {
		Organization   string `json:"organization"`
		AuthType       string `json:"auth_type"`
		AppID          string `json:"app_id"`
		InstallationID int64  `json:"installation_id"`
	}
	var cred struct {
		PrivateKeyPEM string `json:"private_key_pem"`
		Token         string `json:"token"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !providerSegment.MatchString(cfg.Organization) {
		return nil, errors.New("GitHub connection configuration invalid")
	}
	if cfg.AuthType == "" { // Existing app connections seeded before auth_type was recorded.
		cfg.AuthType = "github_app"
	}
	if cfg.AuthType == "fine_grained_pat" || cfg.AuthType == "oauth_app_token" {
		if strings.TrimSpace(cred.Token) == "" {
			return nil, errors.New("GitHub token is required for selected auth type")
		}
		return a.githubUserRepositories(ctx, cfg.Organization, cred.Token)
	}
	if cfg.AuthType != "github_app" || cfg.AppID == "" || cfg.InstallationID <= 0 || cred.PrivateKeyPEM == "" {
		return nil, errors.New("GitHub App connection configuration invalid")
	}
	jwt, err := githubJWT(cfg.AppID, []byte(cred.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(a.GitHubAPI, "/")
	data, err := a.request(ctx, http.MethodPost, base+"/app/installations/"+strconv.FormatInt(cfg.InstallationID, 10)+"/access_tokens", jwt, []byte(`{}`))
	if err != nil {
		return nil, err
	}
	var token struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &token) != nil || token.Token == "" {
		return nil, errors.New("GitHub installation token response invalid")
	}
	var resources []Resource
	for page := 1; page <= 100; page++ {
		url := fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", base, page)
		data, err := a.request(ctx, http.MethodGet, url, token.Token, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Repositories []struct {
				FullName      string `json:"full_name"`
				Private       bool   `json:"private"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repositories"`
		}
		if json.Unmarshal(data, &result) != nil {
			return nil, errors.New("GitHub repositories response invalid")
		}
		for _, repo := range result.Repositories {
			parts := strings.Split(repo.FullName, "/")
			if len(parts) == 2 && strings.EqualFold(parts[0], cfg.Organization) && providerSegment.MatchString(parts[1]) {
				metadata, _ := json.Marshal(map[string]any{"private": repo.Private, "default_branch": repo.DefaultBranch})
				resources = append(resources, Resource{Type: "github_repo", Locator: repo.FullName, Metadata: metadata})
			}
		}
		if len(result.Repositories) < 100 {
			return resources, nil
		}
	}
	return nil, errors.New("GitHub repository pagination limit reached")
}

// User tokens list only repositories the authorized user, app and organization
// policies permit. Filtering by owner avoids importing personal repositories.
func (a NativeAdapters) githubUserRepositories(ctx context.Context, organization, token string) ([]Resource, error) {
	base := strings.TrimSuffix(a.GitHubAPI, "/")
	var resources []Resource
	for page := 1; page <= 100; page++ {
		target := fmt.Sprintf("%s/user/repos?visibility=all&per_page=100&page=%d", base, page)
		data, err := a.request(ctx, http.MethodGet, target, token, nil)
		if err != nil {
			return nil, err
		}
		var repos []struct {
			FullName      string `json:"full_name"`
			Private       bool   `json:"private"`
			DefaultBranch string `json:"default_branch"`
			Owner         struct {
				Login string `json:"login"`
			} `json:"owner"`
		}
		if json.Unmarshal(data, &repos) != nil {
			return nil, errors.New("GitHub user repositories response invalid")
		}
		for _, repo := range repos {
			parts := strings.Split(repo.FullName, "/")
			if len(parts) == 2 && strings.EqualFold(parts[0], organization) && strings.EqualFold(repo.Owner.Login, organization) && providerSegment.MatchString(parts[1]) {
				metadata, _ := json.Marshal(map[string]any{"private": repo.Private, "default_branch": repo.DefaultBranch})
				resources = append(resources, Resource{Type: "github_repo", Locator: repo.FullName, Metadata: metadata})
			}
		}
		if len(repos) < 100 {
			return resources, nil
		}
	}
	return nil, errors.New("GitHub repository pagination limit reached")
}

func githubJWT(appID string, keyPEM []byte) (string, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", errors.New("GitHub App private key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = parsed
	} else if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if key == nil {
		return "", errors.New("GitHub App private key must be RSA")
	}
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", errors.New("GitHub App JWT signing failed")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (a NativeAdapters) dockerHub(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	var cfg struct {
		Namespace  string `json:"namespace"`
		Identifier string `json:"identifier"`
	}
	var cred struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !providerSegment.MatchString(cfg.Namespace) || cfg.Identifier == "" || cred.Token == "" {
		return nil, errors.New("Docker Hub connection configuration invalid")
	}
	base := strings.TrimSuffix(a.DockerAPI, "/")
	loginBody, _ := json.Marshal(map[string]string{"identifier": cfg.Identifier, "secret": cred.Token})
	data, err := a.request(ctx, http.MethodPost, base+"/v2/auth/token", "", loginBody)
	if err != nil {
		return nil, err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(data, &token) != nil || token.AccessToken == "" {
		return nil, errors.New("Docker Hub bearer token response invalid")
	}
	var resources []Resource
	for page := 1; page <= 100; page++ {
		target := fmt.Sprintf("%s/v2/namespaces/%s/repositories?page_size=100&page=%d", base, url.PathEscape(cfg.Namespace), page)
		data, err := a.request(ctx, http.MethodGet, target, token.AccessToken, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Results []struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
				Private   bool   `json:"is_private"`
			} `json:"results"`
			Next string `json:"next"`
		}
		if json.Unmarshal(data, &result) != nil {
			return nil, errors.New("Docker Hub repositories response invalid")
		}
		for _, repo := range result.Results {
			if repo.Namespace != "" && repo.Namespace != cfg.Namespace {
				return nil, errors.New("Docker Hub returned an unexpected namespace")
			}
			if !providerSegment.MatchString(repo.Name) {
				return nil, errors.New("Docker Hub returned an invalid repository name")
			}
			metadata, _ := json.Marshal(map[string]any{"private": repo.Private})
			resources = append(resources, Resource{Type: "container_image", Locator: "docker.io/" + cfg.Namespace + "/" + repo.Name, Metadata: metadata})
		}
		if result.Next == "" {
			return resources, nil
		}
	}
	return nil, errors.New("Docker Hub repository pagination limit reached")
}

func (a NativeAdapters) gar(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	var cfg struct {
		Project  string `json:"project"`
		Location string `json:"location"`
	}
	var cred struct {
		ServiceAccountJSON json.RawMessage `json:"service_account_json"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !providerSegment.MatchString(cfg.Project) || !providerSegment.MatchString(cfg.Location) {
		return nil, errors.New("GAR connection configuration invalid")
	}
	var keyInfo struct {
		Type     string `json:"type"`
		TokenURI string `json:"token_uri"`
	}
	if json.Unmarshal(cred.ServiceAccountJSON, &keyInfo) != nil || keyInfo.Type != "service_account" || keyInfo.TokenURI != "https://oauth2.googleapis.com/token" {
		return nil, errors.New("GAR credential must be a Google service account JSON key with the official token URI")
	}
	googleCreds, err := google.CredentialsFromJSONWithType(ctx, cred.ServiceAccountJSON, google.ServiceAccount, "https://www.googleapis.com/auth/cloud-platform.read-only")
	if err != nil {
		return nil, errors.New("GAR service account JSON invalid")
	}
	token, err := googleCreds.TokenSource.Token()
	if err != nil {
		return nil, errors.New("GAR OAuth token request failed")
	}
	base := strings.TrimSuffix(a.GoogleAPI, "/")
	parent := "projects/" + cfg.Project + "/locations/" + cfg.Location
	var resources []Resource
	pageToken := ""
	for page := 0; page < 100; page++ {
		target := base + "/v1/" + parent + "/repositories?pageSize=100&pageToken=" + url.QueryEscape(pageToken)
		data, err := a.request(ctx, http.MethodGet, target, token.AccessToken, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Repositories []struct {
				Name   string `json:"name"`
				Format string `json:"format"`
			} `json:"repositories"`
			Next string `json:"nextPageToken"`
		}
		if json.Unmarshal(data, &result) != nil {
			return nil, errors.New("GAR repositories response invalid")
		}
		for _, repository := range result.Repositories {
			if repository.Format != "DOCKER" || !strings.HasPrefix(repository.Name, parent+"/repositories/") {
				continue
			}
			images, err := a.garImages(ctx, base, repository.Name, token.AccessToken, cfg.Project, cfg.Location)
			if err != nil {
				return nil, err
			}
			resources = append(resources, images...)
			if len(resources) > 10000 {
				return nil, errors.New("GAR inventory exceeds 10000 resources")
			}
		}
		if result.Next == "" {
			return resources, nil
		}
		pageToken = result.Next
	}
	return nil, errors.New("GAR repository pagination limit reached")
}

func (a NativeAdapters) garImages(ctx context.Context, base, repository, token, project, location string) ([]Resource, error) {
	seen := map[string]bool{}
	var resources []Resource
	pageToken := ""
	for page := 0; page < 100; page++ {
		target := base + "/v1/" + repository + "/dockerImages?pageSize=100&pageToken=" + url.QueryEscape(pageToken)
		data, err := a.request(ctx, http.MethodGet, target, token, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			DockerImages []struct {
				URI string `json:"uri"`
			} `json:"dockerImages"`
			Next string `json:"nextPageToken"`
		}
		if json.Unmarshal(data, &result) != nil {
			return nil, errors.New("GAR docker images response invalid")
		}
		for _, image := range result.DockerImages {
			locator := strings.Split(image.URI, "@")[0]
			repoName := strings.TrimPrefix(repository, "projects/"+project+"/locations/"+location+"/repositories/")
			if !strings.HasPrefix(locator, location+"-docker.pkg.dev/"+project+"/"+repoName+"/") || seen[locator] {
				continue
			}
			seen[locator] = true
			resources = append(resources, Resource{Type: "container_image", Locator: locator})
		}
		if result.Next == "" {
			return resources, nil
		}
		pageToken = result.Next
	}
	return nil, errors.New("GAR image pagination limit reached")
}
