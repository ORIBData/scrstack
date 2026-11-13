package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Providers lists every supported connection provider.
var Providers = []string{"github", "gitlab", "dockerhub", "gar", "harbor", "oci"}

func knownProvider(p string) bool {
	for _, v := range Providers {
		if v == p {
			return true
		}
	}
	return false
}

var registryHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
var repositoryPathPattern = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)

// groupPath accepts a GitLab group with optional subgroups ("team/platform").
func groupPath(v string) bool {
	if v == "" || len(v) > 255 {
		return false
	}
	for _, part := range strings.Split(v, "/") {
		if !providerSegment.MatchString(part) {
			return false
		}
	}
	return true
}

// httpsBase validates an operator-supplied API origin: HTTPS, no credentials,
// query or fragment. A path prefix is allowed for self-hosted installs.
func httpsBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 512 {
		return nil, errors.New("base URL must be an https origin without credentials or query")
	}
	return u, nil
}

type gitLabConfig struct {
	BaseURL string `json:"base_url"`
	Group   string `json:"group"`
}

func (c gitLabConfig) api() string {
	base := c.BaseURL
	if base == "" {
		base = "https://gitlab.com"
	}
	return strings.TrimSuffix(base, "/") + "/api/v4"
}

func parseGitLab(c Connection, secret json.RawMessage) (gitLabConfig, string, error) {
	var cfg gitLabConfig
	var cred struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !groupPath(cfg.Group) || strings.TrimSpace(cred.Token) == "" {
		return cfg, "", errors.New("GitLab connection configuration invalid")
	}
	if cfg.BaseURL != "" {
		if _, err := httpsBase(cfg.BaseURL); err != nil {
			return cfg, "", err
		}
	}
	return cfg, cred.Token, nil
}

// gitLab lists the group's projects, including subgroups, as gitlab_repo assets.
func (a NativeAdapters) gitLab(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	cfg, token, err := parseGitLab(c, secret)
	if err != nil {
		return nil, err
	}
	prefix := strings.ToLower(cfg.Group) + "/"
	var resources []Resource
	for page := 1; page <= 100; page++ {
		target := fmt.Sprintf("%s/groups/%s/projects?include_subgroups=true&archived=false&simple=true&per_page=100&page=%d", cfg.api(), url.PathEscape(cfg.Group), page)
		data, err := a.request(ctx, http.MethodGet, target, token, nil)
		if err != nil {
			return nil, err
		}
		var projects []struct {
			Path          string `json:"path_with_namespace"`
			DefaultBranch string `json:"default_branch"`
			Visibility    string `json:"visibility"`
		}
		if json.Unmarshal(data, &projects) != nil {
			return nil, errors.New("GitLab projects response invalid")
		}
		for _, p := range projects {
			if !strings.HasPrefix(strings.ToLower(p.Path), prefix) || !groupPath(p.Path) {
				continue
			}
			metadata, _ := json.Marshal(map[string]any{"private": p.Visibility != "public", "default_branch": p.DefaultBranch})
			resources = append(resources, Resource{Type: "gitlab_repo", Locator: p.Path, Metadata: metadata})
		}
		if len(projects) < 100 {
			return resources, nil
		}
	}
	return nil, errors.New("GitLab project pagination limit reached")
}

// gitLabSnapshot resolves an immutable commit and downloads its archive from
// the configured GitLab origin only; redirects are refused.
func (a NativeAdapters) gitLabSnapshot(ctx context.Context, c Connection, secret json.RawMessage, repository, ref, commit string) ([]byte, string, bool, error) {
	cfg, token, err := parseGitLab(c, secret)
	if err != nil {
		return nil, "", false, err
	}
	if !c.Enabled || !groupPath(repository) || !strings.HasPrefix(strings.ToLower(repository), strings.ToLower(cfg.Group)+"/") || !c.Scope.matchesResource(Resource{Type: "gitlab_repo", Locator: repository}) {
		return nil, "", false, errors.New("repository is outside connection scope")
	}
	project := cfg.api() + "/projects/" + url.PathEscape(repository)
	resolve := func(value string) (string, error) {
		data, err := a.request(ctx, http.MethodGet, project+"/repository/commits/"+url.PathEscape(value), token, nil)
		if err != nil {
			return "", err
		}
		var result struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &result) != nil || !immutableSHA.MatchString(result.ID) {
			return "", errors.New("invalid commit response")
		}
		return strings.ToLower(result.ID), nil
	}
	if ref == "HEAD" {
		data, err := a.request(ctx, http.MethodGet, project, token, nil)
		if err != nil {
			return nil, "", false, err
		}
		var info struct {
			DefaultBranch string `json:"default_branch"`
		}
		if json.Unmarshal(data, &info) != nil || info.DefaultBranch == "" {
			return nil, "", false, errors.New("GitLab project has no default branch")
		}
		ref = info.DefaultBranch
	}
	target := commit
	if target == "" {
		target = ref
	}
	if target == "" {
		return nil, "", false, errors.New("commit or ref required")
	}
	resolved, err := resolve(target)
	if err != nil {
		return nil, "", false, err
	}
	if commit != "" && !strings.EqualFold(commit, resolved) {
		return nil, "", false, errors.New("provider commit mismatch")
	}
	moved := false
	if commit != "" && ref != "" {
		current, err := resolve(ref)
		if err != nil {
			return nil, "", false, err
		}
		moved = current != resolved
	}
	data, err := a.download(ctx, project+"/repository/archive.tar.gz?sha="+resolved, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }, 64<<20)
	if err != nil {
		return nil, "", false, err
	}
	return data, resolved, moved, nil
}

// download fetches one capped body without following redirects.
func (a NativeAdapters) download(ctx context.Context, target string, auth func(*http.Request), limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("archive request invalid")
	}
	auth(req)
	httpClient := a.Client
	if httpClient == nil {
		httpClient = NewNativeAdapters().Client
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 0 // the caller's context bounds large downloads
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("archive download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("archive download returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("archive exceeded download limit")
	}
	return data, nil
}

// Snapshot fetches a source archive for any git provider.
func (a NativeAdapters) Snapshot(ctx context.Context, c Connection, secret json.RawMessage, repository, ref, commit string) ([]byte, string, bool, error) {
	switch c.Provider {
	case "github":
		return a.GitHubSnapshot(ctx, c, secret, repository, ref, commit)
	case "gitlab":
		return a.gitLabSnapshot(ctx, c, secret, repository, ref, commit)
	}
	return nil, "", false, errors.New("provider has no source repositories")
}

type harborConfig struct {
	URL      string `json:"url"`
	Project  string `json:"project"`
	Username string `json:"username"`
}

func parseHarbor(c Connection, secret json.RawMessage) (harborConfig, string, string, error) {
	var cfg harborConfig
	var cred struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !providerSegment.MatchString(cfg.Project) || cfg.Username == "" || len(cfg.Username) > 255 || cred.Token == "" {
		return cfg, "", "", errors.New("Harbor connection configuration invalid")
	}
	u, err := httpsBase(cfg.URL)
	if err != nil {
		return cfg, "", "", err
	}
	return cfg, strings.ToLower(u.Host), cred.Token, nil
}

// harbor lists one project's repositories through the Harbor v2 API.
func (a NativeAdapters) harbor(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	cfg, host, token, err := parseHarbor(c, secret)
	if err != nil {
		return nil, err
	}
	basic := func(r *http.Request) { r.SetBasicAuth(cfg.Username, token) }
	var resources []Resource
	for page := 1; page <= 100; page++ {
		target := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories?page=%d&page_size=100", strings.TrimSuffix(cfg.URL, "/"), url.PathEscape(cfg.Project), page)
		data, err := a.do(ctx, http.MethodGet, target, basic, nil)
		if err != nil {
			return nil, err
		}
		var repos []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &repos) != nil {
			return nil, errors.New("Harbor repositories response invalid")
		}
		for _, repo := range repos {
			name := strings.ToLower(repo.Name)
			if !strings.HasPrefix(name, strings.ToLower(cfg.Project)+"/") || !repositoryPathPattern.MatchString(name) {
				continue
			}
			resources = append(resources, Resource{Type: "container_image", Locator: host + "/" + name})
		}
		if len(repos) < 100 {
			return resources, nil
		}
	}
	return nil, errors.New("Harbor repository pagination limit reached")
}

type ociConfig struct {
	Registry     string   `json:"registry"`
	Namespace    string   `json:"namespace"`
	Username     string   `json:"username"`
	Repositories []string `json:"repositories"`
}

func parseOCI(c Connection, secret json.RawMessage) (ociConfig, authn.Authenticator, error) {
	var cfg ociConfig
	var cred struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !registryHostPattern.MatchString(cfg.Registry) || len(cfg.Repositories) > 1000 || (cfg.Namespace != "" && !repositoryPathPattern.MatchString(cfg.Namespace)) || (cfg.Username == "") != (cred.Token == "") {
		return cfg, nil, errors.New("OCI registry connection configuration invalid")
	}
	for _, r := range cfg.Repositories {
		if !repositoryPathPattern.MatchString(r) {
			return cfg, nil, errors.New("OCI repository names must be lowercase paths")
		}
	}
	if cfg.Username == "" {
		return cfg, authn.Anonymous, nil
	}
	return cfg, &authn.Basic{Username: cfg.Username, Password: cred.Token}, nil
}

// oci lists a generic OCI registry: the configured repositories, or the
// registry catalog (filtered to the namespace) when none are listed. Registries
// such as GHCR do not offer a catalog; list repositories explicitly there.
func (a NativeAdapters) oci(ctx context.Context, c Connection, secret json.RawMessage) ([]Resource, error) {
	cfg, auth, err := parseOCI(c, secret)
	if err != nil {
		return nil, err
	}
	names := cfg.Repositories
	if len(names) == 0 {
		registry, err := name.NewRegistry(cfg.Registry, name.StrictValidation)
		if err != nil {
			return nil, errors.New("invalid registry")
		}
		options := []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth)}
		if a.Client != nil && a.Client.Transport != nil {
			options = append(options, remote.WithTransport(a.Client.Transport))
		}
		if names, err = remote.Catalog(ctx, registry, options...); err != nil {
			return nil, errors.New("registry catalog unavailable; list repositories in the connection config")
		}
	}
	var resources []Resource
	for _, repo := range names {
		if !repositoryPathPattern.MatchString(repo) || (cfg.Namespace != "" && !strings.HasPrefix(repo, cfg.Namespace+"/")) {
			continue
		}
		resources = append(resources, Resource{Type: "container_image", Locator: cfg.Registry + "/" + repo})
		if len(resources) > 10000 {
			return nil, errors.New("registry inventory exceeds 10000 resources")
		}
	}
	return resources, nil
}

// validateProviderInput checks the newer providers' fields strictly.
func validateProviderInput(c Connection, credential json.RawMessage) error {
	switch c.Provider {
	case "gitlab":
		var cfg gitLabConfig
		var cred struct {
			Token string `json:"token"`
		}
		if decodeStrict(c.Config, &cfg) != nil || decodeStrict(credential, &cred) != nil {
			return errors.New("GitLab connection fields invalid")
		}
		if _, _, err := parseGitLab(c, credential); err != nil {
			return errors.New("GitLab connection fields invalid: group path, https base_url and token required")
		}
	case "harbor":
		var cfg harborConfig
		var cred struct {
			Token string `json:"token"`
		}
		if decodeStrict(c.Config, &cfg) != nil || decodeStrict(credential, &cred) != nil {
			return errors.New("Harbor connection fields invalid")
		}
		if _, _, _, err := parseHarbor(c, credential); err != nil {
			return errors.New("Harbor connection fields invalid: https url, project, username and token required")
		}
	case "oci":
		var cfg ociConfig
		var cred struct {
			Token string `json:"token"`
		}
		if decodeStrict(c.Config, &cfg) != nil || decodeStrict(credential, &cred) != nil {
			return errors.New("OCI registry connection fields invalid")
		}
		if _, _, err := parseOCI(c, credential); err != nil {
			return errors.New("OCI registry connection fields invalid: registry host, lowercase repositories, and username with token (or neither)")
		}
	default:
		return fmt.Errorf("unsupported provider %q", c.Provider)
	}
	return nil
}
