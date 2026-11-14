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
	"strconv"
	"strings"
)

var immutableSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// GitHubSnapshot resolves an immutable commit and downloads only from fixed
// GitHub origins. API credentials are never forwarded to the archive redirect.
func (a NativeAdapters) GitHubSnapshot(ctx context.Context, c Connection, secret json.RawMessage, repository, ref, commit string) ([]byte, string, bool, error) {
	parts := strings.Split(repository, "/")
	if c.Provider != "github" || !c.Enabled || len(parts) != 2 || !providerSegment.MatchString(parts[0]) || !providerSegment.MatchString(parts[1]) || !c.Scope.matchesResource(Resource{Type: "github_repo", Locator: repository}) {
		return nil, "", false, errors.New("repository is outside connection scope")
	}
	var cfg struct {
		Organization   string `json:"organization"`
		AuthType       string `json:"auth_type"`
		AppID          string `json:"app_id"`
		InstallationID int64  `json:"installation_id"`
	}
	var cred struct {
		Token      string `json:"token"`
		PrivateKey string `json:"private_key_pem"`
	}
	if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || !strings.EqualFold(parts[0], cfg.Organization) {
		return nil, "", false, errors.New("invalid GitHub snapshot configuration")
	}
	token := cred.Token
	base := strings.TrimSuffix(a.GitHubAPI, "/")
	if cfg.AuthType == "github_app" || cfg.AuthType == "" {
		jwt, err := githubJWT(cfg.AppID, []byte(cred.PrivateKey))
		if err != nil {
			return nil, "", false, err
		}
		data, err := a.request(ctx, "POST", base+"/app/installations/"+strconv.FormatInt(cfg.InstallationID, 10)+"/access_tokens", jwt, []byte(`{}`))
		if err != nil {
			return nil, "", false, err
		}
		var response struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(data, &response) != nil {
			return nil, "", false, errors.New("installation token response invalid")
		}
		token = response.Token
	}
	if token == "" {
		return nil, "", false, errors.New("GitHub token unavailable")
	}
	resolve := func(value string) (string, error) {
		data, err := a.request(ctx, "GET", base+"/repos/"+repository+"/commits/"+url.PathEscape(value), token, nil)
		if err != nil {
			return "", err
		}
		var result struct {
			SHA string `json:"sha"`
		}
		if json.Unmarshal(data, &result) != nil || !immutableSHA.MatchString(result.SHA) {
			return "", errors.New("invalid commit response")
		}
		return strings.ToLower(result.SHA), nil
	}
	target := commit
	if target == "" {
		target = ref
	}
	if target == "" {
		target = "HEAD"
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
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/repos/"+repository+"/tarball/"+resolved, nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	httpClient := a.Client
	if httpClient == nil {
		httpClient = NewNativeAdapters().Client
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", false, errors.New("archive request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return nil, "", false, errors.New("archive redirect not supplied")
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || location.Scheme != "https" || location.Host != "codeload.github.com" || location.User != nil {
		return nil, "", false, errors.New("archive redirect origin rejected")
	}
	archiveRequest, err := http.NewRequestWithContext(ctx, "GET", location.String(), nil)
	if err != nil {
		return nil, "", false, err
	}
	archive, err := client.Do(archiveRequest)
	if err != nil {
		return nil, "", false, errors.New("archive download failed")
	}
	defer archive.Body.Close()
	if archive.StatusCode != 200 {
		return nil, "", false, errors.New("archive download rejected")
	}
	data, err := io.ReadAll(io.LimitReader(archive.Body, (64<<20)+1))
	if err != nil {
		return nil, "", false, errors.New("archive download failed")
	}
	if len(data) > 64<<20 {
		return nil, "", false, fmt.Errorf("%w: archive exceeded 64 MiB download limit", ErrTooLarge)
	}
	return data, resolved, moved, nil
}
