// Package dtrack pushes SCRS-generated CycloneDX SBOMs to OWASP
// Dependency-Track (P2, section 15.1) through its REST API. SCRS never
// depends on Dependency-Track being reachable: uploads are queued and
// retried, and a failure never affects an assessment.
package dtrack

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/netguard"
	"github.com/google/uuid"
)

// MaxBOM bounds the SBOM size sent in one upload.
const MaxBOM = 32 << 20

var (
	// ErrRejected is a permanent refusal (bad key, missing permission,
	// invalid project): retrying cannot help until the settings change.
	ErrRejected = errors.New("dependency-track rejected the request")
	// ErrUnavailable is a transient failure (network, 429, 5xx).
	ErrUnavailable = errors.New("dependency-track unavailable")
	// ErrForbidden and ErrNotFound refine ErrRejected for 403 and 404, so a
	// caller can tell a missing permission or project from a bad key.
	ErrForbidden = errors.New("permission missing")
	ErrNotFound  = errors.New("not found")
)

// RequiredPermissions are what the key needs to push SBOMs.
var RequiredPermissions = []string{"BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"}

// Client talks to one Dependency-Track API server.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// NewHTTPClient connects only to addresses netguard allows: public
// addresses over https, or the named private hosts (an internal
// Dependency-Track) over http or https. Redirects are not followed.
func NewHTTPClient(private map[string]bool) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           netguard.DialContext(private),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ValidURL checks a Dependency-Track base URL: https, or http for a named
// private host; no credentials, query or fragment.
func ValidURL(raw string, private map[string]bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 500 {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return private[strings.ToLower(u.Hostname())]
	}
	return false
}

func (c Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("X-Api-Key", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// Never echo the URL error verbatim: it can carry the host's
		// internal details, but not the key, which is a header.
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, describe(err))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return data, nil
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode == 403:
		return nil, fmt.Errorf("%w: %w: HTTP 403 (the API key lacks a permission this call needs)", ErrRejected, ErrForbidden)
	case resp.StatusCode == 401:
		return nil, fmt.Errorf("%w: HTTP 401 (the API key is not valid)", ErrRejected)
	case resp.StatusCode == 404:
		return nil, fmt.Errorf("%w: %w: HTTP 404", ErrRejected, ErrNotFound)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("%w: HTTP %d redirect (set the API base URL itself)", ErrRejected, resp.StatusCode)
	}
	return nil, fmt.Errorf("%w: HTTP %d", ErrRejected, resp.StatusCode)
}

func describe(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, netguard.ErrBlocked):
		return "address not allowed (add the host to SCRS_DTRACK_PRIVATE_HOSTS for an internal server)"
	}
	return "connection failed"
}

// Upload is one BOM upload.
type Upload struct {
	ProjectName    string
	ProjectVersion string
	Parent         *uuid.UUID
	BOM            []byte
}

// Upload sends a CycloneDX BOM with PUT /api/v1/bom, creating the project
// if needed, and returns Dependency-Track's processing token.
func (c Client) Upload(ctx context.Context, u Upload) (string, error) {
	if len(u.BOM) == 0 || len(u.BOM) > MaxBOM {
		return "", fmt.Errorf("%w: SBOM empty or larger than %d bytes", ErrRejected, MaxBOM)
	}
	body := map[string]any{"projectName": u.ProjectName, "projectVersion": u.ProjectVersion, "autoCreate": true, "bom": base64.StdEncoding.EncodeToString(u.BOM)}
	if u.Parent != nil {
		body["parentUUID"] = u.Parent.String()
	}
	data, err := c.do(ctx, http.MethodPut, "/api/v1/bom", body)
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(data, &out)
	if len(out.Token) > 64 {
		out.Token = ""
	}
	return out.Token, nil
}

// Version reads the server version from the unauthenticated /api/version.
func (c Client) Version(ctx context.Context) (string, error) {
	data, err := Client{BaseURL: c.BaseURL, HTTP: c.HTTP}.do(ctx, http.MethodGet, "/api/version", nil)
	if err != nil {
		return "", err
	}
	var about struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &about) != nil || about.Version == "" {
		return "", fmt.Errorf("%w: /api/version did not answer like Dependency-Track", ErrRejected)
	}
	if len(about.Version) > 32 {
		about.Version = about.Version[:32]
	}
	return about.Version, nil
}

// CheckResult is what Check learned about the server and the key.
type CheckResult struct {
	Version     string
	Permissions []string
	Missing     []string
}

// Check reads the server version without the key, then reads the key's
// permissions with GET /api/v1/team/self (the key must belong to a team) and
// requires RequiredPermissions. Missing permissions are an ErrRejected error
// that names them; the result is returned either way.
func (c Client) Check(ctx context.Context) (CheckResult, error) {
	var out CheckResult
	version, err := c.Version(ctx)
	out.Version = version
	if err != nil {
		return out, err
	}
	data, err := c.do(ctx, http.MethodGet, "/api/v1/team/self", nil)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return out, fmt.Errorf("%w: the key does not belong to a team; use a team API key", ErrRejected)
		}
		return out, err
	}
	var team struct {
		Permissions []struct {
			Name string `json:"name"`
		} `json:"permissions"`
	}
	if json.Unmarshal(data, &team) != nil {
		return out, fmt.Errorf("%w: /api/v1/team/self did not answer like Dependency-Track", ErrRejected)
	}
	have := map[string]bool{}
	for _, p := range team.Permissions {
		have[p.Name] = true
		out.Permissions = append(out.Permissions, p.Name)
	}
	for _, need := range RequiredPermissions {
		if !have[need] {
			out.Missing = append(out.Missing, need)
		}
	}
	if len(out.Missing) > 0 {
		return out, fmt.Errorf("%w: the key's team lacks %s", ErrRejected, strings.Join(out.Missing, ", "))
	}
	return out, nil
}

// Processing reports whether Dependency-Track is still working on an upload
// token (GET /api/v1/event/token/{token}). It cannot say whether the work
// succeeded: false means finished or failed.
func (c Client) Processing(ctx context.Context, token string) (bool, error) {
	if _, err := uuid.Parse(token); err != nil {
		return false, fmt.Errorf("%w: token is not a UUID", ErrRejected)
	}
	data, err := c.do(ctx, http.MethodGet, "/api/v1/event/token/"+token, nil)
	if err != nil {
		return false, err
	}
	var out struct {
		Processing bool `json:"processing"`
	}
	if json.Unmarshal(data, &out) != nil {
		return false, fmt.Errorf("%w: unexpected token response", ErrRejected)
	}
	return out.Processing, nil
}

// Project is the part of a Dependency-Track project SCRS reads.
type Project struct {
	UUID string
	// LastBOMImport is when Dependency-Track last finished importing a BOM;
	// zero when it never has.
	LastBOMImport time.Time
}

// Project finds a project by name and version (GET /api/v1/project/lookup,
// needs VIEW_PORTFOLIO). ErrNotFound when it does not exist, ErrForbidden
// when the key cannot read projects.
func (c Client) Project(ctx context.Context, name, version string) (Project, error) {
	q := url.Values{"name": {name}, "version": {version}}
	data, err := c.do(ctx, http.MethodGet, "/api/v1/project/lookup?"+q.Encode(), nil)
	if err != nil {
		return Project{}, err
	}
	var raw struct {
		UUID          string `json:"uuid"`
		LastBomImport *int64 `json:"lastBomImport"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.UUID == "" {
		return Project{}, fmt.Errorf("%w: unexpected project response", ErrRejected)
	}
	p := Project{UUID: raw.UUID}
	if raw.LastBomImport != nil && *raw.LastBomImport > 0 {
		p.LastBOMImport = time.UnixMilli(*raw.LastBomImport).UTC()
	}
	return p, nil
}
