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
)

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
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return nil, fmt.Errorf("%w: HTTP %d (check the API key and its BOM_UPLOAD and PROJECT_CREATION_UPLOAD permissions)", ErrRejected, resp.StatusCode)
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

// Check reads the server version without the key, then checks the key
// holds BOM upload permission by asking about an unknown event token.
func (c Client) Check(ctx context.Context) (string, error) {
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
	if _, err := c.do(ctx, http.MethodGet, "/api/v1/event/token/"+uuid.NewString(), nil); err != nil {
		return about.Version, err
	}
	return about.Version, nil
}
