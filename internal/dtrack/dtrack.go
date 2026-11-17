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

// Permissions SCRS may need, by feature. Uploading always needs BasePermissions.
var (
	BasePermissions    = []string{"BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"}
	ImportPermissions  = []string{"VIEW_PORTFOLIO", "VIEW_VULNERABILITY"}
	TriagePermissions  = []string{"VULNERABILITY_ANALYSIS"}
	TaggingPermissions = []string{"PORTFOLIO_MANAGEMENT"}
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

// maxResponse bounds ordinary answers; a project's findings may be larger.
const (
	maxResponse = 1 << 20
	maxFindings = 32 << 20
)

func (c Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	return c.doLimit(ctx, method, path, body, maxResponse)
}

func (c Client) doLimit(ctx context.Context, method, path string, body any, limit int64) ([]byte, error) {
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
	data, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: response larger than %d bytes", ErrRejected, limit)
	}
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
	// IsLatest marks this version as the project's latest (the default
	// branch). Tags replace the project's tags and need PORTFOLIO_MANAGEMENT.
	IsLatest bool
	Tags     []string
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
	if u.IsLatest {
		body["isLatest"] = true
	}
	if len(u.Tags) > 0 {
		tags := make([]map[string]string, len(u.Tags))
		for i, name := range u.Tags {
			tags[i] = map[string]string{"name": name}
		}
		body["projectTags"] = tags
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
// requires every permission in required. Missing permissions are an ErrRejected error
// that names them; the result is returned either way.
func (c Client) Check(ctx context.Context, required []string) (CheckResult, error) {
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
	for _, need := range required {
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

// Finding is one vulnerability Dependency-Track reports for a project,
// reduced to what SCRS stores. IDs holds the vulnerability's own ID and
// every alias.
type Finding struct {
	ComponentUUID     string
	ComponentName     string
	ComponentGroup    string
	ComponentVersion  string
	PURL              string
	VulnerabilityUUID string
	VulnID            string
	Source            string
	Title             string
	Severity          string
	CVSS              float64
	CWEs              []int
	IDs               []string
	Analyzer          string
	ReferenceURL      string
	AnalysisState     string
	Suppressed        bool
}

// Findings reads a project's findings, suppressed ones included
// (GET /api/v1/finding/project/{uuid}, needs VIEW_VULNERABILITY). The answer
// is bounded, and a malformed entry is skipped rather than failing the sync.
func (c Client) Findings(ctx context.Context, project string) ([]Finding, error) {
	if _, err := uuid.Parse(project); err != nil {
		return nil, fmt.Errorf("%w: project is not a UUID", ErrRejected)
	}
	data, err := c.doLimit(ctx, http.MethodGet, "/api/v1/finding/project/"+project+"?suppressed=true", nil, maxFindings)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Component struct {
			UUID    string `json:"uuid"`
			Name    string `json:"name"`
			Group   string `json:"group"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"component"`
		Vulnerability struct {
			UUID     string   `json:"uuid"`
			Source   string   `json:"source"`
			VulnID   string   `json:"vulnId"`
			Title    string   `json:"title"`
			Severity string   `json:"severity"`
			CVSSV3   *float64 `json:"cvssV3BaseScore"`
			CVSSV2   *float64 `json:"cvssV2BaseScore"`
			CWEs     []struct {
				ID int `json:"cweId"`
			} `json:"cwes"`
			Aliases []map[string]any `json:"aliases"`
		} `json:"vulnerability"`
		Analysis struct {
			State      string `json:"state"`
			Suppressed bool   `json:"isSuppressed"`
		} `json:"analysis"`
		Attribution struct {
			Analyzer     string `json:"analyzerIdentity"`
			ReferenceURL string `json:"referenceUrl"`
		} `json:"attribution"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: unexpected findings response", ErrRejected)
	}
	out := make([]Finding, 0, len(raw))
	for _, r := range raw {
		if _, err := uuid.Parse(r.Component.UUID); err != nil {
			continue
		}
		if _, err := uuid.Parse(r.Vulnerability.UUID); err != nil || r.Vulnerability.VulnID == "" {
			continue
		}
		f := Finding{
			ComponentUUID: r.Component.UUID, ComponentName: r.Component.Name, ComponentGroup: r.Component.Group, ComponentVersion: r.Component.Version, PURL: r.Component.PURL,
			VulnerabilityUUID: r.Vulnerability.UUID, VulnID: r.Vulnerability.VulnID, Source: r.Vulnerability.Source, Title: r.Vulnerability.Title,
			Severity: strings.ToLower(r.Vulnerability.Severity), Analyzer: r.Attribution.Analyzer, ReferenceURL: r.Attribution.ReferenceURL,
			AnalysisState: r.Analysis.State, Suppressed: r.Analysis.Suppressed,
		}
		switch {
		case r.Vulnerability.CVSSV3 != nil:
			f.CVSS = *r.Vulnerability.CVSSV3
		case r.Vulnerability.CVSSV2 != nil:
			f.CVSS = *r.Vulnerability.CVSSV2
		}
		for _, cwe := range r.Vulnerability.CWEs {
			f.CWEs = append(f.CWEs, cwe.ID)
		}
		f.IDs = append(f.IDs, r.Vulnerability.VulnID)
		for _, alias := range r.Vulnerability.Aliases {
			for _, v := range alias {
				if id, ok := v.(string); ok && id != "" && len(id) <= 128 {
					f.IDs = append(f.IDs, id)
				}
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// Analysis is a triage decision written to Dependency-Track.
type Analysis struct {
	Project, Component, Vulnerability string
	State, Justification, Response    string
	Details, Comment                  string
	Suppressed                        bool
}

// SetAnalysis records an analysis decision (PUT /api/v1/analysis, needs
// VULNERABILITY_ANALYSIS). Each call also adds a comment to the audit trail.
func (c Client) SetAnalysis(ctx context.Context, a Analysis) error {
	for _, id := range []string{a.Project, a.Component, a.Vulnerability} {
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("%w: analysis target is not a UUID", ErrRejected)
		}
	}
	body := map[string]any{"project": a.Project, "component": a.Component, "vulnerability": a.Vulnerability, "analysisState": a.State, "analysisJustification": orNotSet(a.Justification), "analysisResponse": orNotSet(a.Response), "isSuppressed": a.Suppressed}
	if a.Details != "" {
		body["analysisDetails"] = a.Details
	}
	if a.Comment != "" {
		body["comment"] = a.Comment
	}
	_, err := c.do(ctx, http.MethodPut, "/api/v1/analysis", body)
	return err
}

func orNotSet(s string) string {
	if s == "" {
		return "NOT_SET"
	}
	return s
}
