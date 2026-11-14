// Package taxii polls TAXII 2.1 collections (OpenCTI, MISP, commercial
// vendors, CISA AIS) for STIX objects.
package taxii

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/ORIBData/scrstack/internal/netguard"
)

// MediaType is the TAXII 2.1 media type for requests and responses.
const MediaType = "application/taxii+json;version=2.1"

// Feed is a collection's non-secret settings.
type Feed struct {
	APIRoot    string `json:"api_root"`
	Collection string `json:"collection"`
	// AuthType is none, api_key (Header carries the secret) or basic. A
	// client certificate may be added to any of them.
	AuthType string `json:"auth_type"`
	Header   string `json:"auth_header,omitempty"`
	// CAPEM optionally replaces the system roots for the server certificate.
	CAPEM    string `json:"ca_pem,omitempty"`
	PageSize int    `json:"page_size"`
}

// Secret is the sealed part of a feed.
type Secret struct {
	APIKey   string `json:"api_key,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	CertPEM  string `json:"cert_pem,omitempty"`
	KeyPEM   string `json:"key_pem,omitempty"`
}

// ClientCert reports a configured client certificate (CISA AIS uses one).
func (s Secret) ClientCert() bool { return s.CertPEM != "" }

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// forbiddenHeaders are set by the transport or select the request target.
var forbiddenHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "accept": true, "cookie": true}

// Validate checks settings and the secret they need.
func Validate(f Feed, s Secret) error {
	u, err := url.Parse(f.APIRoot)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(f.APIRoot) > 2048:
		return errors.New("api_root must be an https URL without credentials, query or fragment")
	case !strings.HasSuffix(u.Path, "/"):
		return errors.New("api_root must end with /")
	case f.Collection == "" || len(f.Collection) > 256 || strings.ContainsAny(f.Collection, "/?#"):
		return errors.New("collection must be a collection id")
	case f.PageSize < 1 || f.PageSize > 10000:
		return errors.New("page_size must be 1 to 10000")
	}
	switch f.AuthType {
	case "none":
		if s.APIKey != "" || s.Username != "" || s.Password != "" {
			return errors.New("auth none takes no api_key, username or password")
		}
	case "api_key":
		if s.APIKey == "" || len(s.APIKey) > 4096 || strings.ContainsAny(s.APIKey, "\r\n") {
			return errors.New("api_key auth needs an api_key")
		}
		if !headerName.MatchString(f.Header) || forbiddenHeaders[strings.ToLower(f.Header)] {
			return errors.New("auth_header must be a header name such as Authorization or X-API-Key")
		}
	case "basic":
		if s.Username == "" || strings.Contains(s.Username, ":") || len(s.Username) > 256 || len(s.Password) > 1024 || s.APIKey != "" {
			return errors.New("basic auth needs a username without a colon, and a password")
		}
	default:
		return errors.New("auth_type must be none, api_key or basic")
	}
	if (s.CertPEM == "") != (s.KeyPEM == "") {
		return errors.New("a client certificate needs both cert_pem and key_pem")
	}
	if s.CertPEM != "" {
		if _, err := tls.X509KeyPair([]byte(s.CertPEM), []byte(s.KeyPEM)); err != nil {
			return errors.New("cert_pem and key_pem are not a matching PEM certificate and key")
		}
	}
	if f.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(f.CAPEM)) {
		return errors.New("ca_pem holds no PEM certificates")
	}
	return nil
}

// Client reads one collection.
type Client struct {
	feed   Feed
	secret Secret
	http   *http.Client
}

// NewClient builds a client whose connections pass netguard; hosts in
// private may resolve to internal addresses (an OpenCTI on the same network).
func NewClient(f Feed, s Secret, private map[string]bool) (*Client, error) {
	if err := Validate(f, s); err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if f.CAPEM != "" {
		config.RootCAs = x509.NewCertPool()
		config.RootCAs.AppendCertsFromPEM([]byte(f.CAPEM))
	}
	if s.CertPEM != "" {
		cert, err := tls.X509KeyPair([]byte(s.CertPEM), []byte(s.KeyPEM))
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           netguard.DialContext(private),
		TLSClientConfig:       config,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	}
	// Redirects could carry the credential elsewhere; they are refused.
	client := &http.Client{Transport: transport, Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{feed: f, secret: s, http: client}, nil
}

// Page is one objects response.
type Page struct {
	Objects []json.RawMessage
	More    bool
	Next    string
	// AddedLast is X-TAXII-Date-Added-Last: the next poll's added_after.
	AddedLast string
}

// Collection is the collection resource, for checking a feed's settings.
type Collection struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	CanRead  bool   `json:"can_read"`
	CanWrite bool   `json:"can_write"`
}

func (c *Client) collectionURL() string {
	return c.feed.APIRoot + "collections/" + url.PathEscape(c.feed.Collection) + "/"
}

func (c *Client) get(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", MediaType)
	switch c.feed.AuthType {
	case "api_key":
		req.Header.Set(c.feed.Header, c.secret.APIKey)
	case "basic":
		req.SetBasicAuth(c.secret.Username, c.secret.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TAXII server unreachable: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("TAXII server refused the credentials (HTTP %d)", resp.StatusCode)
	case http.StatusNotFound:
		return nil, errors.New("TAXII collection not found (HTTP 404); check api_root and collection")
	case http.StatusNotAcceptable, http.StatusUnsupportedMediaType:
		return nil, fmt.Errorf("TAXII server does not offer TAXII 2.1 (HTTP %d)", resp.StatusCode)
	case http.StatusTooManyRequests:
		return nil, errors.New("TAXII server rate limit reached (HTTP 429)")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("TAXII server redirected (HTTP %d); set api_root to the final URL", resp.StatusCode)
	}
	return nil, fmt.Errorf("TAXII server returned HTTP %d", resp.StatusCode)
}

// Check reads the collection resource.
func (c *Client) Check(ctx context.Context) (Collection, error) {
	var out Collection
	resp, err := c.get(ctx, c.collectionURL())
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil {
		return out, errors.New("TAXII collection response is not JSON")
	}
	return out, nil
}

// Objects fetches one page of indicator objects added after addedAfter, or
// the page that next names.
func (c *Client) Objects(ctx context.Context, addedAfter, next string) (Page, error) {
	query := url.Values{"limit": {strconv.Itoa(c.feed.PageSize)}, "match[type]": {"indicator"}}
	if next != "" {
		query.Set("next", next)
	}
	if addedAfter != "" {
		query.Set("added_after", addedAfter)
	}
	resp, err := c.get(ctx, c.collectionURL()+"objects/?"+query.Encode())
	if err != nil {
		return Page{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, intelligence.MaxSTIXBytes+1))
	if err != nil {
		return Page{}, fmt.Errorf("TAXII response read failed: %w", err)
	}
	if len(body) > intelligence.MaxSTIXBytes {
		return Page{}, errors.New("TAXII page is over 32 MiB; lower page_size")
	}
	var envelope struct {
		More    bool              `json:"more"`
		Next    string            `json:"next"`
		Objects []json.RawMessage `json:"objects"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return Page{}, errors.New("TAXII response is not a JSON envelope")
	}
	if len(envelope.Next) > 1024 {
		return Page{}, errors.New("TAXII next token is too long")
	}
	page := Page{Objects: envelope.Objects, More: envelope.More, Next: envelope.Next}
	if last := resp.Header.Get("X-TAXII-Date-Added-Last"); last != "" {
		if _, err := time.Parse(time.RFC3339Nano, last); err == nil {
			page.AddedLast = last
		}
	}
	return page, nil
}
