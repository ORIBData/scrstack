package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// Client calls the scrs-sast service from the worker and the API.
type Client struct {
	URL, Token string
	HTTP       *http.Client
}

// ErrBusy is the service's 429: its slots serve other assessments.
var ErrBusy = errors.New("SAST service busy")

// NewClient returns a client for the service at url.
func NewClient(url, token string) *Client {
	return &Client{URL: strings.TrimRight(url, "/"), Token: token, HTTP: &http.Client{Timeout: 50 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("SAST service unavailable")
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrBusy
	case resp.StatusCode != http.StatusOK:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("SAST service returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// Analyze sends a source archive (tar.gz) and the request.
func (c *Client) Analyze(ctx context.Context, archive []byte, r Request) (Response, error) {
	var buf bytes.Buffer
	m := multipart.NewWriter(&buf)
	part, err := m.CreateFormField("request")
	if err != nil {
		return Response{}, err
	}
	if err := json.NewEncoder(part).Encode(r); err != nil {
		return Response{}, err
	}
	file, err := m.CreateFormFile("archive", "source.tar.gz")
	if err != nil {
		return Response{}, err
	}
	if _, err := file.Write(archive); err != nil {
		return Response{}, err
	}
	if err := m.Close(); err != nil {
		return Response{}, err
	}
	var out Response
	return out, c.do(ctx, "POST", "/analyze", m.FormDataContentType(), &buf, &out)
}

// Analyzers lists the bundled analyzers and the reachability tool.
func (c *Client) Analyzers(ctx context.Context) ([]Info, *Info, error) {
	var out struct {
		Analyzers    []Info `json:"analyzers"`
		Reachability *Info  `json:"reachability"`
	}
	err := c.do(ctx, "GET", "/analyzers", "", nil, &out)
	return out.Analyzers, out.Reachability, err
}

// Validate compiles OpenGrep rules in the service without scanning.
func (c *Client) Validate(ctx context.Context, rules []byte) (bool, string, error) {
	var out struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	err := c.do(ctx, "POST", "/rules:validate", "application/yaml", bytes.NewReader(rules), &out)
	return out.Valid, out.Error, err
}
