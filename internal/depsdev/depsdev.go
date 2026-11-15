// Package depsdev reads package licences and published versions from the
// deps.dev API v3 (LIC-001 source "metadata", VUL-008 version lists).
package depsdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/netguard"
)

// DefaultURL is the public deps.dev API.
const DefaultURL = "https://api.deps.dev/v3"

// ErrNotFound means deps.dev does not know the package or version.
var ErrNotFound = errors.New("package not known to deps.dev")

// System maps an OSV ecosystem to a deps.dev system; ok is false for
// ecosystems deps.dev does not cover (OS packages, Pub, CocoaPods, SwiftPM).
func System(ecosystem string) (string, bool) {
	base, _, _ := strings.Cut(ecosystem, ":")
	switch base {
	case "npm":
		return "NPM", true
	case "Go":
		return "GO", true
	case "Maven":
		return "MAVEN", true
	case "PyPI":
		return "PYPI", true
	case "crates.io":
		return "CARGO", true
	case "NuGet":
		return "NUGET", true
	case "RubyGems":
		return "RUBYGEMS", true
	}
	return "", false
}

// Client calls deps.dev.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client whose connections refuse private addresses unless
// the host is listed.
func New(base string, private map[string]bool) Client {
	if base == "" {
		base = DefaultURL
	}
	transport := &http.Transport{DialContext: netguard.DialContext(private), TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxIdleConnsPerHost: 8}
	return Client{BaseURL: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c Client) get(ctx context.Context, path string, out any) error {
	request, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "scrs")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return errors.New("deps.dev unavailable")
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case response.StatusCode != http.StatusOK:
		return fmt.Errorf("deps.dev returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
}

// Licenses returns the SPDX expressions deps.dev lists for a version.
// "non-standard" entries are licences deps.dev could not identify.
func (c Client) Licenses(ctx context.Context, system, name, version string) ([]string, error) {
	var v struct {
		Licenses []string `json:"licenses"`
	}
	path := "/systems/" + url.PathEscape(strings.ToLower(system)) + "/packages/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version)
	if err := c.get(ctx, path, &v); err != nil {
		return nil, err
	}
	if v.Licenses == nil {
		v.Licenses = []string{}
	}
	return v.Licenses, nil
}

// Versions lists a package's published versions, excluding those the
// registry marks deprecated.
func (c Client) Versions(ctx context.Context, system, name string) ([]string, error) {
	var p struct {
		Versions []struct {
			Key struct {
				Version string `json:"version"`
			} `json:"versionKey"`
			Deprecated bool `json:"isDeprecated"`
		} `json:"versions"`
	}
	path := "/systems/" + url.PathEscape(strings.ToLower(system)) + "/packages/" + url.PathEscape(name)
	if err := c.get(ctx, path, &p); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(p.Versions))
	for _, v := range p.Versions {
		if !v.Deprecated && v.Key.Version != "" {
			out = append(out, v.Key.Version)
		}
	}
	if len(out) > 20000 {
		out = out[len(out)-20000:]
	}
	return out, nil
}
