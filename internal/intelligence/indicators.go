package intelligence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Indicator struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	ValidUntil time.Time `json:"valid_until"`
	// Confidence is 0-100 as in STIX 2.1; nil when the producer gives none.
	Confidence *int `json:"confidence,omitempty"`
	// Source, Mode and Severity are set by SCRS in the scan bundle from the
	// indicator's source; uploads must not set them. An empty Mode is block.
	Source   string `json:"source,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Severity string `json:"severity,omitempty"`
}
type Bundle struct {
	Version    string      `json:"version"`
	Indicators []Indicator `json:"indicators"`
}

// LegacySource holds the bundle imported with PUT /feeds/indicators. Its
// indicators keep their plain IDs so existing findings keep their fingerprints.
const LegacySource = "bundle"

// Limits for one import into a source and for the merged scan bundle. The
// store keeps enabled sources within the scan limits.
const (
	MaxImportBytes      = 16 << 20
	MaxImportIndicators = 50000
	MaxScanBundleBytes  = 32 << 20
	MaxScanIndicators   = 100000
)

// Key identifies an indicator across sources: findings use it as advisory ID.
func (i Indicator) Key() string {
	if i.Source == "" || i.Source == LegacySource {
		return i.ID
	}
	return i.Source + ":" + i.ID
}

// EventKind names the integrity event an event pattern raises; event kinds
// are at most 64 bytes.
func (i Indicator) EventKind() string {
	kind := "pattern_" + i.Key()
	if len(kind) > 64 {
		sum := sha256.Sum256([]byte(i.Key()))
		kind = "pattern_" + hex.EncodeToString(sum[:8])
	}
	return kind
}

var domain = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Parse validates an uploaded bundle: at most MaxImportIndicators, with no
// source fields.
func Parse(raw []byte) (Bundle, error) { return parse(raw, MaxImportBytes, MaxImportIndicators, false) }

// ParseScan validates the merged bundle SCRS sends with each scan.
func ParseScan(raw []byte) (Bundle, error) {
	return parse(raw, MaxScanBundleBytes, MaxScanIndicators, true)
}

func parse(raw []byte, maxBytes, maxCount int, scan bool) (Bundle, error) {
	var b Bundle
	if len(raw) > maxBytes {
		return b, errors.New("indicator limit exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || b.Version == "" || len(b.Version) > 128 || len(b.Indicators) > maxCount {
		return b, errors.New("invalid indicator bundle")
	}
	seen := map[string]bool{}
	for n, i := range b.Indicators {
		if i.ID == "" || len(i.ID) > 128 || seen[i.Source+"\x00"+i.ID] || i.ValidUntil.IsZero() || (i.Confidence != nil && (*i.Confidence < 0 || *i.Confidence > 100)) {
			return b, errors.New("invalid indicator metadata")
		}
		seen[i.Source+"\x00"+i.ID] = true
		if !scan && (i.Source != "" || i.Mode != "" || i.Severity != "") {
			return b, errors.New("source, mode and severity come from the indicator source")
		}
		if scan && (len(i.Source) > 64 || (i.Mode != "" && i.Mode != "hunt" && i.Mode != "alert" && i.Mode != "block")) {
			return b, errors.New("invalid indicator source")
		}
		if _, ok := RuleSeverityScore[i.Severity]; scan && i.Severity != "" && !ok {
			return b, errors.New("invalid indicator severity")
		}
		value, err := normalize(i.Type, i.Value)
		if err != nil {
			return b, err
		}
		b.Indicators[n].Value = value
	}
	return b, nil
}

var hashLength = map[string]int{"md5": 32, "sha1": 40, "sha256": 64}

// normalize validates one indicator value and returns its canonical form.
func normalize(kind, value string) (string, error) {
	switch kind {
	case "md5", "sha1", "sha256":
		if len(value) != hashLength[kind] {
			return "", errors.New("invalid hash")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return "", err
		}
		return strings.ToLower(value), nil
	case "domain":
		value = strings.ReplaceAll(value, "[.]", ".")
		if !domain.MatchString(value) {
			return "", errors.New("invalid domain")
		}
		return strings.ToLower(value), nil
	case "ipv4":
		// Reports defang addresses as 1.2.3[.]4; accept and normalize.
		addr, err := netip.ParseAddr(strings.ReplaceAll(value, "[.]", "."))
		if err != nil || !addr.Is4() {
			return "", errors.New("invalid ipv4")
		}
		return addr.String(), nil
	case "url":
		normalized, ok := NormalizeURL(value)
		if !ok {
			return "", errors.New("invalid url")
		}
		return normalized, nil
	case "purl":
		if !strings.HasPrefix(value, "pkg:") || len(value) > 512 {
			return "", errors.New("invalid purl")
		}
		return value, nil
	case "workflow_step_name":
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return "", errors.New("invalid workflow step name")
		}
		return value, nil
	case "pr_title_regex", "git_branch_regex", "commit_message_regex", "file_path_regex", "file_content_regex":
		// Go regexps are RE2: linear time, so operator patterns cannot cause
		// catastrophic backtracking on attacker-controlled text.
		if len(value) > 512 {
			return "", errors.New("pattern too long")
		}
		if _, err := regexp.Compile(value); err != nil {
			return "", errors.New("invalid pattern")
		}
		return value, nil
	}
	return "", errors.New("unsupported indicator type")
}

// NormalizeURL returns the form URL indicators and URLs found in files are
// compared in: defanging undone, scheme and host lower-cased, default port,
// fragment and user info dropped, and an empty path written as "/".
func NormalizeURL(raw string) (string, bool) {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "[.]", ".")
	if len(raw) > 2048 {
		return "", false
	}
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		switch strings.ToLower(scheme) {
		case "hxxp":
			raw = "http://" + rest
		case "hxxps":
			raw = "https://" + rest
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ftp" {
		return "", false
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") || (u.Scheme == "ftp" && port == "21") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	u.Host, u.User, u.Fragment, u.RawFragment = host, nil, "", ""
	if u.Path == "" {
		u.Path, u.RawPath = "/", ""
	}
	return u.String(), true
}

// Patterns returns compiled active indicators of one regex type.
func (b Bundle) Patterns(kind string, now time.Time) []Pattern {
	var out []Pattern
	for _, i := range b.Indicators {
		if i.Type != kind || !now.Before(i.ValidUntil) {
			continue
		}
		if re, err := regexp.Compile(i.Value); err == nil {
			out = append(out, Pattern{Indicator: i, Regexp: re})
		}
	}
	return out
}

type Pattern struct {
	Indicator
	*regexp.Regexp
}

// Active returns unexpired indicators of one type.
func (b Bundle) Active(kind string, now time.Time) []Indicator {
	var out []Indicator
	for _, i := range b.Indicators {
		if i.Type == kind && now.Before(i.ValidUntil) {
			out = append(out, i)
		}
	}
	return out
}
