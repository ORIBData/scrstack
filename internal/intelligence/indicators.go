package intelligence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

type Indicator struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	ValidUntil time.Time `json:"valid_until"`
}
type Bundle struct {
	Version    string      `json:"version"`
	Indicators []Indicator `json:"indicators"`
}

var domain = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func Parse(raw []byte) (Bundle, error) {
	var b Bundle
	if len(raw) > 4<<20 {
		return b, errors.New("indicator limit exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || b.Version == "" || len(b.Version) > 128 || len(b.Indicators) > 10000 {
		return b, errors.New("invalid indicator bundle")
	}
	seen := map[string]bool{}
	for n, i := range b.Indicators {
		if i.ID == "" || len(i.ID) > 128 || seen[i.ID] || i.ValidUntil.IsZero() {
			return b, errors.New("invalid indicator metadata")
		}
		seen[i.ID] = true
		switch i.Type {
		case "sha256":
			if len(i.Value) != 64 {
				return b, errors.New("invalid hash")
			}
			if _, err := hex.DecodeString(i.Value); err != nil {
				return b, err
			}
		case "domain":
			if !domain.MatchString(i.Value) {
				return b, errors.New("invalid domain")
			}
		case "ipv4":
			// Reports defang addresses as 1.2.3[.]4; accept and normalize.
			value := strings.ReplaceAll(i.Value, "[.]", ".")
			addr, err := netip.ParseAddr(value)
			if err != nil || !addr.Is4() {
				return b, errors.New("invalid ipv4")
			}
			b.Indicators[n].Value = addr.String()
			continue
		case "purl":
			if !strings.HasPrefix(i.Value, "pkg:") || len(i.Value) > 512 {
				return b, errors.New("invalid purl")
			}
			continue
		case "workflow_step_name":
			if strings.TrimSpace(i.Value) == "" || len(i.Value) > 256 {
				return b, errors.New("invalid workflow step name")
			}
			continue
		case "pr_title_regex", "git_branch_regex", "commit_message_regex", "file_path_regex", "file_content_regex":
			// Go regexps are RE2: linear time, so operator patterns cannot cause
			// catastrophic backtracking on attacker-controlled text.
			if len(i.Value) > 512 {
				return b, errors.New("pattern too long")
			}
			if _, err := regexp.Compile(i.Value); err != nil {
				return b, errors.New("invalid pattern")
			}
			continue
		default:
			return b, errors.New("unsupported indicator type")
		}
		b.Indicators[n].Value = strings.ToLower(i.Value)
	}
	return b, nil
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
