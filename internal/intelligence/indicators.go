package intelligence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
		default:
			return b, errors.New("unsupported indicator type")
		}
		b.Indicators[n].Value = strings.ToLower(i.Value)
	}
	return b, nil
}
