package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ORIBData/scrstack/internal/intelligence"
)

// scanContext is the per-request intelligence sent ahead of the content.
type scanContext struct {
	indicators *IndicatorBundle
	rules      *RulePack
}

// readContextPart parses an "indicators" or "rules" part into c.
func (c *scanContext) readContextPart(name string, part io.Reader) error {
	limit := int64(intelligence.MaxScanBundleBytes)
	if name == "rules" {
		limit = MaxRulePackSize + 1<<20
	}
	body, err := io.ReadAll(io.LimitReader(part, limit+1))
	if err != nil || int64(len(body)) > limit {
		return errors.New("scan input limit exceeded")
	}
	if name == "indicators" {
		bundle, err := intelligence.ParseScan(body)
		if err != nil {
			return err
		}
		c.indicators = &bundle
		return nil
	}
	var pack RulePack
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&pack) != nil {
		return errors.New("invalid rule pack")
	}
	if _, err := checkPack(pack); err != nil {
		return err
	}
	c.rules = &pack
	return nil
}

// apply returns the engine configured with this request's intelligence.
func (c scanContext) apply(e Engine) Engine {
	e.Indicators, e.Rules = c.indicators, c.rules
	return e
}

func scanInput(w http.ResponseWriter, r *http.Request) ([]byte, scanContext, error) {
	var c scanContext
	// Archive, rule pack and indicator bundle at their limits, plus framing.
	r.Body = http.MaxBytesReader(w, r.Body, 136<<20)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
		b, err := io.ReadAll(io.LimitReader(r.Body, (64<<20)+1))
		if len(b) > 64<<20 {
			return nil, c, errors.New("archive limit exceeded")
		}
		return b, c, err
	}
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, c, err
	}
	var archive []byte
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, c, err
		}
		name := part.FormName()
		if seen[name] || (name != "archive" && name != "indicators" && name != "rules") {
			return nil, c, errors.New("invalid multipart scan request")
		}
		seen[name] = true
		if name != "archive" {
			if err := c.readContextPart(name, part); err != nil {
				return nil, c, err
			}
			continue
		}
		archive, err = io.ReadAll(io.LimitReader(part, (64<<20)+1))
		if err != nil || len(archive) > 64<<20 {
			return nil, c, errors.New("scan input limit exceeded")
		}
	}
	if !seen["archive"] {
		return nil, c, errors.New("archive missing")
	}
	return archive, c, nil
}

// imageInput returns the image stream: the raw body, or the final "image"
// part of a multipart request whose earlier parts carry indicators and rules.
func imageInput(r *http.Request) (io.Reader, scanContext, error) {
	var c scanContext
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
		return r.Body, c, nil
	}
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, c, err
	}
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if err != nil {
			return nil, c, errors.New("image part missing")
		}
		name := part.FormName()
		if name == "image" {
			return part, c, nil
		}
		if seen[name] || (name != "indicators" && name != "rules") {
			return nil, c, errors.New("invalid multipart image request")
		}
		seen[name] = true
		if err := c.readContextPart(name, part); err != nil {
			return nil, c, err
		}
	}
}
