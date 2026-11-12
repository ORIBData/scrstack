package scanner

import (
	"errors"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"io"
	"net/http"
	"strings"
)

func scanInput(w http.ResponseWriter, r *http.Request) ([]byte, *IndicatorBundle, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 70<<20)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
		b, err := io.ReadAll(io.LimitReader(r.Body, (64<<20)+1))
		if len(b) > 64<<20 {
			return nil, nil, errors.New("archive limit exceeded")
		}
		return b, nil, err
	}
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, nil, err
	}
	var archive []byte
	var indicators *IndicatorBundle
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		name := part.FormName()
		if seen[name] || (name != "archive" && name != "indicators") {
			return nil, nil, errors.New("invalid multipart scan request")
		}
		seen[name] = true
		limit := int64(64 << 20)
		if name == "indicators" {
			limit = 4 << 20
		}
		body, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil || int64(len(body)) > limit {
			return nil, nil, errors.New("scan input limit exceeded")
		}
		if name == "archive" {
			archive = body
		} else {
			bundle, err := intelligence.Parse(body)
			if err != nil {
				return nil, nil, err
			}
			indicators = &bundle
		}
	}
	if !seen["archive"] {
		return nil, nil, errors.New("archive missing")
	}
	return archive, indicators, nil
}
