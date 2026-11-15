package sast

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/scanner"
)

// Server is the scrs-sast HTTP service. The worker posts a source archive
// and a Request; nothing here holds SCRS credentials.
type Server struct {
	Engine   *Engine
	WorkRoot string
	Slots    int
}

// Handler authenticates every route except /healthz with the shared token.
func (s *Server) Handler(token string) http.Handler {
	expected := sha256.Sum256([]byte(token))
	slots := make(chan struct{}, max(s.Slots, 1))
	authorized := func(r *http.Request) bool {
		header := r.Header.Get("Authorization")
		provided := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
		return len(token) >= 32 && strings.HasPrefix(header, "Bearer ") && subtle.ConstantTimeCompare(expected[:], provided[:]) == 1
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			for _, a := range s.Engine.Analyzers {
				if a.Version(r.Context()) == "unavailable" && s.Engine.Enabled[a.Meta().Name] {
					http.Error(w, a.Meta().Name+" unavailable", 503)
					return
				}
			}
			_, _ = w.Write([]byte("ok"))
			return
		}
		if !authorized(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/analyzers":
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			analyzers, reach := s.Engine.Describe(ctx)
			writeJSON(w, map[string]any{"analyzers": analyzers, "reachability": reach})
		case r.Method == "POST" && r.URL.Path == "/rules:validate":
			s.validate(w, r)
		case r.Method == "POST" && r.URL.Path == "/analyze":
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				http.Error(w, "analyzer busy", 429)
				return
			}
			s.analyze(w, r)
		default:
			http.Error(w, "not found", 404)
		}
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// analyze reads a multipart body: "request" (JSON) then "archive" (tar.gz).
func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 72<<20)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart request required", 400)
		return
	}
	var req Request
	var archive []byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "invalid multipart request", 400)
			return
		}
		switch part.FormName() {
		case "request":
			if json.NewDecoder(io.LimitReader(part, 4<<20)).Decode(&req) != nil {
				http.Error(w, "invalid request part", 400)
				return
			}
		case "archive":
			archive, err = io.ReadAll(io.LimitReader(part, (64<<20)+1))
			if err != nil || len(archive) > 64<<20 {
				http.Error(w, "archive limit exceeded", 413)
				return
			}
		default:
			http.Error(w, "unexpected part", 400)
			return
		}
	}
	if len(archive) == 0 || len(req.CustomRules) > 50 {
		http.Error(w, "archive missing or too many custom rule files", 400)
		return
	}
	work, err := os.MkdirTemp(s.WorkRoot, "scrs-sast-")
	if err != nil {
		http.Error(w, "work area unavailable", 503)
		return
	}
	defer os.RemoveAll(work)
	source := filepath.Join(work, "src")
	if err := os.Mkdir(source, 0o700); err != nil || scanner.Extract(archive, source) != nil {
		http.Error(w, "archive rejected", 413)
		return
	}
	scratch := filepath.Join(work, "scratch")
	_ = os.Mkdir(scratch, 0o700)
	// The request budget covers every analyzer plus reachability.
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Minute)
	defer cancel()
	writeJSON(w, s.Engine.Analyze(ctx, source, scratch, req))
}

// validate compiles uploaded OpenGrep rules without scanning anything.
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || len(body) == 0 {
		http.Error(w, "rules must be 1 byte to 1 MiB", 400)
		return
	}
	var og *OpenGrep
	for _, a := range s.Engine.Analyzers {
		if o, ok := a.(*OpenGrep); ok {
			og = o
		}
	}
	if og == nil {
		http.Error(w, "opengrep unavailable", 503)
		return
	}
	work, err := os.MkdirTemp(s.WorkRoot, "scrs-rules-")
	if err != nil {
		http.Error(w, "work area unavailable", 503)
		return
	}
	defer os.RemoveAll(work)
	file := filepath.Join(work, "rules.yaml")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		http.Error(w, "work area unavailable", 503)
		return
	}
	for _, d := range []string{"cache", "config"} {
		_ = os.MkdirAll(filepath.Join(work, d), 0o700)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	_, stderr, err := execute(ctx, work, isolatedEnv(work), []int{0}, og.Bin, "validate", "--config", file, "--quiet")
	result := map[string]any{"valid": err == nil}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			result["error"] = "validation timed out"
		} else {
			result["error"] = strings.TrimSpace(firstLine(string(stderr)))
		}
	}
	writeJSON(w, result)
}
