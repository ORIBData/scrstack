package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// Legacy scanner requests are not part of the SCRS public API. Require a
// separate internal-service token, bound concurrent scans and prohibit host paths.
func legacySecurity(token string, next http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(token))
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/" || r.URL.Path == "/version" {
			next.ServeHTTP(w, r)
			return
		}
		if len(token) < 32 {
			http.Error(w, "scanner access is not configured", 503)
			return
		}
		header := r.Header.Get("Authorization")
		provided := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
		if len(header) > 1024 || !strings.HasPrefix(header, "Bearer ") || subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.URL.Path == "/scanFile" || r.URL.Path == "/scanPath" {
			http.Error(w, "host path scanning is disabled; upload content instead", 410)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "scanner capacity reached", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
		next.ServeHTTP(w, r)
	})
}
