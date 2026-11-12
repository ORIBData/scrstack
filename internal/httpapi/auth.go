package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type TokenStore interface {
	Authenticate(context.Context, string, netip.Addr) (connections.Token, error)
	CreateToken(context.Context, connections.Token, uuid.UUID) (connections.Token, string, error)
	Tokens(context.Context, uuid.UUID, int) ([]connections.Token, error)
	RevokeToken(context.Context, uuid.UUID, uuid.UUID) error
}
type principalKey struct{}
type Security struct {
	Store          TokenStore
	Redis          *redis.Client
	DocsPublic     bool
	TrustedProxies []netip.Prefix
	Origins        []string
}

var tokenWindow = redis.NewScript(`
local t=redis.call('TIME')
local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-60000)
if redis.call('ZCARD',KEYS[1])>=120 then return 0 end
redis.call('ZADD',KEYS[1],now,ARGV[1])
redis.call('PEXPIRE',KEYS[1],60000)
return 1`)

func HandlerWithSecurity(check func(context.Context) error, store ConnectionStore, security Security) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+BasePath+"/system/healthz", health)
	mux.Handle("GET "+BasePath+"/system/readyz", readiness(check))
	// Reuse the embedded docs-only mux; protect all its assets consistently.
	docsHandler := Handler()
	if !security.DocsPublic {
		docsHandler = security.protect("", docsHandler)
	}
	mux.Handle(BasePath+"/docs", docsHandler)
	mux.Handle(BasePath+"/docs/", docsHandler)
	handler := connectionHandler{store: store, providerSlots: make(chan struct{}, 4)}
	mux.Handle(BasePath+"/connections", security.protect("admin", handler))
	mux.Handle(BasePath+"/connections/", security.protect("admin", handler))
	mux.Handle("GET "+BasePath+"/assets", security.protect("read", handler))
	mux.Handle(BasePath+"/tokens", security.protect("admin", http.HandlerFunc(security.tokens)))
	mux.Handle(BasePath+"/tokens/", security.protect("admin", http.HandlerFunc(security.tokens)))
	return security.cors(mux)
}
func (s Security) protect(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) > 1024 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, 401, "unauthorized")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		remote, _ := netip.ParseAddr(host)
		remote = s.clientIP(remote, r.Header.Get("X-Forwarded-For"))
		principal, err := s.Store.Authenticate(ctx, strings.TrimPrefix(authorization, "Bearer "), remote)
		if err != nil {
			if errors.Is(err, connections.ErrUnauthorized) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, 401, "unauthorized")
			} else {
				writeError(w, 503, "authentication unavailable")
			}
			return
		}
		if scope != "" && !principal.Allows(scope) {
			writeError(w, 403, "insufficient scope")
			return
		}
		if s.Redis == nil {
			writeError(w, 503, "rate limiter unavailable")
			return
		}
		allowed, err := tokenWindow.Run(ctx, s.Redis, []string{"scrs:token-window:" + principal.ID.String()}, uuid.NewString()).Int()
		if err != nil {
			writeError(w, 503, "rate limiter unavailable")
			return
		}
		if allowed != 1 {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "token rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
	})
}
func (s Security) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			allowed := false
			for _, value := range s.Origins {
				if value == origin && value != "*" {
					allowed = true
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			}
			if r.Method == http.MethodOptions {
				if !allowed {
					writeError(w, 403, "origin not allowed")
				} else {
					w.WriteHeader(204)
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (s Security) tokens(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path == BasePath+"/tokens" {
		switch r.Method {
		case http.MethodGet:
			after := uuid.Nil
			if raw := r.URL.Query().Get("cursor"); raw != "" {
				var err error
				after, err = uuid.Parse(raw)
				if err != nil {
					writeError(w, 400, "invalid cursor")
					return
				}
			}
			items, err := s.Store.Tokens(ctx, after, 101)
			if err != nil {
				writeError(w, 500, "token list failed")
				return
			}
			next := ""
			if len(items) > 100 {
				items = items[:100]
				next = items[99].ID.String()
			}
			writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		case http.MethodPost:
			var input struct {
				Name      string     `json:"name"`
				Scopes    []string   `json:"scopes"`
				Networks  []string   `json:"ip_allow_list"`
				ExpiresAt *time.Time `json:"expires_at"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
				writeError(w, 400, "invalid token request")
				return
			}
			item, secret, err := s.Store.CreateToken(ctx, connections.Token{Name: input.Name, Scopes: input.Scopes, Networks: input.Networks, ExpiresAt: input.ExpiresAt}, actor.ID)
			if err != nil {
				switch {
				case errors.Is(err, connections.ErrTokenInput):
					writeError(w, 400, "invalid token request")
				case errors.Is(err, connections.ErrConflict):
					writeError(w, 409, "token name already exists")
				default:
					writeError(w, 500, "token creation failed")
				}
				return
			}
			writeJSON(w, 201, map[string]any{"token": secret, "metadata": item})
		default:
			w.Header().Set("Allow", "GET, POST")
			writeError(w, 405, "method not allowed")
		}
		return
	}
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, BasePath+"/tokens/"))
	if err != nil {
		writeError(w, 404, "token not found")
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		writeError(w, 405, "method not allowed")
		return
	}
	if err := s.Store.RevokeToken(ctx, id, actor.ID); err != nil {
		if errors.Is(err, connections.ErrTokenInput) {
			writeError(w, 409, "token not found or bootstrap token cannot be revoked; rotate bootstrap via environment")
		} else {
			writeError(w, 500, "token revocation failed")
		}
		return
	}
	w.WriteHeader(204)
}

// Walk the forwarded chain from the socket inward; stop at the first untrusted
// hop. Headers supplied by a direct untrusted client never affect its identity.
func (s Security) clientIP(peer netip.Addr, forwarded string) netip.Addr {
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range s.TrustedProxies {
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) || len(forwarded) > 4096 {
		return peer.Unmap()
	}
	hops := strings.Split(forwarded, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		if !trusted(peer) {
			break
		}
		parsed, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{}
		}
		peer = parsed.Unmap()
	}
	return peer.Unmap()
}
