package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

type ConnectionStore interface {
	List(context.Context) ([]connections.Connection, error)
	Put(context.Context, connections.Connection, json.RawMessage, bool) (bool, error)
	PublicByID(context.Context, uuid.UUID) (connections.Connection, error)
	PublicByName(context.Context, string) (connections.Connection, error)
	NameByID(context.Context, uuid.UUID) (string, error)
	Test(context.Context, string, connections.Adapter) (int, error)
	Discover(context.Context, string, connections.Adapter) (connections.DiscoveryResult, error)
	ListAssetsPage(context.Context, int, string, uuid.UUID) ([]connections.Asset, error)
}

type connectionHandler struct {
	store     ConnectionStore
	tokenHash [32]byte
}

func hashToken(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (h connectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	providedHash := hashToken(strings.TrimPrefix(authorization, prefix))
	if !strings.HasPrefix(authorization, prefix) || len(authorization) > 2048 || subtle.ConstantTimeCompare(providedHash[:], h.tokenHash[:]) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if r.URL.Path == BasePath+"/assets" {
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 500 {
				writeError(w, 400, "limit must be between 1 and 500")
				return
			}
			limit = parsed
		}
		var cursor struct {
			Locator string    `json:"locator"`
			ID      uuid.UUID `json:"id"`
		}
		if raw := r.URL.Query().Get("cursor"); raw != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(raw)
			if len(raw) > 2048 || err != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Locator == "" || cursor.ID == uuid.Nil {
				writeError(w, 400, "invalid asset cursor")
				return
			}
		}
		assets, err := h.store.ListAssetsPage(ctx, limit+1, cursor.Locator, cursor.ID)
		if err != nil {
			writeError(w, 500, "asset list failed")
			return
		}
		next := ""
		if len(assets) > limit {
			assets = assets[:limit]
			last := assets[len(assets)-1]
			encoded, _ := json.Marshal(map[string]any{"locator": last.Locator, "id": last.ID})
			next = base64.RawURLEncoding.EncodeToString(encoded)
		}
		writeJSON(w, 200, map[string]any{"items": assets, "next_cursor": next})
		return
	}
	segment := strings.TrimPrefix(r.URL.Path, BasePath+"/connections")
	if segment == "" {
		switch r.Method {
		case http.MethodGet:
			list, err := h.store.List(ctx)
			if err != nil {
				writeError(w, 500, "connection list failed")
				return
			}
			writeJSON(w, 200, list)
		case http.MethodPost:
			h.create(ctx, w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeError(w, 405, "method not allowed")
		}
		return
	}
	if !strings.HasPrefix(segment, "/") || strings.Contains(strings.TrimPrefix(segment, "/"), "/") {
		writeError(w, 404, "not found")
		return
	}
	segment = strings.TrimPrefix(segment, "/")
	action := ""
	if i := strings.IndexByte(segment, ':'); i >= 0 {
		action, segment = segment[i+1:], segment[:i]
	}
	id, err := uuid.Parse(segment)
	if err != nil {
		writeError(w, 404, "connection not found")
		return
	}
	if action == "" && r.Method == http.MethodGet {
		c, err := h.store.PublicByID(ctx, id)
		if err != nil {
			writeError(w, 404, "connection not found")
			return
		}
		writeJSON(w, 200, c)
		return
	}
	if r.Method != http.MethodPost || (action != "test" && action != "discover") {
		writeError(w, 405, "method not allowed")
		return
	}
	name, err := h.store.NameByID(ctx, id)
	if err != nil {
		writeError(w, 404, "connection not found")
		return
	}
	adapter := connections.NewNativeAdapters()
	if action == "test" {
		count, err := h.store.Test(ctx, name, adapter)
		if err != nil {
			writeError(w, 502, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"connection_id": id, "resource_count": count})
		return
	}
	result, err := h.store.Discover(ctx, name, adapter)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (h connectionHandler) create(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var input struct {
		Provider   string            `json:"provider"`
		Name       string            `json:"name"`
		Config     json.RawMessage   `json:"config"`
		Scope      connections.Scope `json:"scope"`
		Credential json.RawMessage   `json:"credential"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 96<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(w, 400, "invalid connection request")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "invalid trailing request data")
		return
	}
	c := connections.Connection{Provider: input.Provider, Name: input.Name, Config: input.Config, Scope: input.Scope}
	if err := connections.ValidateInput(c, input.Credential); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := c.Scope.Validate(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	written, err := h.store.Put(ctx, c, input.Credential, false)
	if err != nil {
		writeError(w, 500, "connection save failed")
		return
	}
	if !written {
		writeError(w, 409, "connection name already exists")
		return
	}
	item, err := h.store.PublicByName(ctx, c.Name)
	if err != nil {
		writeError(w, 500, "connection created; unable to read it")
		return
	}
	w.Header().Set("Location", BasePath+"/connections/"+item.ID.String())
	writeJSON(w, 201, item)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	if message == "" {
		message = "request failed"
	}
	writeJSON(w, status, map[string]string{"error": message})
}
