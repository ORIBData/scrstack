package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/dtrack"
	"github.com/google/uuid"
)

// dtrackHandler serves the Dependency-Track export settings and uploads
// (P2). The API key is write-only and sealed with the master key.
type dtrackHandler struct {
	store   *assessments.Store
	secrets Sealer
	hosts   map[string]bool
	// client overrides the guarded HTTP client (tests only).
	client *http.Client
}

type dtrackInput struct {
	Enabled bool       `json:"enabled"`
	URL     string     `json:"url"`
	APIKey  *string    `json:"api_key,omitempty"`
	Parent  *uuid.UUID `json:"parent_uuid,omitempty"`
}

func (h dtrackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath+"/integrations/dependency-track")
	admin := func() bool {
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return false
		}
		return true
	}
	switch {
	case path == "" && r.Method == http.MethodGet:
		settings, err := h.store.DTrackSettings(ctx)
		if err != nil {
			licenseError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(settings.Revision, 10)+`"`)
		writeJSON(w, 200, settings)
	case path == "" && r.Method == http.MethodPut:
		if !admin() {
			return
		}
		expected, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var in dtrackInput
		if !readBody(w, r, &in) {
			return
		}
		in.URL = strings.TrimSuffix(strings.TrimSpace(in.URL), "/")
		if (in.URL != "" || in.Enabled) && !dtrack.ValidURL(in.URL, h.hosts) {
			writeError(w, 400, "url must be https, or http for a host in SCRS_DTRACK_PRIVATE_HOSTS, without credentials, query or fragment")
			return
		}
		change := assessments.DTrackChange{Enabled: in.Enabled, URL: in.URL, Parent: in.Parent}
		if in.APIKey != nil {
			key := strings.TrimSpace(*in.APIKey)
			if len(key) < 16 || len(key) > 256 || strings.ContainsAny(key, " \r\n") {
				writeError(w, 400, "api_key must be a Dependency-Track API key (16 to 256 characters)")
				return
			}
			sealed, err := h.secrets.Seal([]byte(key), assessments.DTrackAAD())
			if err != nil {
				writeError(w, 500, "credential sealing failed")
				return
			}
			change.Key = sealed
		}
		settings, err := h.store.SetDTrackSettings(ctx, expected, change, principal.ID)
		if err != nil {
			if errors.Is(err, assessments.ErrInput) {
				writeError(w, 400, "enabling the export needs a url and an api_key")
				return
			}
			licenseError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(settings.Revision, 10)+`"`)
		writeJSON(w, 200, settings)
	case path == ":test" && r.Method == http.MethodPost:
		if !admin() {
			return
		}
		settings, err := h.store.DTrackSettings(ctx)
		if err != nil {
			licenseError(w, err)
			return
		}
		if !dtrack.ValidURL(settings.URL, h.hosts) || len(settings.Key) == 0 {
			writeError(w, 409, "store a url and an api_key first")
			return
		}
		key, err := h.secrets.Unseal(settings.Key, assessments.DTrackAAD())
		if err != nil {
			writeError(w, 409, "the stored api_key cannot be opened with the current master key; store it again")
			return
		}
		client := h.client
		if client == nil {
			client = dtrack.NewHTTPClient(h.hosts)
			defer client.CloseIdleConnections()
		}
		check, err := dtrack.Client{BaseURL: settings.URL, APIKey: string(key), HTTP: client}.Check(ctx)
		result := map[string]any{"ok": err == nil, "version": check.Version, "permissions": nonNil(check.Permissions), "missing_permissions": nonNil(check.Missing), "required_permissions": dtrack.RequiredPermissions}
		if err != nil {
			result["error"] = err.Error()
		}
		writeJSON(w, 200, result)
	case path == "/uploads" && r.Method == http.MethodGet:
		status := r.URL.Query().Get("status")
		if status != "" && status != "queued" && status != "sending" && status != "uploaded" && status != "failed" {
			writeError(w, 400, "status must be queued, sending, uploaded or failed")
			return
		}
		before, err := pageUUID(r, "cursor")
		if err != nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		items, err := h.store.DTrackUploads(ctx, status, before, 50)
		if err != nil {
			licenseError(w, err)
			return
		}
		next := ""
		if len(items) > 50 {
			items = items[:50]
			next = items[49].ID.String()
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	case strings.HasPrefix(path, "/uploads/") && strings.HasSuffix(path, "/retry") && r.Method == http.MethodPost:
		if !admin() {
			return
		}
		id, err := uuid.Parse(strings.TrimSuffix(strings.TrimPrefix(path, "/uploads/"), "/retry"))
		if err != nil {
			writeError(w, 404, "not found")
			return
		}
		if err := h.store.RetryDTrack(ctx, id, principal.ID); err != nil {
			if errors.Is(err, assessments.ErrNotFound) {
				writeError(w, 404, "no failed upload with this id")
				return
			}
			licenseError(w, err)
			return
		}
		w.WriteHeader(204)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// nonNil makes an empty list encode as [] rather than null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
