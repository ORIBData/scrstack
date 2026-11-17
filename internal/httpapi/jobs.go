package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// jobHandler serves GET /jobs, GET /jobs/{id} and POST /jobs/{id}:cancel.
type jobHandler struct{ store *assessments.Store }

func (h jobHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, BasePath+"/jobs"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			writeError(w, 405, "method not allowed")
			return
		}
		h.list(w, r)
		return
	}
	action := ""
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest, action = rest[:i], rest[i+1:]
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		writeError(w, 404, "job not found")
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		job, err := h.store.JobByID(r.Context(), id)
		if err != nil {
			jobError(w, err)
			return
		}
		writeJSON(w, 200, job)
	case action == "cancel" && r.Method == http.MethodPost:
		principal, _ := r.Context().Value(principalKey{}).(connections.Token)
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		job, err := h.store.CancelJob(r.Context(), id, principal.ID, principal.Name)
		if err != nil {
			jobError(w, err)
			return
		}
		writeJSON(w, 200, job)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h jobHandler) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := assessments.JobFilter{Kind: q.Get("kind"), Status: q.Get("status"), Limit: 50}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeError(w, 400, "limit must be between 1 and 200")
			return
		}
		filter.Limit = n
	}
	if raw := q.Get("asset_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, 400, "asset_id must be a UUID")
			return
		}
		filter.Asset = id
	}
	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, 400, "since must be an RFC 3339 time")
			return
		}
		filter.Since = &t
	}
	if raw := q.Get("cursor"); raw != "" {
		var c struct {
			At time.Time `json:"at"`
			ID uuid.UUID `json:"id"`
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if len(raw) > 512 || err != nil || json.Unmarshal(decoded, &c) != nil || c.ID == uuid.Nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		filter.BeforeAt, filter.BeforeID = &c.At, c.ID
	}
	jobs, err := h.store.Jobs(r.Context(), filter)
	if err != nil {
		jobError(w, err)
		return
	}
	next := ""
	if len(jobs) > filter.Limit {
		jobs = jobs[:filter.Limit]
		last := jobs[len(jobs)-1]
		encoded, _ := json.Marshal(map[string]any{"at": last.CreatedAt, "id": last.ID})
		next = base64.RawURLEncoding.EncodeToString(encoded)
	}
	writeJSON(w, 200, map[string]any{"items": jobs, "next_cursor": next})
}

func jobError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "job not found")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "kind or status is not valid")
	case errors.Is(err, assessments.ErrJobNotCancellable):
		writeError(w, 409, err.Error())
	case errors.Is(err, assessments.ErrConflict), errors.Is(err, assessments.ErrQAState):
		writeError(w, 409, "the job has already finished")
	default:
		writeError(w, 500, "job operation failed")
	}
}
