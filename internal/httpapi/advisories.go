package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
)

// advisoryHandler serves advisory search and local advisories (OSV-008).
type advisoryHandler struct{ store *assessments.Store }

func (h advisoryHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "the advisory is already withdrawn")
	case errors.Is(err, assessments.ErrInput):
		msg := "invalid advisory request"
		if _, reason, ok := strings.Cut(err.Error(), ": "); ok && err != assessments.ErrInput {
			msg = reason
		}
		writeError(w, 400, msg)
	default:
		writeError(w, 500, "advisory operation failed")
	}
}

func (h advisoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, BasePath+"/advisories"), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.search(ctx, w, r)
	case rest == "" && r.Method == http.MethodPost:
		if !principal.Allows("write") {
			writeError(w, 403, "write scope required")
			return
		}
		var in assessments.LocalAdvisoryInput
		if !readBody(w, r, &in) {
			return
		}
		record, err := h.store.CreateLocalAdvisory(ctx, in, principal.Name)
		if err != nil {
			h.fail(w, err)
			return
		}
		var id struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(record, &id)
		w.Header().Set("Location", BasePath+"/advisories/"+id.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write(record)
	case strings.HasSuffix(rest, ":withdraw") && r.Method == http.MethodPost:
		if !principal.Allows("write") {
			writeError(w, 403, "write scope required")
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if !readBody(w, r, &in) {
			return
		}
		record, err := h.store.WithdrawLocalAdvisory(ctx, strings.TrimSuffix(rest, ":withdraw"), in.Reason, principal.Name)
		if err != nil {
			h.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(record)
	case strings.HasSuffix(rest, "/affected") && r.Method == http.MethodGet:
		items, err := h.store.AffectedBy(ctx, strings.TrimSuffix(rest, "/affected"))
		if err != nil {
			h.fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "truncated": len(items) >= 1000})
	case rest != "" && !strings.ContainsAny(rest, "/") && r.Method == http.MethodGet:
		if !advisoryID.MatchString(rest) {
			writeError(w, 404, "not found")
			return
		}
		id := rest
		if !strings.HasPrefix(id, "x_") {
			id = strings.ToUpper(id[:3]) + id[3:]
		}
		view, err := h.store.Advisory(ctx, id, r.URL.Query().Get("purl"))
		if err != nil {
			h.fail(w, err)
			return
		}
		writeJSON(w, 200, view)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h advisoryHandler) search(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := assessments.AdvisoryFilter{Query: q.Get("q"), Origin: q.Get("origin"), Ecosystem: q.Get("ecosystem"), Package: q.Get("package"), Alias: q.Get("alias"), Limit: 50}
	var err error
	if raw := q.Get("limit"); raw != "" {
		if f.Limit, err = strconv.Atoi(raw); err != nil || f.Limit < 1 || f.Limit > 200 {
			writeError(w, 400, "limit must be 1 to 200")
			return
		}
	}
	if raw := q.Get("withdrawn"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			writeError(w, 400, "withdrawn must be true or false")
			return
		}
		f.Withdrawn = &v
	}
	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, 400, "since must be an RFC 3339 time")
			return
		}
		f.Since = &t
	}
	if raw := q.Get("cursor"); raw != "" {
		id, origin, ok := strings.Cut(raw, "|")
		if !ok || id == "" || origin == "" {
			writeError(w, 400, "invalid cursor")
			return
		}
		f.AfterID, f.AfterOrig = id, origin
	}
	hits, err := h.store.SearchAdvisories(ctx, f)
	if err != nil {
		h.fail(w, err)
		return
	}
	next := ""
	if len(hits) > f.Limit {
		hits = hits[:f.Limit]
		next = hits[len(hits)-1].ID + "|" + hits[len(hits)-1].Origin
	}
	writeJSON(w, 200, map[string]any{"items": hits, "next_cursor": next})
}
