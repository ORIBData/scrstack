package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// incidentHandler serves /incidents (INT-018).
type incidentHandler struct{ store *assessments.Store }

func (h incidentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	principal, _ := r.Context().Value(principalKey{}).(connections.Token)
	switch {
	case r.Method == http.MethodPost:
		h.create(w, r, principal)
	case r.Method == http.MethodGet && r.PathValue("id") != "":
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, 404, "incident not found")
			return
		}
		incident, err := h.store.Incident(r.Context(), id)
		if err != nil {
			incidentError(w, err)
			return
		}
		writeJSON(w, 200, incident)
	case r.Method == http.MethodGet:
		h.list(w, r)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h incidentHandler) create(w http.ResponseWriter, r *http.Request, principal connections.Token) {
	var input struct {
		Title       string    `json:"title"`
		Actors      []string  `json:"actors"`
		Since       time.Time `json:"since"`
		Until       time.Time `json:"until"`
		Reassess    *bool     `json:"reassess"`
		MaxReassess int       `json:"max_reassess"`
	}
	if !readBody(w, r, &input) {
		return
	}
	if input.Until.IsZero() {
		input.Until = time.Now().UTC().Add(time.Minute)
	}
	reassess := input.Reassess == nil || *input.Reassess
	incident, err := h.store.CreateIncident(r.Context(), assessments.IncidentRequest{Title: input.Title, Actors: input.Actors, Since: input.Since, Until: input.Until, Reassess: reassess, MaxReassess: input.MaxReassess}, principal.ID, principal.Name)
	if err != nil {
		incidentError(w, err)
		return
	}
	w.Header().Set("Location", BasePath+"/incidents/"+incident.ID.String())
	writeJSON(w, 201, incident)
}

func (h incidentHandler) list(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeError(w, 400, "limit must be between 1 and 200")
			return
		}
		limit = n
	}
	var before *time.Time
	var beforeID uuid.UUID
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		var c struct {
			At time.Time `json:"at"`
			ID uuid.UUID `json:"id"`
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if len(raw) > 512 || err != nil || json.Unmarshal(decoded, &c) != nil || c.ID == uuid.Nil {
			writeError(w, 400, "invalid cursor")
			return
		}
		before, beforeID = &c.At, c.ID
	}
	items, err := h.store.Incidents(r.Context(), before, beforeID, limit)
	if err != nil {
		incidentError(w, err)
		return
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		encoded, _ := json.Marshal(map[string]any{"at": last.CreatedAt, "id": last.ID})
		next = base64.RawURLEncoding.EncodeToString(encoded)
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func incidentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "incident not found")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "give 1 to 20 actors, a since time before until, a window of at most 366 days, a title of at most 200 characters and max_reassess of at most 200")
	default:
		writeError(w, 500, "incident operation failed")
	}
}
