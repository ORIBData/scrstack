package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/google/uuid"
)

// RuleValidator compiles one ruleset and returns its warnings, or an
// *intelligence.RuleError locating why it does not compile.
type RuleValidator func(ctx context.Context, rules string) ([]intelligence.Diagnostic, error)

// yaraValidator runs the YARA-X compiler shipped in the SCRS image.
func yaraValidator() RuleValidator {
	binary := os.Getenv("SCRS_YARA_BINARY")
	if binary == "" {
		binary = "/usr/local/bin/yr"
	}
	return func(ctx context.Context, rules string) ([]intelligence.Diagnostic, error) {
		return scanner.ValidateRules(ctx, binary, os.TempDir(), rules)
	}
}

// ruleHandler manages YARA rulesets (TIF). Scope write may create and change
// hunt rulesets; promoting to alert or block, and changing or deleting a
// ruleset that gates verdicts, needs admin.
type ruleHandler struct {
	store    *assessments.Store
	validate RuleValidator
	// compiles bounds concurrent compiler processes.
	compiles chan struct{}
}

type ruleSetInput struct {
	Name        string                 `json:"name"`
	Kind        string                 `json:"kind"`
	Description string                 `json:"description"`
	Mode        string                 `json:"mode"`
	Severity    string                 `json:"severity"`
	Enabled     *bool                  `json:"enabled"`
	Rules       string                 `json:"rules"`
	Origin      assessments.RuleOrigin `json:"origin"`
}

type ruleSetResponse struct {
	assessments.RuleSetRecord
	Warnings []intelligence.Diagnostic `json:"warnings"`
}

var errEnforcingScope = errors.New("rulesets in alert or block mode gate verdicts; admin scope required")

// enforcing reports a ruleset whose matches can change a verdict.
func enforcing(mode string) bool { return mode != "hunt" }

func readRuleBody(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, intelligence.MaxRuleSetBytes+(1<<20)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid request body")
		return false
	}
	return true
}

func ruleError(w http.ResponseWriter, err error) {
	var compile *intelligence.RuleError
	switch {
	case errors.As(err, &compile):
		writeJSON(w, 422, map[string]any{"error": "rules do not compile", "diagnostics": compile.Diagnostics})
	case errors.Is(err, errEnforcingScope):
		writeError(w, 403, err.Error())
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "ruleset not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "ruleset name exists or revision is stale; reload and retry")
	case errors.Is(err, assessments.ErrRulePackLimit):
		writeError(w, 422, err.Error())
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid ruleset: name is lower-case letters, digits and underscores; kind custom or external; mode hunt, alert or block; severity critical, high, medium, low or info; origin url https")
	default:
		writeError(w, 500, "ruleset operation failed")
	}
}

// compile validates rules with a bounded number of compiler processes.
func (h ruleHandler) compile(ctx context.Context, w http.ResponseWriter, rules string) ([]intelligence.Diagnostic, bool) {
	select {
	case h.compiles <- struct{}{}:
		defer func() { <-h.compiles }()
	default:
		w.Header().Set("Retry-After", "5")
		writeError(w, 429, "rule compiler busy")
		return nil, false
	}
	warnings, err := h.validate(ctx, rules)
	if err != nil {
		ruleError(w, err)
		return nil, false
	}
	if warnings == nil {
		warnings = []intelligence.Diagnostic{}
	}
	return warnings, true
}

func (h ruleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath+"/intel/yara-rulesets")
	if r.Method != http.MethodGet && !principal.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	switch {
	case path == "" && r.Method == http.MethodGet:
		items, err := h.store.RuleSets(ctx)
		if err != nil {
			ruleError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == ":validate" && r.Method == http.MethodPost:
		var input struct {
			Rules string `json:"rules"`
		}
		if !readRuleBody(w, r, &input) {
			return
		}
		if warnings, ok := h.compile(ctx, w, input.Rules); ok {
			writeJSON(w, 200, map[string]any{"valid": true, "rule_count": intelligence.CountRules(input.Rules), "warnings": warnings})
		}
	case path == "" && r.Method == http.MethodPost:
		var input ruleSetInput
		if !readRuleBody(w, r, &input) {
			return
		}
		record := assessments.RuleSetRecord{Name: input.Name, Kind: input.Kind, Description: input.Description, Mode: input.Mode, Severity: input.Severity, Enabled: input.Enabled == nil || *input.Enabled, Rules: input.Rules, Origin: input.Origin}
		if record.Kind == "" {
			record.Kind = "custom"
		}
		if record.Mode == "" {
			record.Mode = "hunt"
		}
		if record.Severity == "" {
			record.Severity = "medium"
		}
		if enforcing(record.Mode) && !principal.Allows("admin") {
			ruleError(w, errEnforcingScope)
			return
		}
		warnings, ok := h.compile(ctx, w, record.Rules)
		if !ok {
			return
		}
		created, err := h.store.CreateRuleSet(ctx, record, principal.ID)
		if err != nil {
			ruleError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, created.Revision))
		w.Header().Set("Location", BasePath+"/intel/yara-rulesets/"+created.ID.String())
		writeJSON(w, 201, ruleSetResponse{created, warnings})
	case strings.HasPrefix(path, "/"):
		idPart, action, _ := strings.Cut(strings.TrimPrefix(path, "/"), ":")
		id, err := uuid.Parse(idPart)
		if err != nil {
			writeError(w, 404, "ruleset not found")
			return
		}
		h.item(ctx, w, r, principal, id, action)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h ruleHandler) item(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, action string) {
	allowed := func(before, after assessments.RuleSetRecord) error {
		if (enforcing(before.Mode) || enforcing(after.Mode)) && !principal.Allows("admin") {
			return errEnforcingScope
		}
		return nil
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		record, err := h.store.RuleSet(ctx, id)
		if err != nil {
			ruleError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, record.Revision))
		writeJSON(w, 200, record)
	case action == "" && r.Method == http.MethodPatch:
		revision, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var change assessments.RuleSetChange
		if !readRuleBody(w, r, &change) {
			return
		}
		warnings := []intelligence.Diagnostic{}
		if change.Rules != nil {
			if warnings, ok = h.compile(ctx, w, *change.Rules); !ok {
				return
			}
		}
		updated, err := h.store.UpdateRuleSet(ctx, id, revision, change, principal.ID, allowed)
		if err != nil {
			ruleError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
		writeJSON(w, 200, ruleSetResponse{updated, warnings})
	case action == "" && r.Method == http.MethodDelete:
		err := h.store.DeleteRuleSet(ctx, id, principal.ID, func(record assessments.RuleSetRecord) error { return allowed(record, record) })
		if err != nil {
			ruleError(w, err)
			return
		}
		w.WriteHeader(204)
	case action == "hunt" && r.Method == http.MethodPost:
		// Retro-hunt: rescan the default branch of every in-scope repository
		// so an enabled ruleset runs against current code.
		record, err := h.store.RuleSet(ctx, id)
		if err != nil {
			ruleError(w, err)
			return
		}
		if !record.Enabled {
			writeError(w, 409, "enable the ruleset before hunting")
			return
		}
		queued, err := h.store.EnqueueRescans(ctx, 0, 500)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 202, map[string]int{"rescans_queued": queued})
	default:
		writeError(w, 405, "method not allowed")
	}
}
