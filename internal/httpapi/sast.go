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
	"github.com/ORIBData/scrstack/internal/sast"
	"github.com/google/uuid"
)

// sastHandler serves analyzer visibility (SAST-009, REA-007), settings
// (SAST-002, REA-011) and custom rulesets (SAST-007).
type sastHandler struct {
	store    *assessments.Store
	client   *sast.Client
	defaults assessments.SASTDefaults
}

// staticAnalyzers describe the bundled set when the service is unreachable.
var staticAnalyzers = []sast.Meta{
	sast.Gosec{}.Meta(), sast.Bandit{}.Meta(), (&sast.OpenGrep{}).Meta(), (&sast.Bearer{}).Meta(),
}

func sastError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "revision is stale; read the current settings and retry")
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "rules are tool:rule ids (globs allowed), excludes are path globs, analyzers are gosec, bandit, opengrep or bearer")
	default:
		writeError(w, 500, "SAST operation failed")
	}
}

func (h sastHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath)
	switch {
	case path == "/sast/analyzers" && r.Method == http.MethodGet:
		out := map[string]any{"enabled_by_default": h.defaults.Enabled, "service": "unconfigured"}
		if h.client != nil {
			analyzers, reach, err := h.client.Analyzers(ctx)
			if err == nil {
				out["service"], out["analyzers"], out["reachability"] = "ok", analyzers, reach
				writeJSON(w, 200, out)
				return
			}
			out["service"] = "unavailable"
		}
		static := []sast.Info{}
		for _, m := range staticAnalyzers {
			static = append(static, sast.Info{Meta: m, Version: "unknown", Rules: -1})
		}
		out["analyzers"] = static
		writeJSON(w, 200, out)
	case path == "/reachability/capabilities" && r.Method == http.MethodGet:
		version := "unknown"
		if h.client != nil {
			if _, reach, err := h.client.Analyzers(ctx); err == nil && reach != nil {
				version = reach.Version
			}
		}
		writeJSON(w, 200, map[string]any{"enabled_by_default": h.defaults.Reachability, "capabilities": []map[string]any{
			{"ecosystem": "Go", "method": "call_graph", "tool": "govulncheck", "version": version, "statuses": []string{sast.Reachable, sast.ImportedOnly, sast.NotReachable, sast.Unknown}, "notes": "Module sources come through the go-modules egress proxy; private modules and the standard library report unknown."},
			{"ecosystem": "Rust", "method": "none", "status": sast.Unsupported, "notes": "Rust call analysis compiles the code; it is not offered (REA-006)."},
			{"ecosystem": "npm", "method": "import_graph", "tool": "scrs-imports", "version": "1", "statuses": []string{sast.ImportedOnly, sast.Unknown}, "notes": "Reads the imports of the repository's own JavaScript and TypeScript source. A package it imports is imported_only; any other stays unknown, never not_reachable, because another dependency may still reach it."},
			{"ecosystem": "PyPI", "method": "import_graph", "tool": "scrs-imports", "version": "1", "statuses": []string{sast.ImportedOnly, sast.Unknown}, "notes": "As for npm, on Python source. A distribution is matched to its module names by its own name and a short table of common differences (for example beautifulsoup4 and bs4); others stay unknown."},
			{"ecosystem": "Maven, NuGet, RubyGems, Pub, CocoaPods, SwiftURL", "method": "none", "status": sast.Unsupported, "notes": "No verified open-source call-graph analyzer (spike S12) and no import-level reader."},
		}})
	case path == "/sast/settings":
		h.globalSettings(ctx, w, r, principal)
	case strings.HasPrefix(path, "/assets/"):
		h.assetSettings(ctx, w, r, principal)
	case path == "/sast/rulesets" || strings.HasPrefix(path, "/sast/rulesets/"):
		h.rulesets(ctx, w, r, principal, strings.TrimPrefix(strings.TrimPrefix(path, "/sast/rulesets"), "/"))
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h sastHandler) globalSettings(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token) {
	if r.Method == http.MethodGet {
		g, err := h.store.GlobalSASTSettings(ctx)
		if err != nil {
			sastError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(g.Revision, 10)+`"`)
		writeJSON(w, 200, g)
		return
	}
	if !principal.Allows("admin") {
		writeError(w, 403, "admin scope required")
		return
	}
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var input struct {
		DisabledRules []string `json:"disabled_rules"`
		Excludes      []string `json:"excludes"`
	}
	if !readBody(w, r, &input) {
		return
	}
	g, err := h.store.SetGlobalSASTSettings(ctx, assessments.GlobalSAST{DisabledRules: input.DisabledRules, Excludes: input.Excludes}, expected, principal.ID)
	if err != nil {
		sastError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(g.Revision, 10)+`"`)
	writeJSON(w, 200, g)
}

func (h sastHandler) assetSettings(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "not found")
		return
	}
	if r.Method == http.MethodGet {
		a, err := h.store.AssetSASTSettings(ctx, id)
		if err != nil {
			sastError(w, err)
			return
		}
		effective, err := h.store.EffectiveSASTSettings(ctx, id, h.defaults)
		if err != nil {
			sastError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(a.Revision, 10)+`"`)
		writeJSON(w, 200, map[string]any{"settings": a, "effective": effective})
		return
	}
	if !principal.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var input assessments.AssetSAST
	if !readBody(w, r, &input) {
		return
	}
	a, err := h.store.SetAssetSASTSettings(ctx, id, input, expected, principal.ID)
	if err != nil {
		sastError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(a.Revision, 10)+`"`)
	writeJSON(w, 200, a)
}

func (h sastHandler) rulesets(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, rest string) {
	switch {
	case rest == "" && r.Method == http.MethodGet:
		items, err := h.store.SASTRulesets(ctx)
		if err != nil {
			sastError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case rest == "" && r.Method == http.MethodPost:
		if !principal.Allows("write") {
			writeError(w, 403, "write scope required")
			return
		}
		var input struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Enabled     *bool  `json:"enabled"`
			Rules       string `json:"rules"`
		}
		if !readBodyLimit(w, r, &input, 1<<20+4096) {
			return
		}
		if h.client == nil {
			writeError(w, 503, "SAST service not configured; rules cannot be validated")
			return
		}
		valid, message, err := h.client.Validate(ctx, []byte(input.Rules))
		if err != nil {
			writeError(w, 502, "rule validation failed: "+err.Error())
			return
		}
		if !valid {
			writeError(w, 422, "invalid OpenGrep rules: "+message)
			return
		}
		enabled := input.Enabled == nil || *input.Enabled
		saved, err := h.store.SaveSASTRuleset(ctx, input.Name, input.Description, input.Rules, enabled, principal.ID)
		if err != nil {
			sastError(w, err)
			return
		}
		writeJSON(w, 201, saved)
	default:
		id, err := uuid.Parse(rest)
		if err != nil {
			writeError(w, 404, "not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			rs, err := h.store.SASTRuleset(ctx, id)
			if err != nil {
				sastError(w, err)
				return
			}
			writeJSON(w, 200, rs)
		case http.MethodDelete:
			if !principal.Allows("admin") {
				writeError(w, 403, "admin scope required")
				return
			}
			if err := h.store.DeleteSASTRuleset(ctx, id, principal.ID); err != nil {
				sastError(w, err)
				return
			}
			w.WriteHeader(204)
		default:
			writeError(w, 405, "method not allowed")
		}
	}
}
