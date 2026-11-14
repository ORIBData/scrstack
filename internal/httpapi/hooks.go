package httpapi

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
)

// hookChecker is the GitHub webhook delivery check (INT-001 backstop).
type hookChecker interface {
	GitHubHookChecks(context.Context) ([]connections.HookCheck, error)
	CheckGitHubHooks(context.Context, connections.HookAPI, string, time.Time) ([]connections.HookCheck, bool, error)
}

type hookHandler struct {
	store hookChecker
	api   connections.HookAPI
}

func (h hookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if r.Method == http.MethodGet {
		checks, err := h.store.GitHubHookChecks(ctx)
		if err != nil {
			writeError(w, 500, "webhook check state unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"items": checks})
		return
	}
	checks, ran, err := h.store.CheckGitHubHooks(ctx, h.api, os.Getenv("SCRS_GITHUB_HOOK_URL"), time.Now())
	if err != nil {
		writeError(w, 500, "webhook check failed")
		return
	}
	if !ran {
		w.Header().Set("Retry-After", "30")
		writeError(w, 409, "a webhook check is already running")
		return
	}
	writeJSON(w, 200, map[string]any{"items": checks})
}
