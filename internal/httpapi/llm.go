package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/google/uuid"
)

// llmHandler manages LLM providers (QA test generation). Reading needs read
// scope; creating, changing, deleting and testing need admin, since a
// provider receives repository source and API documents.
type llmHandler struct {
	store   *assessments.Store
	secrets Sealer
	// hosts may resolve to private addresses (SCRS_LLM_PRIVATE_HOSTS).
	hosts map[string]bool
}

type providerInput struct {
	Name        *string  `json:"name"`
	Kind        *string  `json:"kind"`
	BaseURL     *string  `json:"base_url"`
	Model       *string  `json:"model"`
	MaxTokens   *int     `json:"max_tokens"`
	Temperature *float64 `json:"temperature"`
	// ClearTemperature removes a set temperature (PATCH).
	ClearTemperature bool    `json:"clear_temperature"`
	Enabled          *bool   `json:"enabled"`
	APIKey           *string `json:"api_key"`
}

type llmConfigError struct{ message string }

func (e llmConfigError) Error() string { return e.message }

func llmError(w http.ResponseWriter, err error) {
	var config llmConfigError
	switch {
	case errors.As(err, &config):
		writeError(w, 400, "invalid LLM provider: "+config.message)
	case errors.Is(err, errQAAdmin):
		writeError(w, 403, err.Error())
	case errors.Is(err, errNoSealer):
		writeError(w, 503, err.Error())
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid LLM provider: name is 2-63 lower-case letters, digits, hyphens or underscores")
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "LLM provider not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "provider name exists or revision is stale; reload and retry")
	default:
		writeError(w, 500, "LLM provider operation failed")
	}
}

// apply merges input over a provider and key, then validates the result.
func (in providerInput) apply(p assessments.LLMProvider, s llm.Secret, hosts map[string]bool) (assessments.LLMProvider, llm.Secret, error) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = strings.TrimSpace(*src)
		}
	}
	set(&p.Kind, in.Kind)
	set(&p.BaseURL, in.BaseURL)
	set(&p.Model, in.Model)
	if in.MaxTokens != nil {
		p.MaxTokens = *in.MaxTokens
	}
	if in.Temperature != nil {
		p.Temperature = in.Temperature
	}
	if in.ClearTemperature {
		p.Temperature = nil
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.APIKey != nil {
		s.APIKey = *in.APIKey
	}
	p.BaseURL = strings.TrimSuffix(p.BaseURL, "/")
	if err := llm.Validate(llmSettings(p), s, hosts); err != nil {
		return p, s, llmConfigError{err.Error()}
	}
	return p, s, nil
}

func llmSettings(p assessments.LLMProvider) llm.Provider {
	return llm.Provider{Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model, MaxTokens: p.MaxTokens, Temperature: p.Temperature}
}

func (h llmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	rest := strings.TrimPrefix(r.URL.Path, BasePath+"/llm/")
	if r.Method != http.MethodGet && !principal.Allows("admin") {
		llmError(w, errQAAdmin)
		return
	}
	switch {
	case rest == "presets" && r.Method == http.MethodGet:
		kinds := make([]string, 0, len(llm.Presets))
		for k := range llm.Presets {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		items := make([]map[string]any, 0, len(kinds))
		for _, k := range kinds {
			p := llm.Presets[k]
			items = append(items, map[string]any{"kind": k, "protocol": p.Protocol, "base_url": p.BaseURL, "base_url_required": p.BaseURL == "", "api_key_optional": p.KeyOptional})
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	case rest == "providers" && r.Method == http.MethodGet:
		items, err := h.store.LLMProviders(ctx)
		if err != nil {
			llmError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	case rest == "providers" && r.Method == http.MethodPost:
		h.create(ctx, w, r, principal)
		return
	}
	raw, ok := strings.CutPrefix(rest, "providers/")
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	raw, action, _ := strings.Cut(raw, ":")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, 404, "LLM provider not found")
		return
	}
	switch action + " " + r.Method {
	case " GET":
		p, err := h.store.LLMProviderByID(ctx, id)
		if err != nil {
			llmError(w, err)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(p.Revision, 10)))
		writeJSON(w, 200, p)
	case " PATCH":
		revision, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var input providerInput
		if !readBody(w, r, &input) {
			return
		}
		if input.Name != nil {
			writeError(w, 400, "a provider's name cannot change")
			return
		}
		before, secret, err := h.withKey(ctx, id)
		if err != nil {
			llmError(w, err)
			return
		}
		after, secret, err := input.apply(before, secret, h.hosts)
		if err != nil {
			llmError(w, err)
			return
		}
		var sealed []byte
		if input.APIKey != nil {
			if sealed, err = h.seal(id, secret); err != nil {
				llmError(w, err)
				return
			}
		}
		updated, err := h.store.UpdateLLMProvider(ctx, after, revision, sealed, principal.ID)
		if err != nil {
			llmError(w, err)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(updated.Revision, 10)))
		writeJSON(w, 200, updated)
	case " DELETE":
		if err := h.store.DeleteLLMProvider(ctx, id, principal.ID); err != nil {
			llmError(w, err)
			return
		}
		w.WriteHeader(204)
	case "test POST":
		h.test(ctx, w, id)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h llmHandler) seal(id uuid.UUID, s llm.Secret) ([]byte, error) {
	if h.secrets == nil {
		return nil, errNoSealer
	}
	if s.APIKey == "" {
		return []byte{}, nil
	}
	plain, _ := json.Marshal(s)
	return h.secrets.Seal(plain, assessments.LLMAAD(id))
}

// withKey loads a provider and opens its key.
func (h llmHandler) withKey(ctx context.Context, id uuid.UUID) (assessments.LLMProvider, llm.Secret, error) {
	var secret llm.Secret
	p, sealed, err := h.store.LLMProviderCredential(ctx, id)
	if err != nil || len(sealed) == 0 {
		return p, secret, err
	}
	if h.secrets == nil {
		return p, secret, errNoSealer
	}
	plain, err := h.secrets.Unseal(sealed, assessments.LLMAAD(id))
	if err != nil {
		return p, secret, err
	}
	if json.Unmarshal(plain, &secret) != nil {
		return p, secret, errors.New("LLM provider key invalid")
	}
	return p, secret, nil
}

func (h llmHandler) create(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token) {
	var input providerInput
	if !readBody(w, r, &input) {
		return
	}
	if input.Name == nil {
		writeError(w, 400, "name required")
		return
	}
	if h.secrets == nil {
		llmError(w, errNoSealer)
		return
	}
	p, secret, err := input.apply(assessments.LLMProvider{Name: strings.TrimSpace(*input.Name), MaxTokens: 8192, Enabled: true}, llm.Secret{}, h.hosts)
	if err != nil {
		llmError(w, err)
		return
	}
	created, err := h.store.CreateLLMProvider(ctx, p, principal.ID, func(id uuid.UUID) ([]byte, error) { return h.seal(id, secret) })
	if err != nil {
		llmError(w, err)
		return
	}
	w.Header().Set("Location", BasePath+"/llm/providers/"+created.ID.String())
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(created.Revision, 10)))
	writeJSON(w, 201, created)
}

// test sends a one-line prompt with the stored settings and key, so an
// admin can check the endpoint, model and key before a generation.
func (h llmHandler) test(ctx context.Context, w http.ResponseWriter, id uuid.UUID) {
	p, secret, err := h.withKey(ctx, id)
	if err != nil {
		llmError(w, err)
		return
	}
	client, err := llm.NewClient(llmSettings(p), secret, h.hosts)
	if err != nil {
		llmError(w, llmConfigError{err.Error()})
		return
	}
	started := time.Now()
	resp, err := client.Complete(ctx, llm.Request{System: "You are a connectivity check. Reply with the single word OK.", Prompt: "Reply with OK.", MaxTokens: min(p.MaxTokens, 1024)})
	latency := time.Since(started).Milliseconds()
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	recordCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	_ = h.store.RecordLLMTest(recordCtx, id, failure)
	done()
	if err != nil {
		writeJSON(w, 502, map[string]any{"ok": false, "error": failure, "latency_ms": latency})
		return
	}
	reply := strings.TrimSpace(resp.Text)
	if len(reply) > 200 {
		reply = reply[:200]
	}
	writeJSON(w, 200, map[string]any{"ok": true, "model": resp.Model, "reply": reply, "latency_ms": latency, "input_tokens": resp.InputTokens, "output_tokens": resp.OutputTokens})
}
