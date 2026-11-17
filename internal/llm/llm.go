// Package llm calls hosted and self-hosted model inference APIs through one
// interface. Three wire protocols cover the frontier providers: the OpenAI
// chat completions API (OpenAI, Azure OpenAI, Mistral, Groq, DeepSeek, xAI,
// OpenRouter, Together, Ollama, vLLM and other compatible gateways), the
// Anthropic Messages API and the Google Gemini generateContent API.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/llm/guard"
	"github.com/ORIBData/scrstack/internal/netguard"
)

// Preset is a provider kind's wire protocol, default inference URL and
// how the API key is sent.
type Preset struct {
	Protocol string `json:"protocol"`
	BaseURL  string `json:"base_url"`
	// Auth is bearer (Authorization: Bearer), api-key, x-api-key or
	// x-goog-api-key; KeyOptional kinds may run without one.
	Auth        string `json:"auth"`
	KeyOptional bool   `json:"key_optional"`
	// TokenField names the output limit: OpenAI's current models take
	// max_completion_tokens, compatible servers take max_tokens.
	TokenField string `json:"-"`
}

// Presets lists the supported provider kinds. Every base URL can be
// overridden, so a regional endpoint or a gateway (LiteLLM, Portkey, a
// corporate proxy) fronting another provider works as openai_compatible.
var Presets = map[string]Preset{
	"openai":            {Protocol: "openai", BaseURL: "https://api.openai.com/v1", Auth: "bearer", TokenField: "max_completion_tokens"},
	"azure_openai":      {Protocol: "openai", Auth: "api-key", TokenField: "max_completion_tokens"},
	"anthropic":         {Protocol: "anthropic", BaseURL: "https://api.anthropic.com/v1", Auth: "x-api-key"},
	"gemini":            {Protocol: "gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta", Auth: "x-goog-api-key"},
	"mistral":           {Protocol: "openai", BaseURL: "https://api.mistral.ai/v1", Auth: "bearer", TokenField: "max_tokens"},
	"groq":              {Protocol: "openai", BaseURL: "https://api.groq.com/openai/v1", Auth: "bearer", TokenField: "max_tokens"},
	"deepseek":          {Protocol: "openai", BaseURL: "https://api.deepseek.com/v1", Auth: "bearer", TokenField: "max_tokens"},
	"xai":               {Protocol: "openai", BaseURL: "https://api.x.ai/v1", Auth: "bearer", TokenField: "max_tokens"},
	"openrouter":        {Protocol: "openai", BaseURL: "https://openrouter.ai/api/v1", Auth: "bearer", TokenField: "max_tokens"},
	"together":          {Protocol: "openai", BaseURL: "https://api.together.xyz/v1", Auth: "bearer", TokenField: "max_tokens"},
	"ollama":            {Protocol: "openai", BaseURL: "http://localhost:11434/v1", Auth: "bearer", KeyOptional: true, TokenField: "max_tokens"},
	"openai_compatible": {Protocol: "openai", Auth: "bearer", KeyOptional: true, TokenField: "max_tokens"},
}

// Provider is a configured model endpoint's non-secret settings.
type Provider struct {
	Kind        string   `json:"kind"`
	BaseURL     string   `json:"base_url"`
	Model       string   `json:"model"`
	MaxTokens   int      `json:"max_tokens"`
	Temperature *float64 `json:"temperature,omitempty"`
}

// Secret is the sealed part of a provider.
type Secret struct {
	APIKey string `json:"api_key,omitempty"`
}

var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)

// Resolve fills the preset's base URL when none is set.
func (p Provider) Resolve() Provider {
	if p.BaseURL == "" {
		p.BaseURL = Presets[p.Kind].BaseURL
	}
	p.BaseURL = strings.TrimSuffix(p.BaseURL, "/")
	return p
}

// Validate checks settings and the key they need. Plain http is accepted
// only for hosts in private, the operator's list of self-hosted servers.
func Validate(p Provider, s Secret, private map[string]bool) error {
	preset, ok := Presets[p.Kind]
	if !ok {
		return errors.New("kind must be one of openai, azure_openai, anthropic, gemini, mistral, groq, deepseek, xai, openrouter, together, ollama or openai_compatible")
	}
	p = p.Resolve()
	if p.BaseURL == "" {
		return fmt.Errorf("kind %s needs a base_url", p.Kind)
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(p.BaseURL) > 2048 {
		return errors.New("base_url must be an absolute URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && private[strings.ToLower(u.Hostname())]) {
		return errors.New("base_url must use https; plain http is allowed only for hosts in SCRS_LLM_PRIVATE_HOSTS")
	}
	if !modelName.MatchString(p.Model) {
		return errors.New("model must be the provider's model or deployment name")
	}
	if p.MaxTokens < 256 || p.MaxTokens > 131072 {
		return errors.New("max_tokens must be 256 to 131072")
	}
	if p.Temperature != nil && (*p.Temperature < 0 || *p.Temperature > 2) {
		return errors.New("temperature must be 0 to 2")
	}
	if len(s.APIKey) > 4096 || strings.ContainsAny(s.APIKey, "\r\n") {
		return errors.New("api_key is invalid")
	}
	if s.APIKey == "" && !preset.KeyOptional {
		return fmt.Errorf("kind %s needs an api_key", p.Kind)
	}
	return nil
}

// Request is one completion: a system instruction and a user message.
type Request struct {
	System string
	Prompt string
	// MaxTokens overrides the provider's limit when lower and positive.
	MaxTokens int
	// Schema asks for output that matches a JSON Schema (response_format
	// json_schema, strict) from OpenAI and Azure OpenAI. Other providers
	// ignore it, so callers still validate what comes back.
	Schema     json.RawMessage
	SchemaName string
}

// Redactions counts what the guard replaced, by kind. Values are never kept.
type Redactions struct {
	Input  map[string]int `json:"input,omitempty"`
	Output map[string]int `json:"output,omitempty"`
}

// Response is the model's text and token usage.
type Response struct {
	Text         string `json:"text"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	// Truncated reports that the output stopped at the token limit.
	Truncated bool `json:"truncated"`
	// Redactions is what the guard removed from the prompt and the answer.
	Redactions Redactions `json:"redactions"`
}

// Client calls one provider.
type Client struct {
	provider Provider
	preset   Preset
	secret   Secret
	http     *http.Client
	// retryWait is the pause before a retry when the server names none.
	retryWait time.Duration
	// guard screens every prompt and answer; it cannot be switched off.
	guard *guard.Guard
}

// NewClient builds a client whose connections pass netguard; hosts in
// private may resolve to internal addresses (a self-hosted model server).
func NewClient(p Provider, s Secret, private map[string]bool) (*Client, error) {
	if err := Validate(p, s, private); err != nil {
		return nil, err
	}
	timeout := RequestTimeout()
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           netguard.DialContext(private),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout - 30*time.Second,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	}
	// Redirects could carry the key elsewhere; they are refused.
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// The guard knows this process's own secrets (master key, database and
	// API tokens from the environment) and the provider key being used.
	g := guard.New(append(guard.KnownFromEnv(os.Environ()), s.APIKey)...)
	return &Client{provider: p.Resolve(), preset: Presets[p.Kind], secret: s, http: client, retryWait: 2 * time.Second, guard: g}, nil
}

// RequestTimeout is how long one model call may take, from SCRS_LLM_TIMEOUT_SECONDS
// (default 360, allowed 60 to 3600). A hosted provider answers in seconds; a
// model on CPU can need many minutes for a long file, so raise it for those.
func RequestTimeout() time.Duration {
	n, err := strconv.Atoi(os.Getenv("SCRS_LLM_TIMEOUT_SECONDS"))
	if err != nil || n < 60 || n > 3600 {
		n = 360
	}
	return time.Duration(n) * time.Second
}

// MaxResponseBytes bounds a provider response body.
const MaxResponseBytes = 8 << 20

// Complete sends one request. Rate limits and server errors are retried
// twice; other failures return at once with the provider's reason.
func (c *Client) Complete(ctx context.Context, r Request) (Response, error) {
	var in map[string]int
	r.System, in = c.guard.Screen(r.System)
	var prompt map[string]int
	r.Prompt, prompt = c.guard.Screen(r.Prompt)
	in = guard.Merge(in, prompt)
	resp, err := c.complete(ctx, r)
	if err != nil {
		return resp, err
	}
	var out map[string]int
	resp.Text, out = c.guard.ScreenOutput(resp.Text)
	resp.Redactions = Redactions{Input: nilIfEmpty(in), Output: nilIfEmpty(out)}
	return resp, nil
}

func nilIfEmpty(m map[string]int) map[string]int {
	if len(m) == 0 {
		return nil
	}
	return m
}

func (c *Client) complete(ctx context.Context, r Request) (Response, error) {
	limit := c.provider.MaxTokens
	if r.MaxTokens > 0 && r.MaxTokens < limit {
		limit = r.MaxTokens
	}
	target, body := c.encode(r, limit)
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		resp, retry, wait, err := c.send(ctx, target, body)
		if err == nil {
			return resp, nil
		}
		last = err
		if !retry || attempt == 2 {
			break
		}
		if wait <= 0 {
			wait = c.retryWait << attempt
		}
		select {
		case <-ctx.Done():
			return Response{}, ctx.Err()
		case <-time.After(wait):
		}
	}
	return Response{}, last
}

func (c *Client) encode(r Request, limit int) (string, []byte) {
	var payload any
	target := c.provider.BaseURL
	switch c.preset.Protocol {
	case "anthropic":
		target += "/messages"
		body := map[string]any{"model": c.provider.Model, "max_tokens": limit, "messages": []map[string]string{{"role": "user", "content": r.Prompt}}}
		if r.System != "" {
			body["system"] = r.System
		}
		if c.provider.Temperature != nil {
			body["temperature"] = *c.provider.Temperature
		}
		payload = body
	case "gemini":
		target += "/models/" + url.PathEscape(c.provider.Model) + ":generateContent"
		config := map[string]any{"maxOutputTokens": limit}
		if c.provider.Temperature != nil {
			config["temperature"] = *c.provider.Temperature
		}
		body := map[string]any{"contents": []map[string]any{{"role": "user", "parts": []map[string]string{{"text": r.Prompt}}}}, "generationConfig": config}
		if r.System != "" {
			body["systemInstruction"] = map[string]any{"parts": []map[string]string{{"text": r.System}}}
		}
		payload = body
	default:
		target += "/chat/completions"
		messages := []map[string]string{}
		if r.System != "" {
			messages = append(messages, map[string]string{"role": "system", "content": r.System})
		}
		messages = append(messages, map[string]string{"role": "user", "content": r.Prompt})
		body := map[string]any{"model": c.provider.Model, "messages": messages, c.preset.TokenField: limit}
		if c.provider.Temperature != nil {
			body["temperature"] = *c.provider.Temperature
		}
		if len(r.Schema) > 0 && (c.provider.Kind == "openai" || c.provider.Kind == "azure_openai") {
			name := r.SchemaName
			if name == "" {
				name = "result"
			}
			body["response_format"] = map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": name, "strict": true, "schema": r.Schema}}
		}
		payload = body
	}
	encoded, _ := json.Marshal(payload)
	return target, encoded
}

// send makes one attempt. It reports whether a failure may be retried and
// the server's requested wait.
func (c *Client) send(ctx context.Context, target string, body []byte) (Response, bool, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return Response{}, false, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if key := c.secret.APIKey; key != "" {
		switch c.preset.Auth {
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+key)
		case "api-key":
			req.Header.Set("api-key", key)
		case "x-api-key":
			req.Header.Set("x-api-key", key)
		case "x-goog-api-key":
			req.Header.Set("x-goog-api-key", key)
		}
	}
	if c.preset.Protocol == "anthropic" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, false, 0, ctx.Err()
		}
		return Response{}, true, 0, fmt.Errorf("model endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return Response{}, true, 0, fmt.Errorf("model response read failed: %w", err)
	}
	if len(data) > MaxResponseBytes {
		return Response{}, false, 0, errors.New("model response is over 8 MiB")
	}
	if resp.StatusCode != http.StatusOK {
		return c.failure(resp, data)
	}
	out, err := c.decode(data)
	return out, false, 0, err
}

// failure turns an error status into a message that names the cause and
// quotes the provider's own reason, which never contains the key.
func (c *Client) failure(resp *http.Response, data []byte) (Response, bool, time.Duration, error) {
	reason := providerReason(data)
	if reason != "" {
		reason = ": " + reason
	}
	wait := time.Duration(0)
	if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
		wait = min(time.Duration(seconds)*time.Second, 30*time.Second)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Response{}, false, 0, fmt.Errorf("model provider refused the API key (HTTP %d)%s", resp.StatusCode, reason)
	case resp.StatusCode == http.StatusNotFound:
		return Response{}, false, 0, fmt.Errorf("model or endpoint not found (HTTP 404); check base_url and model%s", reason)
	case resp.StatusCode == http.StatusTooManyRequests:
		return Response{}, true, wait, fmt.Errorf("model provider rate limit reached (HTTP 429)%s", reason)
	case resp.StatusCode >= 500:
		return Response{}, true, wait, fmt.Errorf("model provider error (HTTP %d)%s", resp.StatusCode, reason)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return Response{}, false, 0, fmt.Errorf("model endpoint redirected (HTTP %d); set base_url to the final URL", resp.StatusCode)
	}
	return Response{}, false, 0, fmt.Errorf("model provider rejected the request (HTTP %d)%s", resp.StatusCode, reason)
}

// providerReason extracts the error message the common error envelopes carry.
func providerReason(data []byte) string {
	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return ""
	}
	message := envelope.Message
	var nested struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(envelope.Error, &nested) == nil && nested.Message != "" {
		message = nested.Message
	} else if message == "" {
		_ = json.Unmarshal(envelope.Error, &message)
	}
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}

func (c *Client) decode(data []byte) (Response, error) {
	out := Response{Model: c.provider.Model}
	switch c.preset.Protocol {
	case "anthropic":
		var body struct {
			Model   string `json:"model"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			StopReason string `json:"stop_reason"`
			Usage      struct {
				Input  int `json:"input_tokens"`
				Output int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(data, &body) != nil {
			return out, errors.New("model response is not a Messages API result")
		}
		var text strings.Builder
		for _, block := range body.Content {
			if block.Type == "text" {
				text.WriteString(block.Text)
			}
		}
		out.Text, out.InputTokens, out.OutputTokens = text.String(), body.Usage.Input, body.Usage.Output
		out.Truncated = body.StopReason == "max_tokens"
		if body.Model != "" {
			out.Model = body.Model
		}
	case "gemini":
		var body struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text    string `json:"text"`
						Thought bool   `json:"thought"`
					} `json:"parts"`
				} `json:"content"`
				FinishReason string `json:"finishReason"`
			} `json:"candidates"`
			Usage struct {
				Prompt     int `json:"promptTokenCount"`
				Candidates int `json:"candidatesTokenCount"`
			} `json:"usageMetadata"`
			ModelVersion string `json:"modelVersion"`
		}
		if json.Unmarshal(data, &body) != nil || len(body.Candidates) == 0 {
			return out, errors.New("model response has no candidates; the prompt may have been blocked")
		}
		var text strings.Builder
		for _, part := range body.Candidates[0].Content.Parts {
			if !part.Thought {
				text.WriteString(part.Text)
			}
		}
		out.Text, out.InputTokens, out.OutputTokens = text.String(), body.Usage.Prompt, body.Usage.Candidates
		out.Truncated = body.Candidates[0].FinishReason == "MAX_TOKENS"
		if body.ModelVersion != "" {
			out.Model = body.ModelVersion
		}
	default:
		var body struct {
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Content json.RawMessage `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage struct {
				Prompt     int `json:"prompt_tokens"`
				Completion int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(data, &body) != nil || len(body.Choices) == 0 {
			return out, errors.New("model response is not a chat completion")
		}
		out.Text = contentText(body.Choices[0].Message.Content)
		out.InputTokens, out.OutputTokens = body.Usage.Prompt, body.Usage.Completion
		out.Truncated = body.Choices[0].FinishReason == "length"
		if body.Model != "" {
			out.Model = body.Model
		}
	}
	if strings.TrimSpace(out.Text) == "" {
		return out, errors.New("model returned no text")
	}
	return out, nil
}

// contentText reads a chat message's content, a string or a list of parts.
func contentText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "text" || p.Type == "" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}
