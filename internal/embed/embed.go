// Package embed turns text into vectors with a self-hosted embedding server
// that speaks the OpenAI embeddings API (POST {base}/embeddings): Hugging
// Face Text Embeddings Inference, Ollama, vLLM and similar. SCRS never sends
// text to a hosted provider for embedding.
//
// Text is screened for credentials before it is sent, vectors are checked for
// the configured dimension and normalised to unit length (so a dot product is
// the cosine similarity), and the endpoint is reached only through the
// netguard dialer: https, or http for hosts the operator names.
package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

// Config is the embedding endpoint.
type Config struct {
	// BaseURL is the API root, such as http://scrs-embed:80/v1.
	BaseURL string
	// Model names the model; it is recorded with every vector so vectors of
	// different models are never compared.
	Model string
	// Dim is the vector length the model produces.
	Dim int
	// APIKey is optional; a private server often has none.
	APIKey string
	// MaxBatch is how many texts go in one request (default 32).
	MaxBatch int
	// MaxChars bounds one text (default 1500, about 400 tokens, inside the
	// 512-token window of small models such as bge-small); longer text is an
	// error, since silent truncation would drop content from the knowledge base.
	MaxChars int
}

// ConfigFromEnv reads SCRS_EMBED_URL, SCRS_EMBED_MODEL, SCRS_EMBED_DIM and
// SCRS_EMBED_API_KEY. ok is false when no URL is set (the feature is off).
func ConfigFromEnv() (Config, bool, error) {
	base := strings.TrimSpace(os.Getenv("SCRS_EMBED_URL"))
	if base == "" {
		return Config{}, false, nil
	}
	dim, err := strconv.Atoi(os.Getenv("SCRS_EMBED_DIM"))
	if err != nil {
		return Config{}, true, errors.New("SCRS_EMBED_DIM must be the model's vector length")
	}
	cfg := Config{BaseURL: base, Model: os.Getenv("SCRS_EMBED_MODEL"), Dim: dim, APIKey: os.Getenv("SCRS_EMBED_API_KEY")}
	if raw := os.Getenv("SCRS_EMBED_MAX_CHARS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 200 || n > 8000 {
			return Config{}, true, errors.New("SCRS_EMBED_MAX_CHARS must be 200 to 8000")
		}
		cfg.MaxChars = n
	}
	return cfg, true, nil
}

var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)

// Validate checks the settings. Plain http is accepted only for hosts in
// private (SCRS_EMBED_PRIVATE_HOSTS).
func (c Config) Validate(private map[string]bool) error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(c.BaseURL) > 2048 {
		return errors.New("embedding URL must be absolute, without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && private[strings.ToLower(u.Hostname())]) {
		return errors.New("embedding URL must use https; plain http is allowed only for hosts in SCRS_EMBED_PRIVATE_HOSTS")
	}
	if !modelName.MatchString(c.Model) {
		return errors.New("embedding model name is missing or invalid")
	}
	if c.Dim < 8 || c.Dim > 8192 {
		return errors.New("embedding dimension must be 8 to 8192")
	}
	return nil
}

// Client embeds text.
type Client struct {
	cfg   Config
	http  *http.Client
	guard *guard.Guard
}

// New builds a client; connections pass netguard.
func New(cfg Config, private map[string]bool) (*Client, error) {
	if err := cfg.Validate(private); err != nil {
		return nil, err
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 32
	}
	if cfg.MaxChars <= 0 {
		cfg.MaxChars = 1500
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           netguard.DialContext(private),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	}
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{cfg: cfg, http: httpClient, guard: guard.New(append(guard.KnownFromEnv(os.Environ()), cfg.APIKey)...)}, nil
}

// Model is the model name recorded with each vector.
func (c *Client) Model() string { return c.cfg.Model }

// Dim is the vector length.
func (c *Client) Dim() int { return c.cfg.Dim }

// maxResponse bounds one answer: 32 texts of 8192 floats is about 5 MiB.
const maxResponse = 32 << 20

// Embed returns one unit-length vector per text, in order. Texts are screened
// for credentials first. It retries rate limits and server errors twice.
func (c *Client) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, 0, len(texts))
	for start := 0; start < len(texts); start += c.cfg.MaxBatch {
		end := min(start+c.cfg.MaxBatch, len(texts))
		batch := make([]string, 0, end-start)
		for _, t := range texts[start:end] {
			if strings.TrimSpace(t) == "" {
				return nil, errors.New("cannot embed empty text")
			}
			if len(t) > c.cfg.MaxChars {
				return nil, fmt.Errorf("text of %d characters is over the %d limit; split it first", len(t), c.cfg.MaxChars)
			}
			clean, _ := c.guard.Screen(t)
			batch = append(batch, clean)
		}
		vectors, err := c.embedBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, vectors...)
	}
	return out, nil
}

func (c *Client) embedBatch(ctx context.Context, batch []string) ([][]float32, error) {
	body, _ := json.Marshal(map[string]any{"model": c.cfg.Model, "input": batch})
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		vectors, retry, err := c.send(ctx, body, len(batch))
		if err == nil {
			return vectors, nil
		}
		last = err
		if !retry || attempt == 2 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second << attempt):
		}
	}
	return nil, last
}

func (c *Client) send(ctx context.Context, body []byte, want int) ([][]float32, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, errors.New("embedding server unreachable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return nil, false, errors.New("embedding response unreadable or too large")
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("embedding server error (HTTP %d)", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("embedding server rejected the request (HTTP %d); check SCRS_EMBED_URL and the model", resp.StatusCode)
	}
	var parsed struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &parsed) != nil || len(parsed.Data) != want {
		return nil, false, errors.New("embedding server answered with an unexpected shape")
	}
	vectors := make([][]float32, want)
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= want || vectors[d.Index] != nil {
			return nil, false, errors.New("embedding server returned a bad index")
		}
		if len(d.Embedding) != c.cfg.Dim {
			return nil, false, fmt.Errorf("embedding has %d dimensions, SCRS_EMBED_DIM says %d", len(d.Embedding), c.cfg.Dim)
		}
		v, err := normalise(d.Embedding)
		if err != nil {
			return nil, false, err
		}
		vectors[d.Index] = v
	}
	return vectors, false, nil
}

// normalise scales to unit length; an all-zero or non-finite vector is an
// error, since it would match everything or nothing.
func normalise(in []float64) ([]float32, error) {
	var sum float64
	for _, x := range in {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, errors.New("embedding contains a non-finite value")
		}
		sum += x * x
	}
	if sum == 0 {
		return nil, errors.New("embedding is all zeros")
	}
	norm := math.Sqrt(sum)
	out := make([]float32, len(in))
	for i, x := range in {
		out[i] = float32(x / norm)
	}
	return out, nil
}
