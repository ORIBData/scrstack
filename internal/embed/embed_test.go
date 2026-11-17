package embed

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

var local = map[string]bool{"127.0.0.1": true}

func serve(t *testing.T, handler func(inputs []string, call int) (int, any)) (*httptest.Server, *[][]string) {
	t.Helper()
	var calls int32
	var seen [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		var body struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body.Input)
		status, reply := handler(body.Input, int(atomic.AddInt32(&calls, 1)))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

// vectors answers like Text Embeddings Inference: one vector per input, out
// of order, with the index saying which.
func vectors(dim int) func(inputs []string, call int) (int, any) {
	return func(inputs []string, call int) (int, any) {
		data := make([]map[string]any, len(inputs))
		for i := range inputs {
			v := make([]float64, dim)
			v[i%dim] = 3 // unnormalised on purpose
			v[(i+1)%dim] = 4
			data[len(inputs)-1-i] = map[string]any{"index": i, "embedding": v}
		}
		return 200, map[string]any{"data": data}
	}
}

func TestEmbedBatchesNormalisesAndKeepsOrder(t *testing.T) {
	server, seen := serve(t, vectors(8))
	c, err := New(Config{BaseURL: server.URL + "/v1", Model: "bge-small-en-v1.5", Dim: 8, MaxBatch: 2}, local)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Embed(context.Background(), []string{"a", "b", "c", "d", "e"})
	if err != nil || len(out) != 5 || len(*seen) != 3 {
		t.Fatalf("%d vectors, %d requests, %v", len(out), len(*seen), err)
	}
	for i, v := range out {
		var sum float64
		for _, x := range v {
			sum += float64(x) * float64(x)
		}
		if math.Abs(sum-1) > 1e-5 || v[i%2%8] == 0 && i%2 == 0 {
			t.Errorf("vector %d: norm² %f", i, sum)
		}
	}
	// Index order is honoured even when the server shuffles the answers.
	if out[0][0] < 0.59 || out[0][0] > 0.61 || out[0][1] < 0.79 || out[0][1] > 0.81 {
		t.Fatalf("first vector %v", out[0])
	}
}

func TestEmbedScreensCredentialsBeforeSending(t *testing.T) {
	server, seen := serve(t, vectors(8))
	c, _ := New(Config{BaseURL: server.URL + "/v1", Model: "m", Dim: 8}, local)
	key := strings.Join([]string{"AK", "IA", "IOSFODNN7", "EXAMPLE"}, "")
	if _, err := c.Embed(context.Background(), []string{"rotate " + key + " today"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(*seen), key) || !strings.Contains(fmt.Sprint(*seen), "REDACTED") {
		t.Fatalf("server received %v", *seen)
	}
}

func TestEmbedRefusesBadInputAndBadAnswers(t *testing.T) {
	server, _ := serve(t, vectors(8))
	c, _ := New(Config{BaseURL: server.URL + "/v1", Model: "m", Dim: 8, MaxChars: 10}, local)
	ctx := context.Background()
	if _, err := c.Embed(ctx, []string{"  "}); err == nil {
		t.Fatal("empty text")
	}
	if _, err := c.Embed(ctx, []string{"this is longer than ten"}); err == nil || !strings.Contains(err.Error(), "split") {
		t.Fatal("over-long text must not be silently truncated:", err)
	}
	wrongDim, _ := New(Config{BaseURL: server.URL + "/v1", Model: "m", Dim: 16}, local)
	if _, err := wrongDim.Embed(ctx, []string{"x"}); err == nil || !strings.Contains(err.Error(), "dimensions") {
		t.Fatal("dimension mismatch:", err)
	}
	zero, _ := serve(t, func(in []string, _ int) (int, any) {
		return 200, map[string]any{"data": []map[string]any{{"index": 0, "embedding": make([]float64, 8)}}}
	})
	z, _ := New(Config{BaseURL: zero.URL + "/v1", Model: "m", Dim: 8}, local)
	if _, err := z.Embed(ctx, []string{"x"}); err == nil || !strings.Contains(err.Error(), "zeros") {
		t.Fatal("all-zero vector:", err)
	}
	short, _ := serve(t, func(in []string, _ int) (int, any) { return 200, map[string]any{"data": []any{}} })
	s, _ := New(Config{BaseURL: short.URL + "/v1", Model: "m", Dim: 8}, local)
	if _, err := s.Embed(ctx, []string{"x"}); err == nil {
		t.Fatal("missing vectors")
	}
}

func TestEmbedRetriesTransientFailuresOnly(t *testing.T) {
	server, seen := serve(t, func(in []string, call int) (int, any) {
		if call < 3 {
			return 503, map[string]string{"error": "loading"}
		}
		return vectors(8)(in, call)
	})
	c, _ := New(Config{BaseURL: server.URL + "/v1", Model: "m", Dim: 8}, local)
	if _, err := c.Embed(context.Background(), []string{"x"}); err != nil || len(*seen) != 3 {
		t.Fatalf("%d attempts, %v", len(*seen), err)
	}
	bad, seenBad := serve(t, func(in []string, _ int) (int, any) { return 400, map[string]string{"error": "no"} })
	b, _ := New(Config{BaseURL: bad.URL + "/v1", Model: "m", Dim: 8}, local)
	if _, err := b.Embed(context.Background(), []string{"x"}); err == nil || len(*seenBad) != 1 {
		t.Fatalf("a rejected request is not retried: %d, %v", len(*seenBad), err)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"plain http to an unnamed host": {BaseURL: "http://embed.example.net/v1", Model: "m", Dim: 8},
		"credentials in the URL":        {BaseURL: "https://u:p@embed.example.net/v1", Model: "m", Dim: 8},
		"no model":                      {BaseURL: "https://embed.example.net/v1", Dim: 8},
		"no dimension":                  {BaseURL: "https://embed.example.net/v1", Model: "m"},
	} {
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(Config{BaseURL: "http://scrs-embed/v1", Model: "m", Dim: 384}, map[string]bool{"scrs-embed": true}); err != nil {
		t.Fatal("a named private host may use http:", err)
	}
	t.Setenv("SCRS_EMBED_URL", "")
	if _, ok, _ := ConfigFromEnv(); ok {
		t.Fatal("no URL means off")
	}
	t.Setenv("SCRS_EMBED_URL", "http://scrs-embed/v1")
	t.Setenv("SCRS_EMBED_MODEL", "bge-small-en-v1.5")
	t.Setenv("SCRS_EMBED_DIM", "384")
	if cfg, ok, err := ConfigFromEnv(); !ok || err != nil || cfg.Dim != 384 {
		t.Fatal(cfg, ok, err)
	}
	t.Setenv("SCRS_EMBED_DIM", "x")
	if _, _, err := ConfigFromEnv(); err == nil {
		t.Fatal("bad dimension")
	}
}

func TestMaxCharsDefaultsToWhatASmallModelCanRead(t *testing.T) {
	// bge-small reads about 512 tokens; the default keeps a chunk inside that,
	// and an over-long text is an error rather than silently cut.
	server, _ := serve(t, vectors(8))
	c, err := New(Config{BaseURL: server.URL + "/v1", Model: "m", Dim: 8}, local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Embed(context.Background(), []string{strings.Repeat("a", 1501)}); err == nil || !strings.Contains(err.Error(), "1500") {
		t.Fatal("the default limit is 1500 characters:", err)
	}
	t.Setenv("SCRS_EMBED_URL", "http://scrs-embed/v1")
	t.Setenv("SCRS_EMBED_MODEL", "m")
	t.Setenv("SCRS_EMBED_DIM", "384")
	t.Setenv("SCRS_EMBED_MAX_CHARS", "1200")
	if cfg, _, err := ConfigFromEnv(); err != nil || cfg.MaxChars != 1200 {
		t.Fatal(cfg, err)
	}
	for _, bad := range []string{"50", "99999", "x"} {
		t.Setenv("SCRS_EMBED_MAX_CHARS", bad)
		if _, _, err := ConfigFromEnv(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
