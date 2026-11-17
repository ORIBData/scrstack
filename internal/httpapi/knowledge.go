package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/embed"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/google/uuid"
)

// Embedder turns text into vectors; *embed.Client is the real one.
type Embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	Model() string
}

var _ Embedder = (*embed.Client)(nil)

// knowledgeHandler serves similarity search over an asset's chronicle and
// the backfill of vectors for documents stored without them.
type knowledgeHandler struct {
	store    *assessments.Store
	embedder Embedder // nil when no embedding server is configured
	busy     sync.Mutex
}

func (h *knowledgeHandler) unavailable(w http.ResponseWriter) bool {
	if h.embedder == nil {
		writeError(w, http.StatusServiceUnavailable, "no embedding server is configured (SCRS_EMBED_URL); see docs/MODEL_HOST.md")
		return true
	}
	return false
}

// search serves GET /assets/{id}/chronicle/search.
func (h *knowledgeHandler) search(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	asset, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "asset not found")
		return
	}
	q := r.URL.Query()
	text := strings.TrimSpace(q.Get("q"))
	if text == "" || len(text) > 500 {
		writeError(w, 400, "q is required and at most 500 characters")
		return
	}
	k := 8
	if raw := q.Get("k"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 20 {
			writeError(w, 400, "k must be 1 to 20")
			return
		}
		k = n
	}
	query := knowledge.Query{AssetID: &asset, K: k, IncludeSuperseded: q.Get("include_superseded") == "true"}
	if kind := q.Get("kind"); kind != "" {
		for _, v := range strings.Split(kind, ",") {
			query.Kinds = append(query.Kinds, strings.TrimSpace(v))
		}
	}
	if raw := q.Get("finding_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, 400, "invalid finding_id")
			return
		}
		query.FindingID = &id
	}
	if h.unavailable(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	vectors, err := h.embedder.Embed(ctx, []string{text})
	if err != nil || len(vectors) != 1 {
		writeError(w, 502, "the embedding server could not embed the question")
		return
	}
	query.Vector, query.EmbedModel = vectors[0], h.embedder.Model()
	kn := h.store.Knowledge()
	result, err := kn.Search(ctx, query)
	if err != nil {
		aiSummaryError(w, err)
		return
	}
	unindexed, err := kn.CountMissingVectors(ctx, asset, query.EmbedModel)
	if err != nil {
		aiSummaryError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"query": text, "model": query.EmbedModel, "hits": result.Hits, "candidates": result.Candidates, "truncated": result.Truncated, "unindexed_documents": unindexed})
}

// backfill serves POST /knowledge:backfill.
func (h *knowledgeHandler) backfill(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	principal, _ := r.Context().Value(principalKey{}).(connections.Token)
	if !principal.Allows("admin") {
		writeError(w, 403, "admin scope required")
		return
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeError(w, 400, "limit must be 1 to 200")
			return
		}
		limit = n
	}
	if h.unavailable(w) {
		return
	}
	if !h.busy.TryLock() {
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusConflict, "a backfill is already running")
		return
	}
	defer h.busy.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	kn := h.store.Knowledge()
	model := h.embedder.Model()
	docs, remaining, err := kn.MissingVectors(ctx, model, limit)
	if err != nil {
		aiSummaryError(w, err)
		return
	}
	embedded, failed := 0, 0
	for _, d := range docs {
		parts := knowledge.Split(d.Body, 1000, 120)
		if len(parts) == 0 {
			failed++
			continue
		}
		vectors, err := h.embedder.Embed(ctx, parts)
		if err != nil || len(vectors) != len(parts) {
			failed++
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				break
			}
			continue
		}
		chunks := make([]knowledge.Chunk, len(parts))
		for i := range parts {
			chunks[i] = knowledge.Chunk{Text: parts[i], Vector: vectors[i]}
		}
		if err := kn.AddChunks(ctx, d.ID, model, chunks); err != nil {
			failed++
			continue
		}
		embedded++
	}
	writeJSON(w, 200, map[string]any{"model": model, "embedded": embedded, "failed": failed, "remaining": max(remaining-embedded, 0)})
}
