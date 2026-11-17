package httpapi

import (
	"encoding/json"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ORIBData/scrstack/internal/embed"
	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/google/uuid"
)

// bagOfWords is a stand-in embedding model: words hash into eight buckets, so
// texts sharing words have a high cosine similarity.
func bagOfWords(text string) []float64 {
	v := make([]float64, 8)
	for _, word := range strings.Fields(strings.ToLower(text)) {
		h := fnv.New32a()
		_, _ = h.Write([]byte(strings.Trim(word, ".,;:!?")))
		v[h.Sum32()%8]++
	}
	return v
}

type embeddingServer struct {
	server *httptest.Server
	fail   atomic.Bool
	calls  atomic.Int32
}

func newEmbeddingServer(t *testing.T) *embeddingServer {
	t.Helper()
	e := &embeddingServer{}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.calls.Add(1)
		if e.fail.Load() {
			w.WriteHeader(400)
			return
		}
		var in struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		type item struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		}
		var data []item
		for i, text := range in.Input {
			data = append(data, item{i, bagOfWords(text)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *embeddingServer) client(t *testing.T) *embed.Client {
	t.Helper()
	c, err := embed.New(embed.Config{BaseURL: e.server.URL + "/v1", Model: "test-embed", Dim: 8}, map[string]bool{"127.0.0.1": true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Similarity search over an asset's chronicle and the backfill of vectors:
// documents stored without vectors are reported as unindexed, indexed by an
// admin, and then found by meaning; an unconfigured or failing embedding
// server answers 503 or 502.
func TestPostgresChronicleSearchAndBackfill(t *testing.T) {
	server := newEmbeddingServer(t)
	h := newHarnessWith(t, func(s *Security) { s.Embedder = server.client(t) })
	asset, _ := h.upload("searchable", "a")
	other, _ := h.upload("elsewhere", "b")
	kn := h.jobs.Knowledge()
	add := func(asset uuid.UUID, kind, title, body string) uuid.UUID {
		t.Helper()
		id, err := kn.AddDocument(h.ctx, knowledge.Document{Kind: kind, AssetID: &asset, Title: title, Body: body, Origin: knowledge.OriginLLM}, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	advisory := add(asset, knowledge.KindAdvisory, "Upgrade lodash", "Upgrade lodash to fix the prototype pollution flaw in the template function.")
	summary := add(asset, knowledge.KindAssessmentSummary, "Mostly clean", "The repository is mostly clean with one licence issue under the GPL.")
	add(asset, knowledge.KindAssetChronicle, "Typosquat", "A typosquat of react was flagged and accepted by the owner.")
	add(other, knowledge.KindAdvisory, "Other asset", "Prototype pollution lodash template, written for another asset.")
	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	path := "/assets/" + asset.String() + "/chronicle/search"
	type searchResult struct {
		Model     string `json:"model"`
		Hits      []knowledge.Hit
		Unindexed int `json:"unindexed_documents"`
	}
	search := func(query string, status int) searchResult {
		t.Helper()
		var out searchResult
		w := h.expect(h.call("GET", path+query, read, nil, ""), status)
		if status == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}

	// Before the backfill nothing is indexed, and the answer says so.
	if got := search("?q=prototype+pollution+lodash", 200); len(got.Hits) != 0 || got.Unindexed != 3 || got.Model != "test-embed" {
		t.Fatalf("before the backfill: %+v", got)
	}
	// Only an admin backfills, in batches, and it is repeatable.
	h.expect(h.call("POST", "/knowledge:backfill", write, nil, ""), 403)
	h.expect(h.call("POST", "/knowledge:backfill?limit=0", h.admin, nil, ""), 400)
	h.expect(h.call("POST", "/knowledge:backfill?limit=201", h.admin, nil, ""), 400)
	var filled struct {
		Model                       string
		Embedded, Failed, Remaining int
	}
	if err := json.Unmarshal(h.expect(h.call("POST", "/knowledge:backfill?limit=2", h.admin, nil, ""), 200).Body.Bytes(), &filled); err != nil || filled.Embedded != 2 || filled.Remaining != 2 || filled.Model != "test-embed" {
		t.Fatalf("first batch: %+v %v", filled, err)
	}
	if err := json.Unmarshal(h.expect(h.call("POST", "/knowledge:backfill", h.admin, nil, ""), 200).Body.Bytes(), &filled); err != nil || filled.Embedded != 2 || filled.Remaining != 0 {
		t.Fatalf("second batch: %+v %v", filled, err)
	}
	if err := json.Unmarshal(h.expect(h.call("POST", "/knowledge:backfill", h.admin, nil, ""), 200).Body.Bytes(), &filled); err != nil || filled.Embedded != 0 || filled.Remaining != 0 {
		t.Fatalf("nothing left: %+v %v", filled, err)
	}

	// Search finds by meaning, only inside the asset, and honours kind and k.
	got := search("?q=prototype+pollution+lodash+template", 200)
	if len(got.Hits) == 0 || got.Hits[0].DocumentID != advisory || got.Hits[0].Kind != "advisory" || got.Hits[0].Score <= 0.5 || got.Unindexed != 0 {
		t.Fatalf("search: %+v", got)
	}
	for _, hit := range got.Hits {
		if hit.AssetID == nil || *hit.AssetID != asset {
			t.Fatalf("a hit from another asset: %+v", hit)
		}
	}
	if got := search("?q=licence+GPL+clean&kind=assessment_summary&k=1", 200); len(got.Hits) != 1 || got.Hits[0].DocumentID != summary {
		t.Fatalf("kind filter: %+v", got)
	}
	if got := search("?q=licence+GPL+clean&kind=advisory", 200); len(got.Hits) != 1 || got.Hits[0].Kind != "advisory" {
		t.Fatalf("kind filter excludes other kinds: %+v", got)
	}
	// Input checks.
	search("", 400)
	search("?q=%20%20", 400)
	search("?q="+strings.Repeat("x", 501), 400)
	search("?q=a&k=0", 400)
	search("?q=a&k=21", 400)
	search("?q=a&finding_id=nope", 400)
	h.expect(h.call("GET", "/assets/nope/chronicle/search?q=a", read, nil, ""), 404)
	h.expect(h.call("GET", path+"?q=a", "", nil, ""), 401)
	if got := (func() searchResult {
		var out searchResult
		w := h.expect(h.call("GET", "/assets/"+uuid.NewString()+"/chronicle/search?q=anything", read, nil, ""), 200)
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	})(); len(got.Hits) != 0 {
		t.Fatalf("an asset with no documents: %+v", got)
	}

	// A failing embedding server: search answers 502, the backfill counts failures and stays resumable.
	add(asset, knowledge.KindCodeReview, "Review", "A code review found nothing of note.")
	server.fail.Store(true)
	search("?q=anything", 502)
	if err := json.Unmarshal(h.expect(h.call("POST", "/knowledge:backfill", h.admin, nil, ""), 200).Body.Bytes(), &filled); err != nil || filled.Failed != 1 || filled.Embedded != 0 || filled.Remaining != 1 {
		t.Fatalf("failing server: %+v %v", filled, err)
	}
	server.fail.Store(false)
	if err := json.Unmarshal(h.expect(h.call("POST", "/knowledge:backfill", h.admin, nil, ""), 200).Body.Bytes(), &filled); err != nil || filled.Embedded != 1 || filled.Remaining != 0 {
		t.Fatalf("resumed: %+v %v", filled, err)
	}

	// Without an embedding server both endpoints say so.
	plain := newHarness(t)
	plainAsset, _ := plain.upload("plain", "c")
	plain.expect(plain.call("GET", "/assets/"+plainAsset.String()+"/chronicle/search?q=a", plain.admin, nil, ""), 503)
	plain.expect(plain.call("POST", "/knowledge:backfill", plain.admin, nil, ""), 503)
}
