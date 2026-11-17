package knowledge_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func unit(v ...float32) []float32 {
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	out := make([]float32, len(v))
	for i, x := range v {
		out[i] = float32(float64(x) / math.Sqrt(sum))
	}
	return out
}

func TestPostgresKnowledge(t *testing.T) {
	databaseURL := os.Getenv("SCRS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	for range 2 { // migrations rerun on every start
		if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: databaseURL, DatabaseSchema: schema}); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	store := knowledge.New(pool, schema)

	assetA, assetB, assessment, finding := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const model = "bge-small-en-v1.5"
	doc := func(kind string, asset uuid.UUID, title, body string, vector []float32, mutate func(*knowledge.Document)) uuid.UUID {
		t.Helper()
		d := knowledge.Document{Kind: kind, AssetID: &asset, Title: title, Body: body, Origin: knowledge.OriginLLM, Provenance: map[string]any{"model": "m", "prompt_version": "advisory-1"}}
		if mutate != nil {
			mutate(&d)
		}
		id, err := store.AddDocument(ctx, d, model, []knowledge.Chunk{{Text: body, Vector: vector}})
		if err != nil {
			t.Fatal(title, err)
		}
		time.Sleep(5 * time.Millisecond) // distinct creation times
		return id
	}

	// An asset's history, oldest first, with a later advisory replacing an earlier one.
	first := doc(knowledge.KindAdvisory, assetA, "lodash CVE-2021-23337", "Upgrade lodash to 4.17.21 to fix command injection.", unit(1, 0, 0), func(d *knowledge.Document) { d.FindingID = &finding; d.AssessmentID = &assessment })
	summary := doc(knowledge.KindAssessmentSummary, assetA, "Assessment of main", "Two high findings, one critical.", unit(0, 1, 0), func(d *knowledge.Document) { d.AssessmentID = &assessment })
	second := doc(knowledge.KindAdvisory, assetA, "lodash CVE-2021-23337 (reassessed)", "Fixed in 4.17.21; the upgrade was applied and verified.", unit(0.9, 0.1, 0), func(d *knowledge.Document) { d.FindingID = &finding; d.Supersedes = &first })
	other := doc(knowledge.KindAdvisory, assetB, "another asset", "Unrelated advisory.", unit(1, 0, 0), nil)

	history, err := store.Chronicle(ctx, knowledge.ChronicleQuery{AssetID: assetA, IncludeSuperseded: true})
	if err != nil || len(history) != 3 || history[0].ID != first || history[1].ID != summary || history[2].ID != second {
		t.Fatalf("chronicle %v %v", ids(history), err)
	}
	if history[0].SupersededAt == nil || history[2].Supersedes == nil || *history[2].Supersedes != first || history[2].Provenance["prompt_version"] != "advisory-1" || len(history[2].BodySHA256) != 64 {
		t.Fatalf("the chain and provenance are kept: %+v", history[0])
	}
	current, _ := store.Chronicle(ctx, knowledge.ChronicleQuery{AssetID: assetA})
	if len(current) != 2 {
		t.Fatal("superseded documents are hidden unless asked for:", ids(current))
	}
	forFinding, _ := store.Chronicle(ctx, knowledge.ChronicleQuery{AssetID: assetA, FindingID: &finding, IncludeSuperseded: true, Kinds: []string{knowledge.KindAdvisory}})
	if len(forFinding) != 2 {
		t.Fatal("per-finding chronicle:", ids(forFinding))
	}
	if _, err := store.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindAdvisory, AssetID: &assetA, Title: "x", Body: "y", Origin: knowledge.OriginLLM, Supersedes: &first}, model, nil); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatal("a document that is already superseded cannot be superseded again:", err)
	}

	// The current document of a kind, and the chronicle of one assessment.
	latest, err := store.Latest(ctx, assetA, knowledge.KindAdvisory, &finding)
	if err != nil || latest.ID != second {
		t.Fatalf("latest advisory for the finding: %v %v", latest.ID, err)
	}
	if _, err := store.Latest(ctx, assetB, knowledge.KindAssessmentSummary, nil); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatal("no summary for that asset:", err)
	}
	byAssessment, _ := store.Chronicle(ctx, knowledge.ChronicleQuery{AssetID: assetA, AssessmentID: &assessment, IncludeSuperseded: true})
	if len(byAssessment) != 2 {
		t.Fatal("documents of one assessment:", ids(byAssessment))
	}

	// Search: nearest first, scoped to the asset, kind and model.
	res, err := store.Search(ctx, knowledge.Query{Vector: unit(1, 0.1, 0), EmbedModel: model, AssetID: &assetA, K: 5})
	if err != nil || len(res.Hits) != 2 || res.Hits[0].DocumentID != second || res.Hits[0].Score < 0.99 || res.Hits[0].Score < res.Hits[1].Score || res.Truncated {
		t.Fatalf("search %+v %v", res, err)
	}
	for _, h := range res.Hits {
		if h.DocumentID == first || h.DocumentID == other {
			t.Fatal("superseded and other-asset chunks must not be returned:", h)
		}
	}
	withOld, _ := store.Search(ctx, knowledge.Query{Vector: unit(1, 0, 0), EmbedModel: model, AssetID: &assetA, K: 1, IncludeSuperseded: true})
	if len(withOld.Hits) != 1 || withOld.Hits[0].DocumentID != first || withOld.Hits[0].Score < 0.999 {
		t.Fatalf("including superseded: %+v", withOld)
	}
	onlySummaries, _ := store.Search(ctx, knowledge.Query{Vector: unit(1, 0, 0), EmbedModel: model, AssetID: &assetA, Kinds: []string{knowledge.KindAssessmentSummary}})
	if len(onlySummaries.Hits) != 1 || onlySummaries.Hits[0].Kind != knowledge.KindAssessmentSummary {
		t.Fatalf("kind filter: %+v", onlySummaries)
	}
	if wrong, _ := store.Search(ctx, knowledge.Query{Vector: unit(1, 0, 0), EmbedModel: "another-model", AssetID: &assetA}); len(wrong.Hits) != 0 {
		t.Fatal("vectors of different models are never compared")
	}
	if wrong, _ := store.Search(ctx, knowledge.Query{Vector: unit(1, 0), EmbedModel: model, AssetID: &assetA}); len(wrong.Hits) != 0 {
		t.Fatal("vectors of another length are never compared")
	}
	portfolio, _ := store.Search(ctx, knowledge.Query{Vector: unit(1, 0, 0), EmbedModel: model, K: 10})
	if len(portfolio.Hits) != 3 {
		t.Fatalf("no asset filter searches every asset: %d", len(portfolio.Hits))
	}
	capped, _ := store.Search(ctx, knowledge.Query{Vector: unit(1, 0, 0), EmbedModel: model, MaxCandidates: 2})
	if !capped.Truncated || capped.Candidates != 2 {
		t.Fatalf("the candidate cap is reported: %+v", capped)
	}
	if _, err := store.Search(ctx, knowledge.Query{EmbedModel: model}); !errors.Is(err, knowledge.ErrInput) {
		t.Fatal("empty vector")
	}

	// Credentials never reach the table, and the document says so.
	awsKey := strings.Join([]string{"AK", "IA", "IOSFODNN7", "EXAMPLE"}, "")
	id := doc(knowledge.KindFindingSummary, assetA, "leaky "+awsKey, "Rotate "+awsKey+" and password=Hunter2Hunter2! now.", unit(0, 0, 1), nil)
	stored, err := store.Get(ctx, id)
	if err != nil || strings.Contains(stored.Body+stored.Title, awsKey) || strings.Contains(stored.Body, "Hunter2Hunter2!") {
		t.Fatalf("stored %+v %v", stored, err)
	}
	redactions, _ := stored.Provenance["redactions"].(map[string]any)
	if redactions["aws_access_key"] == nil || redactions["credential_assignment"] == nil {
		t.Fatalf("provenance should count what was removed: %v", stored.Provenance)
	}
	var chunkText string
	if err := pool.QueryRow(ctx, `SELECT text FROM `+schema+`.knowledge_chunks WHERE document_id=$1`, id).Scan(&chunkText); err != nil || strings.Contains(chunkText, awsKey) {
		t.Fatalf("chunk %q %v", chunkText, err)
	}

	// Chunks may be added later, when embedding was unavailable.
	lateID := doc(knowledge.KindQASummary, assetA, "qa run", "Karate: 12 passed, 1 failed.", unit(0, 1, 1), nil)
	pending, err := store.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindReport, AssetID: &assetA, Title: "report", Body: "Quarterly report text.", Origin: knowledge.OriginSCRS}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddChunks(ctx, pending, model, []knowledge.Chunk{{Text: "Quarterly report text.", Vector: unit(1, 1, 1)}, {Text: "second part", Vector: unit(1, 1, 0)}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddChunks(ctx, uuid.New(), model, []knowledge.Chunk{{Text: "x", Vector: unit(1, 0, 0)}}); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatal("chunks for a missing document:", err)
	}
	if _, err := store.AddDocument(ctx, knowledge.Document{Kind: knowledge.KindReport, AssetID: &assetA, Title: "t", Body: "b", Origin: knowledge.OriginSCRS}, model, []knowledge.Chunk{{Text: "a", Vector: unit(1, 0)}, {Text: "b", Vector: unit(1, 0, 0)}}); !errors.Is(err, knowledge.ErrInput) {
		t.Fatal("chunks of different lengths in one document:", err)
	}
	var orphans int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.knowledge_documents WHERE title='t'`).Scan(&orphans)
	if orphans != 0 {
		t.Fatal("a rejected document must leave nothing behind")
	}
	for _, bad := range []knowledge.Document{
		{Kind: "poem", Title: "t", Body: "b", Origin: knowledge.OriginLLM},
		{Kind: knowledge.KindAdvisory, Title: " ", Body: "b", Origin: knowledge.OriginLLM},
		{Kind: knowledge.KindAdvisory, Title: "t", Body: "", Origin: knowledge.OriginLLM},
		{Kind: knowledge.KindAdvisory, Title: "t", Body: "b", Origin: "someone"},
	} {
		if _, err := store.AddDocument(ctx, bad, model, nil); !errors.Is(err, knowledge.ErrInput) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
	_ = lateID

	// Budget: spend is summed per assessment, and a call that would exceed
	// either ceiling is refused before it is made.
	budget := knowledge.Budget{AssessmentInput: 10000, AssessmentOutput: 2000}
	if err := store.Reserve(ctx, assessment, budget, 9000, 1500); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := store.RecordUsage(ctx, knowledge.Usage{Purpose: "advisory", AssetID: &assetA, AssessmentID: &assessment, Provider: "openai", Model: "m", InputTokens: 2500, OutputTokens: 400, Status: "ok", Redactions: map[string]int{"aws_access_key": 1}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordUsage(ctx, knowledge.Usage{Purpose: "advisory", AssessmentID: &assessment, InputTokens: 100, OutputTokens: 100, Truncated: true, Status: "truncated"}); err != nil {
		t.Fatal(err)
	}
	in, out, err := store.Spent(ctx, assessment)
	if err != nil || in != 7600 || out != 1300 {
		t.Fatalf("spent %d %d %v", in, out, err)
	}
	if err := store.Reserve(ctx, assessment, budget, 2000, 600); err != nil {
		t.Fatal("fits:", err)
	}
	if err := store.Reserve(ctx, assessment, budget, 2500, 100); !errors.Is(err, knowledge.ErrBudget) {
		t.Fatal("input ceiling:", err)
	}
	if err := store.Reserve(ctx, assessment, budget, 100, 800); !errors.Is(err, knowledge.ErrBudget) {
		t.Fatal("output ceiling:", err)
	}
	if err := store.Reserve(ctx, uuid.New(), budget, 9999, 1999); err != nil {
		t.Fatal("another assessment has its own budget:", err)
	}
	if err := store.RecordUsage(ctx, knowledge.Usage{Purpose: "", Status: "ok"}); !errors.Is(err, knowledge.ErrInput) {
		t.Fatal("a ledger row needs a purpose")
	}
	var redactionCount int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.llm_usage WHERE redactions ? 'aws_access_key'`).Scan(&redactionCount)
	if redactionCount != 3 {
		t.Fatal("redaction counts are kept in the ledger:", redactionCount)
	}
}

func ids(docs []knowledge.Document) string {
	var out []string
	for _, d := range docs {
		out = append(out, d.Title)
	}
	return fmt.Sprint(out)
}
