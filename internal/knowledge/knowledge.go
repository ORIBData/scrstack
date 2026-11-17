// Package knowledge is SCRS's persisted memory for language-model work: the
// documents SCRS and the model produce (advisories, summaries, chronicles),
// their text chunks with embeddings from the self-hosted embedding server,
// and a ledger of what each model call cost.
//
// It needs nothing beyond standard PostgreSQL. Vectors are stored as bytes
// and searched exactly (cosine similarity) after the database has filtered by
// asset, kind and embedding model, so it works on any PostgreSQL, including
// managed servers that allow no extensions. Every document keeps its
// provenance and is linked to its asset, assessment and finding, so the
// history of an asset reads as a chronicle. Nothing here is deleted by the
// retention jobs that prune findings: the chronicle outlives them.
//
// All text is screened for credentials before it is stored.
package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/llm/guard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Document kinds.
const (
	KindAdvisory          = "advisory"
	KindFindingSummary    = "finding_summary"
	KindAssessmentSummary = "assessment_summary"
	KindAssetChronicle    = "asset_chronicle"
	KindQASummary         = "qa_summary"
	KindCodeReview        = "code_review"
	KindReport            = "report"
)

var kinds = map[string]bool{KindAdvisory: true, KindFindingSummary: true, KindAssessmentSummary: true, KindAssetChronicle: true, KindQASummary: true, KindCodeReview: true, KindReport: true}

// Origins say who wrote a document's text.
const (
	OriginSCRS = "scrs"
	OriginLLM  = "llm"
)

var (
	ErrInput    = errors.New("invalid knowledge input")
	ErrNotFound = errors.New("knowledge document not found")
	ErrBudget   = errors.New("assessment language-model budget exhausted")
	// ErrMonthlyCap is a kind of ErrBudget: the provider's monthly token cap
	// is used up, so a hosted provider cannot run up an unbounded bill.
	ErrMonthlyCap = fmt.Errorf("%w (monthly provider token cap reached)", ErrBudget)
)

// Schema is applied under the storage migration lock. No destructive DDL.
// There are no foreign keys to assets, assessments or findings: the chronicle
// must survive their retention.
func Schema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.knowledge_documents(id uuid PRIMARY KEY,kind text NOT NULL,asset_id uuid,assessment_id uuid,finding_id uuid,ref text NOT NULL DEFAULT '',title text NOT NULL,body text NOT NULL,body_sha256 text NOT NULL,origin text NOT NULL CHECK(origin IN ('scrs','llm')),provenance jsonb NOT NULL DEFAULT '{}',supersedes uuid,superseded_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE INDEX IF NOT EXISTS knowledge_documents_asset_idx ON ` + s + `.knowledge_documents(asset_id,created_at)`,
		`CREATE INDEX IF NOT EXISTS knowledge_documents_finding_idx ON ` + s + `.knowledge_documents(finding_id) WHERE finding_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS knowledge_documents_assessment_idx ON ` + s + `.knowledge_documents(assessment_id) WHERE assessment_id IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.knowledge_chunks(id uuid PRIMARY KEY,document_id uuid NOT NULL REFERENCES ` + s + `.knowledge_documents(id) ON DELETE CASCADE,asset_id uuid,seq integer NOT NULL,text text NOT NULL,embed_model text NOT NULL,dim integer NOT NULL CHECK(dim>0),embedding bytea NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(document_id,seq,embed_model))`,
		`CREATE INDEX IF NOT EXISTS knowledge_chunks_scope_idx ON ` + s + `.knowledge_chunks(embed_model,asset_id)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.llm_usage(id bigserial PRIMARY KEY,purpose text NOT NULL,asset_id uuid,assessment_id uuid,document_id uuid,provider text NOT NULL DEFAULT '',model text NOT NULL DEFAULT '',input_tokens bigint NOT NULL DEFAULT 0,output_tokens bigint NOT NULL DEFAULT 0,truncated boolean NOT NULL DEFAULT false,redactions jsonb NOT NULL DEFAULT '{}',status text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE INDEX IF NOT EXISTS llm_usage_assessment_idx ON ` + s + `.llm_usage(assessment_id) WHERE assessment_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS llm_usage_created_idx ON ` + s + `.llm_usage(created_at)`,
	}
}

// Store reads and writes the knowledge tables.
type Store struct {
	pool   *pgxpool.Pool
	schema string
	guard  *guard.Guard
}

// New wraps an open pool. schema is the SCRS database schema.
func New(pool *pgxpool.Pool, schema string) *Store {
	return &Store{pool: pool, schema: schema, guard: guard.New(guard.KnownFromEnv(os.Environ())...)}
}

// Document is one stored text.
type Document struct {
	ID           uuid.UUID      `json:"id"`
	Kind         string         `json:"kind"`
	AssetID      *uuid.UUID     `json:"asset_id,omitempty"`
	AssessmentID *uuid.UUID     `json:"assessment_id,omitempty"`
	FindingID    *uuid.UUID     `json:"finding_id,omitempty"`
	Ref          string         `json:"ref,omitempty"`
	Title        string         `json:"title"`
	Body         string         `json:"body"`
	BodySHA256   string         `json:"body_sha256"`
	Origin       string         `json:"origin"`
	Provenance   map[string]any `json:"provenance"`
	// Supersedes names the earlier document this one replaces, which is then
	// marked superseded but kept.
	Supersedes   *uuid.UUID `json:"supersedes,omitempty"`
	SupersededAt *time.Time `json:"superseded_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Chunk is a part of a document's text and its vector.
type Chunk struct {
	Text   string
	Vector []float32
}

func encodeVector(v []float32) []byte {
	out := make([]byte, 4*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint32(out[4*i:], math.Float32bits(x))
	}
	return out
}

func decodeVector(b []byte, dim int) ([]float32, bool) {
	if len(b) != 4*dim {
		return nil, false
	}
	out := make([]float32, dim)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
	}
	return out, true
}

const maxBody = 1 << 20

// AddDocument stores a document and its chunks in one transaction. embedModel
// names the model that made the vectors; every vector must have the same
// length. Title, body and chunk text are screened for credentials; what was
// removed is counted in provenance.redactions. A document may have no chunks
// (embedding was unavailable); AddChunks adds them later.
func (s *Store) AddDocument(ctx context.Context, d Document, embedModel string, chunks []Chunk) (uuid.UUID, error) {
	if !kinds[d.Kind] || (d.Origin != OriginSCRS && d.Origin != OriginLLM) || strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.Body) == "" || len(d.Body) > maxBody || len(d.Title) > 500 || len(d.Ref) > 255 {
		return uuid.Nil, ErrInput
	}
	if len(chunks) > 0 && embedModel == "" {
		return uuid.Nil, ErrInput
	}
	redactions := map[string]int{}
	var hits map[string]int
	d.Title, hits = s.guard.Screen(d.Title)
	redactions = guard.Merge(redactions, hits)
	d.Body, hits = s.guard.Screen(d.Body)
	redactions = guard.Merge(redactions, hits)
	if d.Provenance == nil {
		d.Provenance = map[string]any{}
	}
	if len(redactions) > 0 {
		d.Provenance["redactions"] = redactions
	}
	provenance, err := json.Marshal(d.Provenance)
	if err != nil {
		return uuid.Nil, ErrInput
	}
	sum := sha256.Sum256([]byte(d.Body))
	d.ID = uuid.New()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	if d.Supersedes != nil {
		tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.knowledge_documents SET superseded_at=clock_timestamp() WHERE id=$1 AND superseded_at IS NULL`, *d.Supersedes)
		if err != nil {
			return uuid.Nil, err
		}
		if tag.RowsAffected() == 0 {
			return uuid.Nil, ErrNotFound
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.knowledge_documents(id,kind,asset_id,assessment_id,finding_id,ref,title,body,body_sha256,origin,provenance,supersedes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		d.ID, d.Kind, d.AssetID, d.AssessmentID, d.FindingID, d.Ref, d.Title, d.Body, hex.EncodeToString(sum[:]), d.Origin, provenance, d.Supersedes); err != nil {
		return uuid.Nil, err
	}
	if err := s.addChunks(ctx, tx, d.ID, d.AssetID, embedModel, chunks); err != nil {
		return uuid.Nil, err
	}
	return d.ID, tx.Commit(ctx)
}

// AddChunks adds embedded chunks to an existing document.
func (s *Store) AddChunks(ctx context.Context, document uuid.UUID, embedModel string, chunks []Chunk) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var asset *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT asset_id FROM `+s.schema+`.knowledge_documents WHERE id=$1`, document).Scan(&asset); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if err := s.addChunks(ctx, tx, document, asset, embedModel, chunks); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) addChunks(ctx context.Context, tx pgx.Tx, document uuid.UUID, asset *uuid.UUID, embedModel string, chunks []Chunk) error {
	if len(chunks) == 0 {
		return nil
	}
	dim := len(chunks[0].Vector)
	var next int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(seq)+1,0) FROM `+s.schema+`.knowledge_chunks WHERE document_id=$1 AND embed_model=$2`, document, embedModel).Scan(&next); err != nil {
		return err
	}
	for i, c := range chunks {
		if dim == 0 || len(c.Vector) != dim || strings.TrimSpace(c.Text) == "" {
			return ErrInput
		}
		text, _ := s.guard.Screen(c.Text)
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.knowledge_chunks(id,document_id,asset_id,seq,text,embed_model,dim,embedding) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			uuid.New(), document, asset, next+i, text, embedModel, dim, encodeVector(c.Vector)); err != nil {
			return err
		}
	}
	return nil
}

// Get returns one document.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (Document, error) {
	d, err := scanDocument(s.pool.QueryRow(ctx, `SELECT `+documentColumns+` FROM `+s.schema+`.knowledge_documents WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

const documentColumns = `id,kind,asset_id,assessment_id,finding_id,ref,title,body,body_sha256,origin,provenance,supersedes,superseded_at,created_at`

func scanDocument(row pgx.Row) (Document, error) {
	var d Document
	var provenance []byte
	err := row.Scan(&d.ID, &d.Kind, &d.AssetID, &d.AssessmentID, &d.FindingID, &d.Ref, &d.Title, &d.Body, &d.BodySHA256, &d.Origin, &provenance, &d.Supersedes, &d.SupersededAt, &d.CreatedAt)
	if err == nil {
		d.Provenance = map[string]any{}
		_ = json.Unmarshal(provenance, &d.Provenance)
	}
	return d, err
}

// ChronicleQuery selects an asset's documents.
type ChronicleQuery struct {
	AssetID           uuid.UUID
	Kinds             []string
	FindingID         *uuid.UUID
	AssessmentID      *uuid.UUID
	Since             *time.Time
	IncludeSuperseded bool
	// Limit bounds the result (default 200, at most 1000).
	Limit int
}

// Chronicle returns an asset's documents oldest first, so the history reads
// in the order it happened: each advisory, summary and review, with the
// finding and assessment it belongs to. Superseded documents are kept and,
// unless excluded, shown with when they were replaced.
func (s *Store) Chronicle(ctx context.Context, q ChronicleQuery) ([]Document, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	if q.Kinds == nil {
		q.Kinds = []string{} // a nil slice is SQL NULL, which matches nothing
	}
	rows, err := s.pool.Query(ctx, `SELECT `+documentColumns+` FROM `+s.schema+`.knowledge_documents WHERE asset_id=$1 AND (cardinality($2::text[])=0 OR kind=ANY($2)) AND ($3::uuid IS NULL OR finding_id=$3) AND ($4::timestamptz IS NULL OR created_at>=$4) AND ($5 OR superseded_at IS NULL) AND ($6::uuid IS NULL OR assessment_id=$6) ORDER BY created_at,id LIMIT $7`,
		q.AssetID, q.Kinds, q.FindingID, q.Since, q.IncludeSuperseded, q.AssessmentID, q.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Latest returns the current (not superseded) document of a kind for an asset,
// or for one finding of it; ErrNotFound when there is none. A new document
// that replaces it names it in Supersedes.
func (s *Store) Latest(ctx context.Context, asset uuid.UUID, kind string, finding *uuid.UUID) (Document, error) {
	d, err := scanDocument(s.pool.QueryRow(ctx, `SELECT `+documentColumns+` FROM `+s.schema+`.knowledge_documents WHERE asset_id=$1 AND kind=$2 AND ($3::uuid IS NULL OR finding_id=$3) AND superseded_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1`, asset, kind, finding))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// Query is a similarity search. The database filters by embedding model,
// vector length, asset, kind and finding; the nearest chunks of what is left
// are found exactly.
type Query struct {
	Vector            []float32
	EmbedModel        string
	AssetID           *uuid.UUID
	FindingID         *uuid.UUID
	Kinds             []string
	K                 int
	IncludeSuperseded bool
	// MaxCandidates bounds the chunks compared (default 50000). Newer
	// chunks are compared first; Result.Truncated says some were left out.
	MaxCandidates int
}

// Hit is one matching chunk.
type Hit struct {
	DocumentID uuid.UUID  `json:"document_id"`
	Seq        int        `json:"seq"`
	Text       string     `json:"text"`
	Score      float64    `json:"score"`
	Kind       string     `json:"kind"`
	Title      string     `json:"title"`
	AssetID    *uuid.UUID `json:"asset_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Result is a search's hits and how complete the search was.
type Result struct {
	Hits       []Hit `json:"hits"`
	Candidates int   `json:"candidates"`
	Truncated  bool  `json:"truncated"`
}

// Search finds the chunks nearest to q.Vector by cosine similarity.
func (s *Store) Search(ctx context.Context, q Query) (Result, error) {
	var res Result
	if len(q.Vector) == 0 || q.EmbedModel == "" {
		return res, ErrInput
	}
	if q.K <= 0 || q.K > 100 {
		q.K = 8
	}
	if q.Kinds == nil {
		q.Kinds = []string{}
	}
	if q.MaxCandidates <= 0 || q.MaxCandidates > 500000 {
		q.MaxCandidates = 50000
	}
	var qnorm float64
	for _, x := range q.Vector {
		qnorm += float64(x) * float64(x)
	}
	if qnorm == 0 {
		return res, ErrInput
	}
	qnorm = math.Sqrt(qnorm)
	rows, err := s.pool.Query(ctx, `SELECT c.document_id,c.seq,c.text,c.embedding,d.kind,d.title,d.asset_id,d.created_at FROM `+s.schema+`.knowledge_chunks c JOIN `+s.schema+`.knowledge_documents d ON d.id=c.document_id WHERE c.embed_model=$1 AND c.dim=$2 AND ($3::uuid IS NULL OR d.asset_id=$3) AND ($4::uuid IS NULL OR d.finding_id=$4) AND (cardinality($5::text[])=0 OR d.kind=ANY($5)) AND ($6 OR d.superseded_at IS NULL) ORDER BY d.created_at DESC,c.document_id,c.seq LIMIT $7`,
		q.EmbedModel, len(q.Vector), q.AssetID, q.FindingID, q.Kinds, q.IncludeSuperseded, q.MaxCandidates+1)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var h Hit
		var raw []byte
		if err := rows.Scan(&h.DocumentID, &h.Seq, &h.Text, &raw, &h.Kind, &h.Title, &h.AssetID, &h.CreatedAt); err != nil {
			return res, err
		}
		if res.Candidates == q.MaxCandidates {
			res.Truncated = true
			break
		}
		res.Candidates++
		v, ok := decodeVector(raw, len(q.Vector))
		if !ok {
			continue
		}
		var dot, norm float64
		for i, x := range v {
			dot += float64(x) * float64(q.Vector[i])
			norm += float64(x) * float64(x)
		}
		if norm == 0 {
			continue
		}
		h.Score = dot / (math.Sqrt(norm) * qnorm)
		res.Hits = append(res.Hits, h)
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	sort.SliceStable(res.Hits, func(i, j int) bool { return res.Hits[i].Score > res.Hits[j].Score })
	if len(res.Hits) > q.K {
		res.Hits = res.Hits[:q.K]
	}
	if res.Hits == nil {
		res.Hits = []Hit{}
	}
	return res, nil
}

// ---- usage ledger and budgets ----

// Usage is one model call.
type Usage struct {
	Purpose      string
	AssetID      *uuid.UUID
	AssessmentID *uuid.UUID
	DocumentID   *uuid.UUID
	Provider     string
	Model        string
	InputTokens  int64
	OutputTokens int64
	Truncated    bool
	// Redactions is what the guard removed (counts by kind, never values).
	Redactions map[string]int
	// Status is ok, truncated, refused or error.
	Status string
}

// RecordUsage writes one ledger row.
func (s *Store) RecordUsage(ctx context.Context, u Usage) error {
	if u.Purpose == "" || u.Status == "" || u.InputTokens < 0 || u.OutputTokens < 0 {
		return ErrInput
	}
	redactions, _ := json.Marshal(u.Redactions)
	if u.Redactions == nil {
		redactions = []byte(`{}`)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.llm_usage(purpose,asset_id,assessment_id,document_id,provider,model,input_tokens,output_tokens,truncated,redactions,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		u.Purpose, u.AssetID, u.AssessmentID, u.DocumentID, u.Provider, u.Model, u.InputTokens, u.OutputTokens, u.Truncated, redactions, u.Status)
	return err
}

// Spent is what the model calls of one assessment have used so far.
func (s *Store) Spent(ctx context.Context, assessment uuid.UUID) (input, output int64, err error) {
	err = s.pool.QueryRow(ctx, `SELECT COALESCE(sum(input_tokens),0),COALESCE(sum(output_tokens),0) FROM `+s.schema+`.llm_usage WHERE assessment_id=$1`, assessment).Scan(&input, &output)
	return
}

// Budget is how many tokens the model work of one assessment may use in all:
// its summary, its advisories, its reviews. It is a ceiling on spend, not the
// size of a single answer (that is the provider's max_tokens, and a cut-off
// answer is reported as truncated rather than stored as complete).
type Budget struct {
	AssessmentInput  int64
	AssessmentOutput int64
	// Provider, when set, also applies the monthly cap to what that provider
	// has used this calendar month (UTC), across every purpose and
	// assessment. Set it for hosted providers, whose bill is per token.
	Provider      string
	MonthlyInput  int64
	MonthlyOutput int64
}

// Default budget: an assessment of a large repository has a few hundred
// findings; summarising them, advising on the most serious and keeping the
// answers well below a provider's output limit uses a small fraction of this.
const (
	DefaultAssessmentInput  = 300000
	DefaultAssessmentOutput = 60000
)

// BudgetFromEnv reads SCRS_LLM_ASSESSMENT_INPUT_TOKENS and
// SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS.
func BudgetFromEnv() Budget {
	read := func(name string, fallback int64) int64 {
		n, err := strconv.ParseInt(os.Getenv(name), 10, 64)
		if err != nil || n < 1000 || n > 100000000 {
			return fallback
		}
		return n
	}
	return Budget{AssessmentInput: read("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", DefaultAssessmentInput), AssessmentOutput: read("SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS", DefaultAssessmentOutput)}
}

// Monthly cap defaults for a hosted provider: tokens per calendar month
// (UTC). They are a safety ceiling for a pay-per-token bill, not a forecast;
// tune them with SCRS_LLM_MONTHLY_INPUT_TOKENS and
// SCRS_LLM_MONTHLY_OUTPUT_TOKENS ("0" removes a cap).
const (
	DefaultMonthlyInput  = 20000000
	DefaultMonthlyOutput = 4000000
)

// MonthlyFromEnv returns the monthly caps (0 means no cap).
func MonthlyFromEnv() (input, output int64) {
	read := func(name string, fallback int64) int64 {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			return fallback
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 || n > 1000000000000 {
			return fallback
		}
		return n
	}
	return read("SCRS_LLM_MONTHLY_INPUT_TOKENS", DefaultMonthlyInput), read("SCRS_LLM_MONTHLY_OUTPUT_TOKENS", DefaultMonthlyOutput)
}

// WithMonthly returns the budget with the monthly caps of a provider applied.
func (b Budget) WithMonthly(provider string) Budget {
	b.Provider = provider
	b.MonthlyInput, b.MonthlyOutput = MonthlyFromEnv()
	return b
}

// SpentThisMonth is what a provider has used since the start of the calendar
// month (UTC), by the ledger's provider name.
func (s *Store) SpentThisMonth(ctx context.Context, provider string) (input, output int64, err error) {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	err = s.pool.QueryRow(ctx, `SELECT COALESCE(sum(input_tokens),0),COALESCE(sum(output_tokens),0) FROM `+s.schema+`.llm_usage WHERE provider=$1 AND created_at>=$2`, provider, start).Scan(&input, &output)
	return
}

// ReserveMonth fails with ErrMonthlyCap when a call that may use estInput and
// estOutput tokens would pass the provider's monthly cap.
func (s *Store) ReserveMonth(ctx context.Context, b Budget, estInput, estOutput int64) error {
	if b.Provider == "" || (b.MonthlyInput == 0 && b.MonthlyOutput == 0) {
		return nil
	}
	in, out, err := s.SpentThisMonth(ctx, b.Provider)
	if err != nil {
		return err
	}
	if (b.MonthlyInput > 0 && in+estInput > b.MonthlyInput) || (b.MonthlyOutput > 0 && out+estOutput > b.MonthlyOutput) {
		return ErrMonthlyCap
	}
	return nil
}

// EstimateTokens is a cautious count for text: three characters a token,
// which over-counts prose and is close for identifiers and code.
func EstimateTokens(text string) int64 { return int64(len(text)+2) / 3 }

// Reserve checks that a call of about estInput and estOutput tokens fits in
// the assessment's remaining budget. It checks, it does not hold: calls for
// one assessment are made one after another by the worker.
func (s *Store) Reserve(ctx context.Context, assessment uuid.UUID, b Budget, estInput, estOutput int64) error {
	in, out, err := s.Spent(ctx, assessment)
	if err != nil {
		return err
	}
	if in+estInput > b.AssessmentInput || out+estOutput > b.AssessmentOutput {
		return ErrBudget
	}
	return s.ReserveMonth(ctx, b, estInput, estOutput)
}

// Split cuts text into chunks of at most maxChars, at paragraph then line
// then word boundaries, with overlap characters of the previous chunk
// repeated so a sentence at a boundary is found from either side.
func Split(text string, maxChars, overlap int) []string {
	text = strings.TrimSpace(text)
	if text == "" || maxChars < 100 {
		return nil
	}
	if overlap < 0 || overlap >= maxChars/2 {
		overlap = 0
	}
	var chunks []string
	for len(text) > 0 {
		if len(text) <= maxChars {
			chunks = append(chunks, text)
			break
		}
		cut := boundary(text, maxChars)
		chunks = append(chunks, strings.TrimSpace(text[:cut]))
		next := cut - overlap
		if next <= 0 {
			next = cut
		}
		// Start the next chunk on a word, not inside one.
		if next < cut {
			if i := strings.IndexAny(text[next:cut], " \n\t"); i >= 0 {
				next += i + 1
			}
		}
		text = strings.TrimSpace(text[next:])
	}
	return chunks
}

// boundary finds the last paragraph, line or word break before max.
func boundary(text string, max int) int {
	window := text[:max]
	for _, sep := range []string{"\n\n", "\n", ". ", " "} {
		if i := strings.LastIndex(window, sep); i > max/3 {
			return i + len(sep)
		}
	}
	// No break at all: do not split a multi-byte character.
	for max > 0 && !isRuneStart(text[max]) {
		max--
	}
	return max
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// LatestByAssets returns, for each of the assets, its current (not
// superseded) document of a kind, newest first among the assets. Assets
// without one are left out.
func (s *Store) LatestByAssets(ctx context.Context, assets []uuid.UUID, kind string) ([]Document, error) {
	if len(assets) == 0 {
		return []Document{}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+documentColumns+` FROM (SELECT DISTINCT ON (asset_id) * FROM `+s.schema+`.knowledge_documents WHERE asset_id=ANY($1) AND kind=$2 AND superseded_at IS NULL ORDER BY asset_id,created_at DESC,id DESC) d ORDER BY created_at DESC,id`, assets, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MissingVectors returns documents with no chunk embedded by the model,
// oldest first, at most limit, with how many there are in all. Superseded
// documents are included: the chronicle keeps them searchable.
func (s *Store) MissingVectors(ctx context.Context, model string, limit int) ([]Document, int, error) {
	if model == "" {
		return nil, 0, ErrInput
	}
	if limit < 1 || limit > 500 {
		limit = 25
	}
	var remaining int
	where := ` FROM ` + s.schema + `.knowledge_documents d WHERE NOT EXISTS(SELECT 1 FROM ` + s.schema + `.knowledge_chunks c WHERE c.document_id=d.id AND c.embed_model=$1)`
	if err := s.pool.QueryRow(ctx, `SELECT count(*)`+where, model).Scan(&remaining); err != nil {
		return nil, 0, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+documentColumns+where+` ORDER BY d.created_at,d.id LIMIT $2`, model, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, remaining, rows.Err()
}

// CountMissingVectors counts an asset's documents with no chunk embedded by
// the model, so a search can say its answer is incomplete.
func (s *Store) CountMissingVectors(ctx context.Context, asset uuid.UUID, model string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM `+s.schema+`.knowledge_documents d WHERE d.asset_id=$1 AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.knowledge_chunks c WHERE c.document_id=d.id AND c.embed_model=$2)`, asset, model).Scan(&n)
	return n, err
}
