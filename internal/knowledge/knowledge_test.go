package knowledge

import (
	"math"
	"strings"
	"testing"
)

func TestVectorEncodingRoundTrips(t *testing.T) {
	in := []float32{0.5, -0.25, 1e-7, float32(math.Pi), 0}
	out, ok := decodeVector(encodeVector(in), len(in))
	if !ok || len(out) != len(in) {
		t.Fatal(out, ok)
	}
	for i := range in {
		if in[i] != out[i] {
			t.Errorf("%d: %v != %v", i, in[i], out[i])
		}
	}
	if _, ok := decodeVector(encodeVector(in), len(in)+1); ok {
		t.Fatal("a vector of another length must not decode")
	}
}

func TestSplitKeepsChunksBoundedAndLosesNothing(t *testing.T) {
	var paragraphs []string
	for i := 0; i < 40; i++ {
		paragraphs = append(paragraphs, strings.Repeat("The package is vulnerable to remote code execution. ", 3)+"Paragraph "+string(rune('A'+i%26)))
	}
	text := strings.Join(paragraphs, "\n\n")
	chunks := Split(text, 600, 80)
	if len(chunks) < 8 {
		t.Fatalf("expected several chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > 600 || strings.TrimSpace(c) == "" {
			t.Fatalf("chunk %d has %d characters", i, len(c))
		}
	}
	// Every word of the input appears in some chunk, even with overlap.
	joined := strings.Join(chunks, " ")
	for _, word := range strings.Fields(text) {
		if !strings.Contains(joined, word) {
			t.Fatalf("%q lost", word)
		}
	}
	if got := Split("short text that needs no split. "+strings.Repeat("x", 80), 4000, 100); len(got) != 1 {
		t.Fatal("short text stays whole", len(got))
	}
	// A run with no break is cut without splitting a character.
	wide := strings.Repeat("é", 700)
	for _, c := range Split(wide, 300, 0) {
		if !strings.HasPrefix(c, "é") || strings.Contains(c, "�") || len(c) > 300 {
			t.Fatalf("bad cut %d", len(c))
		}
	}
	if Split("   ", 600, 0) != nil || Split("text", 10, 0) != nil {
		t.Fatal("empty and too-small limits")
	}
}

func TestBudgetFromEnvAndEstimate(t *testing.T) {
	t.Setenv("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", "")
	t.Setenv("SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS", "")
	if b := BudgetFromEnv(); b.AssessmentInput != DefaultAssessmentInput || b.AssessmentOutput != DefaultAssessmentOutput {
		t.Fatal(b)
	}
	t.Setenv("SCRS_LLM_ASSESSMENT_INPUT_TOKENS", "1000000")
	t.Setenv("SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS", "12")
	if b := BudgetFromEnv(); b.AssessmentInput != 1000000 || b.AssessmentOutput != DefaultAssessmentOutput {
		t.Fatal("a value below 1000 is not a budget:", b)
	}
	if EstimateTokens(strings.Repeat("a", 300)) != 100 || EstimateTokens("") != 0 {
		t.Fatal("estimate")
	}
}
