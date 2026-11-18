package assessments

import (
	"testing"

	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/google/uuid"
)

func TestQAProfileValidateLintOnly(t *testing.T) {
	provider := uuid.New()
	base := QAProfile{Enabled: true, AutoRun: true, Threads: 1, TimeoutSeconds: 600, TestPath: "karate"}
	cases := map[string]struct {
		mutate func(*QAProfile)
		ok     bool
	}{
		"functional profile needs a base_url": {func(p *QAProfile) { p.Functional = true }, false},
		"functional profile with a base_url":  {func(p *QAProfile) { p.Functional, p.BaseURL = true, "https://staging.example.com" }, true},
		"lint-only profile needs no base_url": {func(p *QAProfile) { p.Lint = &qa.Lint{Tools: []string{"ktlint"}} }, true},
		"nothing to run":                      {func(p *QAProfile) {}, false},
		"lint-only with a malformed base_url": {func(p *QAProfile) { p.Lint, p.BaseURL = &qa.Lint{Tools: []string{"ruff"}}, "ftp://x" }, false},
		"perf needs a base_url": {func(p *QAProfile) {
			p.Perf = &QAPerf{Perf: qa.Perf{Features: []string{"a.feature"}, Users: 1, DurationSeconds: 5, P95Millis: 100}}
		}, false},
		"unknown linter":             {func(p *QAProfile) { p.Lint = &qa.Lint{Tools: []string{"rm"}} }, false},
		"every linter":               {func(p *QAProfile) { p.Lint = &qa.Lint{Tools: qa.LintToolNames()} }, true},
		"ai triage needs a provider": {func(p *QAProfile) { p.Lint, p.AITriage = &qa.Lint{Tools: []string{"ruff"}}, true }, false},
		"ai triage with a provider": {func(p *QAProfile) {
			p.Lint, p.AITriage, p.LLMProviderID = &qa.Lint{Tools: []string{"ruff"}}, true, &provider
		}, true},
	}
	for name, c := range cases {
		p := base
		c.mutate(&p)
		if err := p.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
