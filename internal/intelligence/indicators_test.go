package intelligence

import (
	"strings"
	"testing"
	"time"
)

func TestIndicatorValidation(t *testing.T) {
	valid := `{"version":"v1","indicators":[{"id":"one","type":"domain","value":"BAD.example","valid_until":"2099-01-01T00:00:00Z"}]}`
	b, err := Parse([]byte(valid))
	if err != nil || b.Indicators[0].Value != "bad.example" {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, "BAD.example", "bad..example", 1), strings.Replace(valid, "domain", "regex", 1), strings.Replace(valid, `"valid_until":"2099-01-01T00:00:00Z"`, `"valid_until":null`, 1), valid + `{}`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("invalid indicator accepted")
		}
	}
}

func TestCampaignIndicatorTypes(t *testing.T) {
	bundle := `{"version":"wfx-loot","indicators":[
{"id":"ip","type":"ipv4","value":"194.150.166[.]244","valid_until":"2099-01-01T00:00:00Z"},
{"id":"pr","type":"pr_title_regex","value":"(?i)dependency audit","valid_until":"2099-01-01T00:00:00Z"},
{"id":"br","type":"git_branch_regex","value":"^wfx-docs$","valid_until":"2099-01-01T00:00:00Z"},
{"id":"old","type":"git_branch_regex","value":"^old$","valid_until":"2000-01-01T00:00:00Z"},
{"id":"pkg","type":"purl","value":"pkg:golang/github.com/onuragtas/docker-env@v1.0.278","valid_until":"2099-01-01T00:00:00Z"},
{"id":"step","type":"workflow_step_name","value":"Pass runtime","valid_until":"2099-01-01T00:00:00Z"}]}`
	b, err := Parse([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if b.Indicators[0].Value != "194.150.166.244" {
		t.Fatal("defanged address not normalized", b.Indicators[0].Value)
	}
	now := time.Now()
	if p := b.Patterns("pr_title_regex", now); len(p) != 1 || !p[0].MatchString("docs: Dependency Audit notes") {
		t.Fatal("PR title pattern not applied")
	}
	if p := b.Patterns("git_branch_regex", now); len(p) != 1 {
		t.Fatal("expired branch pattern still active")
	}
	for _, bad := range []string{`"type":"pr_title_regex","value":"(unclosed"`, `"type":"ipv4","value":"::1"`, `"type":"purl","value":"npm/x"`} {
		if _, err := Parse([]byte(`{"version":"v","indicators":[{"id":"x",` + bad + `,"valid_until":"2099-01-01T00:00:00Z"}]}`)); err == nil {
			t.Fatal("invalid indicator accepted", bad)
		}
	}
}
