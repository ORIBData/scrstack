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

func TestHashAndURLIndicators(t *testing.T) {
	b, err := Parse([]byte(`{"version":"v","indicators":[
{"id":"m","type":"md5","value":"D41D8CD98F00B204E9800998ECF8427E","valid_until":"2099-01-01T00:00:00Z","confidence":80},
{"id":"s","type":"sha1","value":"da39a3ee5e6b4b0d3255bfef95601890afd80709","valid_until":"2099-01-01T00:00:00Z"},
{"id":"u","type":"url","value":"hxxps://EVIL[.]example:443/Drop.sh#x","valid_until":"2099-01-01T00:00:00Z"},
{"id":"h","type":"url","value":"http://evil.example","valid_until":"2099-01-01T00:00:00Z"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range []string{"d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "https://evil.example/Drop.sh", "http://evil.example/"} {
		if b.Indicators[n].Value != want {
			t.Errorf("indicator %d normalized to %q, want %q", n, b.Indicators[n].Value, want)
		}
	}
	if *b.Indicators[0].Confidence != 80 {
		t.Fatal("confidence lost")
	}
	for _, bad := range []string{
		`"type":"md5","value":"d41d8cd98f00b204e9800998ecf8427"`,
		`"type":"sha1","value":"zz39a3ee5e6b4b0d3255bfef95601890afd80709"`,
		`"type":"url","value":"javascript:alert(1)"`,
		`"type":"url","value":"/relative/path"`,
		`"type":"domain","value":"bad.example","confidence":101`,
		`"type":"domain","value":"bad.example","mode":"block"`,
		`"type":"domain","value":"bad.example","source":"other"`,
	} {
		if _, err := Parse([]byte(`{"version":"v","indicators":[{"id":"x",` + bad + `,"valid_until":"2099-01-01T00:00:00Z"}]}`)); err == nil {
			t.Error("invalid indicator accepted", bad)
		}
	}
}

func TestScanBundleSources(t *testing.T) {
	merged := `{"version":"m","indicators":[
{"id":"x","type":"domain","value":"a.example","valid_until":"2099-01-01T00:00:00Z","source":"bundle","mode":"block","severity":"critical"},
{"id":"x","type":"domain","value":"b.example","valid_until":"2099-01-01T00:00:00Z","source":"partner_feed","mode":"alert","severity":"medium"}]}`
	b, err := ParseScan([]byte(merged))
	if err != nil {
		t.Fatal("the same ID in two sources is allowed", err)
	}
	if b.Indicators[0].Key() != "x" || b.Indicators[1].Key() != "partner_feed:x" {
		t.Fatal("legacy indicators keep plain IDs; others are prefixed", b.Indicators[0].Key(), b.Indicators[1].Key())
	}
	long := Indicator{Source: strings.Repeat("s", 63), ID: strings.Repeat("i", 128)}
	if kind := long.EventKind(); len(kind) > 64 || !strings.HasPrefix(kind, "pattern_") {
		t.Fatal("event kinds fit 64 bytes", kind)
	}
	if _, err := ParseScan([]byte(strings.Replace(merged, `"mode":"alert"`, `"mode":"loud"`, 1))); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := Parse([]byte(merged)); err == nil {
		t.Fatal("uploads cannot set source fields")
	}
}
