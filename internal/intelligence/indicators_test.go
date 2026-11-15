package intelligence

import (
	"encoding/json"
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

func TestIPv6Indicators(t *testing.T) {
	b, err := Parse([]byte(`{"version":"v","indicators":[
{"id":"a","type":"ipv6","value":"2001:DB8:0:0:0:0:0:1","valid_until":"2099-01-01T00:00:00Z"},
{"id":"b","type":"ipv6","value":"[2001:db8::dead[:]beef]","valid_until":"2099-01-01T00:00:00Z"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if b.Indicators[0].Value != "2001:db8::1" || b.Indicators[1].Value != "2001:db8::dead:beef" {
		t.Fatal("IPv6 not canonical", b.Indicators)
	}
	for _, bad := range []string{"1.2.3.4", "::ffff:1.2.3.4", "fe80::1%eth0", "gggg::1"} {
		if _, err := Parse([]byte(`{"version":"v","indicators":[{"id":"x","type":"ipv6","value":"` + bad + `","valid_until":"2099-01-01T00:00:00Z"}]}`)); err == nil {
			t.Error("invalid ipv6 accepted", bad)
		}
	}
}

func TestParseCSV(t *testing.T) {
	csvText := "\xef\xbb\xbfIndicator,Kind,Seen,Score,Campaign\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,,2026-11-01,90,Wfx Loot\n" +
		"evil[.]example,domain,,,\n" +
		"2001:db8::1,ip,,,\n" +
		"198.51.100.7,ip-dst,2026-01-01T00:00:00Z,,\n" +
		"hxxps://drop[.]example/x.sh,uri,,,\n" +
		"not a value,md5,,,\n" +
		"x,commit_message_regex,,,\n" +
		"evil.example,domain,,150,\n" +
		",domain,,,\n"
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	b, report, err := ParseCSV([]byte(csvText), CSVOptions{Mapping: CSVMapping{Value: "indicator", Type: "kind", FirstSeen: "seen", Confidence: "score", Label: "campaign"}, ValidDays: 30, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Rows != 9 || report.Accepted != 5 || report.Skipped != 4 || len(report.Problems) != 4 {
		t.Fatalf("report %+v", report)
	}
	got := map[string]Indicator{}
	for _, i := range b.Indicators {
		got[i.Type] = i
	}
	sha := got["sha256"]
	if sha.Confidence == nil || *sha.Confidence != 90 || !strings.HasPrefix(sha.ID, "wfx-loot-") || !sha.ValidUntil.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("sha256 row %+v", sha)
	}
	if got["domain"].Value != "evil.example" || got["ipv6"].Value != "2001:db8::1" || got["ipv4"].Value != "198.51.100.7" || got["url"].Value != "https://drop.example/x.sh" {
		t.Fatalf("rows %+v", got)
	}
	if _, err := Parse(mustJSON(t, b)); err != nil {
		t.Fatal("CSV bundle is not a valid import bundle", err)
	}
	if _, _, err := ParseCSV([]byte("a,b\n1,2\n"), CSVOptions{}); err == nil {
		t.Fatal("missing value column accepted")
	}
	if _, report, err := ParseCSV([]byte("value\n1.2.3.4\n"), CSVOptions{DefaultType: "sha256"}); err != nil || report.Skipped != 1 {
		t.Fatal("default type not applied", report, err)
	}
	if DetectType("d41d8cd98f00b204e9800998ecf8427e") != "md5" || DetectType("pkg:npm/x@1") != "purl" || DetectType("a.example") != "domain" {
		t.Fatal("DetectType")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
