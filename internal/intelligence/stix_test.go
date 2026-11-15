package intelligence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func stixBundle(objects ...string) []byte {
	return []byte(`{"type":"bundle","id":"bundle--5d0092c5-5f74-4287-9642-33f4c354e56d","objects":[` + strings.Join(objects, ",") + `]}`)
}

func stixIndicator(n int, pattern string, extra string) string {
	body, _ := json.Marshal(pattern)
	return fmt.Sprintf(`{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-%012d","created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","pattern":%s,"pattern_type":"stix","valid_from":"2026-01-01T00:00:00Z"%s}`, n, body, extra)
}

func TestSTIXPatterns(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    []string // type=value
		partial bool
		reason  string
	}{
		{`[file:hashes.'SHA-256' = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855']`, []string{"sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, false, ""},
		{`[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e' OR file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']`, []string{"md5=d41d8cd98f00b204e9800998ecf8427e", "sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709"}, false, ""},
		// The hash identifies the file; the name condition is dropped.
		{`[file:name = 'invoice.exe' AND file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']`, []string{"md5=d41d8cd98f00b204e9800998ecf8427e"}, false, ""},
		{`[domain-name:value = 'Evil.Example'] OR [ipv4-addr:value = '198.51.100.7/32']`, []string{"domain=evil.example", "ipv4=198.51.100.7"}, false, ""},
		{`[url:value = 'http://evil.example/a\'b']`, []string{"url=http://evil.example/a'b"}, false, ""},
		{`[domain-name:value IN ('a.example', 'b.example')]`, []string{"domain=a.example", "domain=b.example"}, false, ""},
		{`[file:name = 'run.sh']`, []string{`file_path_regex=(?:^|/)run\.sh$`}, false, ""},
		{`([url:value = 'https://evil.example/'] OR [network-traffic:dst_port = 4444])`, []string{"url=https://evil.example/"}, true, ""},
		{`[ipv4-addr:value = '198.51.100.7'] AND [domain-name:value = 'evil.example']`, nil, false, SkipObservations},
		{`[ipv4-addr:value = '198.51.100.7'] FOLLOWEDBY [domain-name:value = 'evil.example']`, nil, false, SkipObservations},
		{`[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e'] REPEATS 5 TIMES WITHIN 600 SECONDS`, nil, false, SkipTimeWindow},
		{`[network-traffic:dst_ref.value = '198.51.100.7' AND network-traffic:dst_port = 443]`, nil, false, SkipObject},
		{`[process:name = 'evil.exe']`, nil, false, SkipObject},
		{`[file:size > 1000000]`, nil, false, SkipObject},
		{`[domain-name:value MATCHES '^evil']`, nil, false, SkipOperator},
		{`[domain-name:value NOT = 'evil.example']`, nil, false, SkipOperator},
		{`[file:name = 'a.exe' AND file:size = 10]`, nil, false, SkipConditions},
		{`[file:hashes.'SHA-512' = 'abc']`, nil, false, SkipHash},
		{`[ipv4-addr:value = '198.51.100.0/24']`, nil, false, SkipValue},
		{`[ipv6-addr:value = '2001:DB8::7/128']`, []string{"ipv6=2001:db8::7"}, false, ""},
		{`[ipv6-addr:value = '2001:db8::/32']`, nil, false, SkipValue},
		{`[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.5]`, nil, false, SkipObject},
		{`[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e'`, nil, false, SkipInvalid},
		{`[domain-name:value = 'unterminated]`, nil, false, SkipInvalid},
		{strings.Repeat("(", 40) + `[domain-name:value = 'a.example']` + strings.Repeat(")", 40), nil, false, SkipInvalid},
	} {
		matches, partial, reason, detail := checkablePattern(tc.pattern)
		var got []string
		for _, m := range matches {
			got = append(got, m.kind+"="+m.value)
		}
		if strings.Join(got, " ") != strings.Join(tc.want, " ") || partial != tc.partial || (len(tc.want) == 0 && reason != tc.reason) {
			t.Errorf("%s\n got %v partial=%v reason=%s (%s)\nwant %v partial=%v reason=%s", tc.pattern, got, partial, reason, detail, tc.want, tc.partial, tc.reason)
		}
	}
}

func TestParseSTIXBundle(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	raw := stixBundle(
		`{"type":"identity","spec_version":"2.1","id":"identity--00000000-0000-4000-8000-000000000001","name":"CERT"}`,
		stixIndicator(1, `[domain-name:value = 'evil.example']`, `,"confidence":85`),
		stixIndicator(2, `[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e' OR file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']`, `,"valid_until":"2027-01-01T00:00:00Z"`),
		stixIndicator(3, `[domain-name:value = 'old.example']`, `,"valid_until":"2026-02-01T00:00:00Z"`),
		stixIndicator(4, `[domain-name:value = 'gone.example']`, `,"revoked":true`),
		stixIndicator(5, `[network-traffic:dst_port = 4444]`, ``),
		strings.Replace(stixIndicator(6, `alert tcp any any -> any 4444`, ``), `"pattern_type":"stix"`, `"pattern_type":"snort"`, 1),
		strings.Replace(stixIndicator(7, "import \"pe\"\nrule Dropper { condition: pe.is_pe }", ``), `"pattern_type":"stix"`, `"pattern_type":"yara"`, 1),
		strings.Replace(stixIndicator(8, `[domain-name:value = 'x.example']`, ``), `"spec_version":"2.1"`, `"spec_version":"2.0"`, 1),
		// Two versions of one indicator: the later modified wins.
		strings.Replace(stixIndicator(9, `[domain-name:value = 'first.example']`, ``), `"modified":"2026-01-01T00:00:00Z"`, `"modified":"2026-03-01T00:00:00Z"`, 1),
		stixIndicator(9, `[domain-name:value = 'stale.example']`, ``),
	)
	imp, err := ParseSTIX(raw, now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := imp.Report
	if r.Objects != 11 || r.Indicators != 10 || r.Imported != 4 || r.Yara != 1 || len(imp.Touched) != 9 {
		t.Fatalf("report %+v touched %d", r, len(imp.Touched))
	}
	for reason, n := range map[string]int{SkipExpired: 1, SkipRevoked: 1, SkipObject: 1, SkipPatternType: 1, SkipVersion: 1, SkipSuperseded: 1} {
		if r.Skipped[reason] != n {
			t.Errorf("skipped[%s] = %d, want %d (%v)", reason, r.Skipped[reason], n, r.Skipped)
		}
	}
	byID := map[string]Indicator{}
	for _, i := range imp.Indicators {
		byID[i.ID] = i
	}
	first := byID["indicator--00000000-0000-4000-8000-000000000001"]
	if first.Value != "evil.example" || first.Confidence == nil || *first.Confidence != 85 || !first.ValidUntil.Equal(now.Add(90*24*time.Hour)) {
		t.Fatalf("defaults and confidence: %+v", first)
	}
	if byID["indicator--00000000-0000-4000-8000-000000000002#1"].Type != "md5" || byID["indicator--00000000-0000-4000-8000-000000000002#2"].Type != "sha1" {
		t.Fatal("multi-value patterns get numbered IDs", byID)
	}
	if byID["indicator--00000000-0000-4000-8000-000000000009"].Value != "first.example" {
		t.Fatal("the later version should win", byID)
	}
	if imp.Yara[0].ID != "indicator--00000000-0000-4000-8000-000000000007" {
		t.Fatal("YARA pattern lost", imp.Yara)
	}
	if imp.BundleID != "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d" {
		t.Fatal(imp.BundleID)
	}
	for _, bad := range []string{`{"type":"indicator"}`, `{"type":"bundle","id":"x","objects":[]}`, `[]`} {
		if _, err := ParseSTIX([]byte(bad), now, time.Hour); err == nil {
			t.Error("accepted", bad)
		}
	}
}

func TestCombineRules(t *testing.T) {
	combined, reasons := CombineRules([]string{
		"import \"pe\"\nrule A { condition: pe.is_pe }",
		"import \"pe\"\nimport \"math\"\nrule B { condition: math.entropy(0, filesize) > 7 }",
		"rule A { condition: true }",
	})
	if reasons[0] != "" || reasons[1] != "" || reasons[2] != SkipDuplicateRule {
		t.Fatal(reasons)
	}
	if strings.Count(combined, `import "pe"`) != 1 || !strings.HasPrefix(combined, "import \"pe\"\nimport \"math\"\n") || strings.Count(combined, "rule ") != 2 {
		t.Fatal(combined)
	}
	if combined, _ := CombineRules([]string{"rule A { condition: true }"}); !strings.Contains(combined, "rule A") {
		t.Fatal(combined)
	}
}
