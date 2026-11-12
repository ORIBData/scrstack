package intelligence

import (
	"strings"
	"testing"
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
