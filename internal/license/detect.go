package license

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/google/licensecheck"
)

// Detection is a licence identified from a licence file's text (LIC-001,
// source "detected").
type Detection struct {
	Expression string `json:"expression"`
	// Confidence is the share of the file's words that match licence
	// texts, from 0 to 1.
	Confidence float64  `json:"confidence"`
	Copyright  []string `json:"copyright,omitempty"`
}

// MinConfidence is the coverage below which a detection is not used.
const MinConfidence = 0.5

// Detect identifies licences in a LICENSE, COPYING or copyright file using
// github.com/google/licensecheck (the detector pkg.go.dev uses). Several
// licence texts in one file are combined with AND.
func Detect(text []byte) (Detection, bool) {
	if len(text) == 0 || len(text) > 1<<20 {
		return Detection{}, false
	}
	coverage := licensecheck.Scan(text)
	out := Detection{Confidence: coverage.Percent / 100, Copyright: Copyrights(text)}
	ids := []string{}
	for _, m := range coverage.Match {
		if m.IsURL {
			continue
		}
		n := Normalize(m.ID)
		ids = append(ids, n.Expression)
	}
	out.Expression = And(ids...)
	if out.Expression == NoAssertion || out.Confidence < MinConfidence {
		return out, false
	}
	return out, true
}

var copyrightLine = regexp.MustCompile(`(?i)^\s*(?:copyright\b|\(c\)\s|©)`)

// Copyrights returns up to ten copyright lines from the start of a file,
// for third-party notices (LIC-009).
func Copyrights(text []byte) []string {
	out := []string{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(text))
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)
	for line := 0; scanner.Scan() && line < 400 && len(out) < 10; line++ {
		t := strings.TrimSpace(strings.TrimLeft(scanner.Text(), "#*/;- \t"))
		if !copyrightLine.MatchString(t) || strings.Contains(strings.ToLower(t), "copyright notice") || strings.Contains(strings.ToLower(t), "copyright holder") || strings.Contains(strings.ToLower(t), "copyright (c) <year>") {
			continue
		}
		if len(t) > 200 {
			t = t[:200]
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// IsLicenseFile reports whether a file name looks like a licence text.
func IsLicenseFile(name string) bool {
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "UNLICENSE", "MIT-LICENSE", "LICENSE-MIT", "LICENSE-APACHE"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}
