package intelligence

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CSV indicator import (TIF-005): a header row names the columns; the
// mapping says which header holds the value, type, first-seen date,
// confidence, label and expiry. Rows that do not parse are skipped and
// reported, so one bad line does not reject a vendor export.

// CSVMapping names the header of each field; empty uses the default name.
type CSVMapping struct {
	Value      string `json:"value"`
	Type       string `json:"type"`
	FirstSeen  string `json:"first_seen"`
	Confidence string `json:"confidence"`
	Label      string `json:"label"`
	ValidUntil string `json:"valid_until"`
}

// CSVOptions configure one import.
type CSVOptions struct {
	Mapping CSVMapping
	// DefaultType applies to rows without a type column or value; empty
	// detects hashes, IP addresses, URLs and domains from the value.
	DefaultType string
	// ValidDays sets the expiry from first_seen (or now) when a row has no
	// valid_until.
	ValidDays int
	Comma     rune
	Now       time.Time
}

// CSVSkip is a row that was not imported.
type CSVSkip struct {
	Row    int    `json:"row"`
	Reason string `json:"reason"`
}

// CSVReport counts an import.
type CSVReport struct {
	Rows     int       `json:"rows"`
	Accepted int       `json:"accepted"`
	Skipped  int       `json:"skipped"`
	Problems []CSVSkip `json:"problems"`
}

var hexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)
var labelSlug = regexp.MustCompile(`[^a-z0-9]+`)

// DetectType guesses an indicator type from its value.
func DetectType(value string) string {
	v := strings.TrimSpace(value)
	if hexOnly.MatchString(v) {
		switch len(v) {
		case 32:
			return "md5"
		case 40:
			return "sha1"
		case 64:
			return "sha256"
		}
	}
	plain := strings.Trim(strings.ReplaceAll(strings.ReplaceAll(v, "[.]", "."), "[:]", ":"), "[]")
	if addr, err := netip.ParseAddr(plain); err == nil {
		if addr.Is4() {
			return "ipv4"
		}
		return "ipv6"
	}
	if strings.HasPrefix(v, "pkg:") {
		return "purl"
	}
	if strings.Contains(v, "://") {
		return "url"
	}
	return "domain"
}

// typeAliases maps common vendor type names to SCRS indicator types.
var typeAliases = map[string]string{
	"sha-256": "sha256", "sha-1": "sha1", "hash_sha256": "sha256", "hash_sha1": "sha1", "hash_md5": "md5", "filehash-sha256": "sha256", "filehash-sha1": "sha1", "filehash-md5": "md5",
	"ip": "", "ip-dst": "", "ip-src": "", "ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "hostname": "domain", "domain-name": "domain", "fqdn": "domain", "uri": "url", "link": "url",
}

// csvTypes are the indicator types a CSV row may carry: values matched in
// files, packages and workflow steps (event patterns come from bundles).
var csvTypes = map[string]bool{"md5": true, "sha1": true, "sha256": true, "domain": true, "ipv4": true, "ipv6": true, "url": true, "purl": true, "workflow_step_name": true, "file_path_regex": true, "file_content_regex": true}

func parseDate(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// ParseCSV reads indicators from CSV. It fails only when the file itself is
// unusable (size, no header, no value column).
func ParseCSV(raw []byte, o CSVOptions) (Bundle, CSVReport, error) {
	report := CSVReport{Problems: []CSVSkip{}}
	if len(raw) > MaxImportBytes {
		return Bundle{}, report, errors.New("CSV is over 16 MiB")
	}
	if o.ValidDays <= 0 {
		o.ValidDays = 180
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	names := map[string]string{"value": o.Mapping.Value, "type": o.Mapping.Type, "first_seen": o.Mapping.FirstSeen, "confidence": o.Mapping.Confidence, "label": o.Mapping.Label, "valid_until": o.Mapping.ValidUntil}
	for field, name := range names {
		if name == "" {
			names[field] = field
		}
	}
	if o.DefaultType != "" && !csvTypes[o.DefaultType] {
		return Bundle{}, report, fmt.Errorf("type %s cannot be imported from CSV", o.DefaultType)
	}
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))))
	if o.Comma != 0 {
		reader.Comma = o.Comma
	}
	reader.FieldsPerRecord = -1
	reader.Comment = '#'
	header, err := reader.Read()
	if err != nil {
		return Bundle{}, report, errors.New("CSV has no header row")
	}
	column := map[string]int{}
	for i, h := range header {
		column[strings.ToLower(strings.TrimSpace(h))] = i
	}
	index := func(field string) int {
		if i, ok := column[strings.ToLower(names[field])]; ok {
			return i
		}
		return -1
	}
	valueAt := index("value")
	if valueAt < 0 {
		return Bundle{}, report, fmt.Errorf("CSV has no %q column; set value_column", names["value"])
	}
	typeAt, seenAt, confidenceAt, labelAt, untilAt := index("type"), index("first_seen"), index("confidence"), index("label"), index("valid_until")
	bundle := Bundle{Version: "csv"}
	seen := map[string]bool{}
	skip := func(row int, reason string) {
		report.Skipped++
		if len(report.Problems) < 50 {
			report.Problems = append(report.Problems, CSVSkip{Row: row, Reason: reason})
		}
	}
	for row := 2; ; row++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			skip(row, "unreadable CSV row")
			if report.Skipped > 10000 {
				return Bundle{}, report, errors.New("CSV is not readable")
			}
			continue
		}
		report.Rows++
		cell := func(i int) string {
			if i < 0 || i >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[i])
		}
		value := cell(valueAt)
		if value == "" {
			skip(row, "empty value")
			continue
		}
		kind := strings.ToLower(cell(typeAt))
		if alias, ok := typeAliases[kind]; ok {
			kind = alias
		}
		if kind == "" {
			kind = o.DefaultType
		}
		if kind == "" {
			kind = DetectType(value)
		}
		if !csvTypes[kind] {
			skip(row, "type "+clip(kind, 40)+" cannot be imported from CSV")
			continue
		}
		normalized, err := normalize(kind, value)
		if err != nil {
			skip(row, err.Error())
			continue
		}
		indicator := Indicator{Type: kind, Value: normalized}
		if raw := cell(confidenceAt); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 || n > 100 {
				skip(row, "confidence must be 0 to 100")
				continue
			}
			indicator.Confidence = &n
		}
		start := o.Now
		if raw := cell(seenAt); raw != "" {
			t, ok := parseDate(raw)
			if !ok {
				skip(row, "first_seen is not a date")
				continue
			}
			start = t
		}
		indicator.ValidUntil = start.AddDate(0, 0, o.ValidDays)
		if raw := cell(untilAt); raw != "" {
			t, ok := parseDate(raw)
			if !ok {
				skip(row, "valid_until is not a date")
				continue
			}
			indicator.ValidUntil = t
		}
		sum := sha256.Sum256([]byte(kind + "\x00" + normalized))
		id := "csv-" + hex.EncodeToString(sum[:8])
		if label := strings.Trim(labelSlug.ReplaceAllString(strings.ToLower(cell(labelAt)), "-"), "-"); label != "" {
			id = clip(label, 64) + "-" + hex.EncodeToString(sum[:8])
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if len(bundle.Indicators) >= MaxImportIndicators {
			return Bundle{}, report, errors.New("CSV has more than 50000 indicators")
		}
		indicator.ID = id
		bundle.Indicators = append(bundle.Indicators, indicator)
	}
	report.Accepted = len(bundle.Indicators)
	sum := sha256.Sum256(raw)
	bundle.Version = "csv:" + hex.EncodeToString(sum[:6])
	return bundle, report, nil
}
