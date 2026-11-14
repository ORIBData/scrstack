// Package advisory reads CVE-level advisory sources that OSV lacks (VUL-002,
// VUL-006): the NVD API 2.0 and the CVE Program's CVE Services API. Both are
// converted to one OSV-shaped record with the original kept verbatim, so
// severity sources, CWEs and vendor descriptions sit beside OSV data.
package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CVEPattern matches a CVE identifier.
var CVEPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// CVSS is one score offered by a source (VUL-004).
type CVSS struct {
	Version      string  `json:"version"`
	Vector       string  `json:"vector"`
	BaseScore    float64 `json:"base_score"`
	BaseSeverity string  `json:"base_severity,omitempty"`
	Source       string  `json:"source,omitempty"`
	Type         string  `json:"type,omitempty"`
}

// Reference is an advisory link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Severity is an OSV severity entry.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Record is a CVE in OSV schema with origin nvd or cve5.
type Record struct {
	ID         string      `json:"id"`
	Origin     string      `json:"origin"`
	Modified   time.Time   `json:"modified"`
	Published  *time.Time  `json:"published,omitempty"`
	Withdrawn  *time.Time  `json:"withdrawn,omitempty"`
	Aliases    []string    `json:"aliases"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	Severity   []Severity  `json:"severity"`
	References []Reference `json:"references"`
	// DatabaseSpecific carries what OSV has no field for.
	DatabaseSpecific struct {
		CVSS     []CVSS          `json:"cvss"`
		CWE      []string        `json:"cwe"`
		Status   string          `json:"status,omitempty"`
		Assigner string          `json:"assigner,omitempty"`
		Affected json.RawMessage `json:"affected,omitempty"`
	} `json:"database_specific"`
}

// Raw is a record with its original source document.
type Raw struct {
	Record Record
	Source json.RawMessage
}

// Client calls one source over HTTPS.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// ErrNotFound means the source has no record for the id.
var ErrNotFound = errors.New("no such CVE at the source")

// ErrRateLimited means the source asked SCRS to slow down.
var ErrRateLimited = errors.New("advisory source rate limit reached")

func (c Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c Client) get(ctx context.Context, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SCRS-advisory-sync/1")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("advisory source unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("advisory response read failed: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden && c.APIKey == "":
		return nil, ErrRateLimited
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("advisory source returned HTTP %d", resp.StatusCode)
	case int64(len(data)) > limit:
		return nil, errors.New("advisory response exceeds its size limit")
	}
	return data, nil
}

// NVD response shapes (API 2.0).
type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		Vector       string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type nvdCVE struct {
	ID          string    `json:"id"`
	Source      string    `json:"sourceIdentifier"`
	Published   string    `json:"published"`
	Modified    string    `json:"lastModified"`
	Status      string    `json:"vulnStatus"`
	Description []langStr `json:"descriptions"`
	Metrics     struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []langStr `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

type langStr struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func english(list []langStr) string {
	for _, d := range list {
		if strings.HasPrefix(d.Lang, "en") {
			return d.Value
		}
	}
	if len(list) > 0 {
		return list[0].Value
	}
	return ""
}

// nvdTime parses NVD's timestamps, which omit the zone (they are UTC).
func nvdTime(raw string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func severityType(version string) string {
	switch {
	case strings.HasPrefix(version, "4"):
		return "CVSS_V4"
	case strings.HasPrefix(version, "3"):
		return "CVSS_V3"
	}
	return "CVSS_V2"
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func fromNVD(c nvdCVE, raw json.RawMessage) (Raw, error) {
	if !CVEPattern.MatchString(c.ID) {
		return Raw{}, errors.New("NVD record has no CVE id")
	}
	r := Record{ID: c.ID, Origin: "nvd", Aliases: []string{}, Severity: []Severity{}, References: []Reference{}, Details: clip(english(c.Description), 16384)}
	r.DatabaseSpecific.CVSS, r.DatabaseSpecific.CWE = []CVSS{}, []string{}
	r.Modified, _ = nvdTime(c.Modified)
	if t, ok := nvdTime(c.Published); ok {
		r.Published = &t
	}
	r.DatabaseSpecific.Status = c.Status
	r.DatabaseSpecific.Assigner = c.Source
	if strings.EqualFold(c.Status, "Rejected") {
		withdrawn := r.Modified
		r.Withdrawn = &withdrawn
	}
	for _, group := range [][]nvdMetric{c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
		for _, m := range group {
			severity := firstNonEmpty(m.CVSSData.BaseSeverity, m.BaseSeverity)
			r.DatabaseSpecific.CVSS = append(r.DatabaseSpecific.CVSS, CVSS{Version: m.CVSSData.Version, Vector: m.CVSSData.Vector, BaseScore: m.CVSSData.BaseScore, BaseSeverity: strings.ToUpper(severity), Source: m.Source, Type: m.Type})
			if m.Type == "Primary" && m.CVSSData.Vector != "" {
				r.Severity = append(r.Severity, Severity{Type: severityType(m.CVSSData.Version), Score: m.CVSSData.Vector})
			}
		}
	}
	cwe := map[string]bool{}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") && !cwe[d.Value] {
				cwe[d.Value] = true
				r.DatabaseSpecific.CWE = append(r.DatabaseSpecific.CWE, d.Value)
			}
		}
	}
	sort.Strings(r.DatabaseSpecific.CWE)
	for _, ref := range c.References {
		kind := "WEB"
		for _, tag := range ref.Tags {
			switch tag {
			case "Patch":
				kind = "FIX"
			case "Vendor Advisory", "Third Party Advisory":
				kind = "ADVISORY"
			}
		}
		if len(r.References) < 100 {
			r.References = append(r.References, Reference{Type: kind, URL: clip(ref.URL, 2048)})
		}
	}
	return Raw{Record: r, Source: raw}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// NVDPage is one page of the NVD CVE API.
type NVDPage struct {
	Records []Raw
	Total   int
	Start   int
	PerPage int
}

func (c Client) nvd(ctx context.Context, query url.Values) (NVDPage, error) {
	data, err := c.get(ctx, strings.TrimSuffix(c.BaseURL, "/")+"?"+query.Encode(), 64<<20)
	if err != nil {
		return NVDPage{}, err
	}
	var body struct {
		PerPage int `json:"resultsPerPage"`
		Start   int `json:"startIndex"`
		Total   int `json:"totalResults"`
		Vulns   []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal(data, &body) != nil {
		return NVDPage{}, errors.New("NVD response is not JSON")
	}
	page := NVDPage{Total: body.Total, Start: body.Start, PerPage: body.PerPage}
	for _, v := range body.Vulns {
		var c nvdCVE
		if json.Unmarshal(v.CVE, &c) != nil {
			continue
		}
		if r, err := fromNVD(c, v.CVE); err == nil {
			page.Records = append(page.Records, r)
		}
	}
	return page, nil
}

// NVDCVE fetches one CVE from the NVD.
func (c Client) NVDCVE(ctx context.Context, id string) (Raw, error) {
	page, err := c.nvd(ctx, url.Values{"cveId": {id}})
	if err != nil {
		return Raw{}, err
	}
	if len(page.Records) == 0 {
		return Raw{}, ErrNotFound
	}
	return page.Records[0], nil
}

// NVDTimeFormat is the NVD API's date parameter format.
const NVDTimeFormat = "2006-01-02T15:04:05.000Z"

// NVDModified returns one page of CVEs modified in [start, end); the NVD
// allows windows of at most 120 days.
func (c Client) NVDModified(ctx context.Context, start, end time.Time, startIndex int) (NVDPage, error) {
	return c.nvd(ctx, url.Values{"lastModStartDate": {start.UTC().Format(NVDTimeFormat)}, "lastModEndDate": {end.UTC().Format(NVDTimeFormat)}, "startIndex": {strconv.Itoa(startIndex)}, "resultsPerPage": {"2000"}})
}

// CVE JSON 5 record shapes.
type cve5Metric struct {
	V40 *cve5Score `json:"cvssV4_0"`
	V31 *cve5Score `json:"cvssV3_1"`
	V30 *cve5Score `json:"cvssV3_0"`
	V20 *cve5Score `json:"cvssV2_0"`
}

type cve5Score struct {
	Version      string  `json:"version"`
	Vector       string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cve5Container struct {
	ProviderMetadata struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Descriptions []langStr `json:"descriptions"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWE string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	Metrics    []cve5Metric      `json:"metrics"`
	Affected   json.RawMessage   `json:"affected"`
	References []json.RawMessage `json:"references"`
}

// CVE5 fetches one CVE record from the CVE Program's CVE Services API.
func (c Client) CVE5(ctx context.Context, id string) (Raw, error) {
	data, err := c.get(ctx, strings.TrimSuffix(c.BaseURL, "/")+"/"+url.PathEscape(id), 16<<20)
	if err != nil {
		return Raw{}, err
	}
	return ParseCVE5(data)
}

// ParseCVE5 converts a CVE JSON 5 record.
func ParseCVE5(data []byte) (Raw, error) {
	var body struct {
		Metadata struct {
			ID        string `json:"cveId"`
			State     string `json:"state"`
			Published string `json:"datePublished"`
			Updated   string `json:"dateUpdated"`
			Rejected  string `json:"dateRejected"`
			Assigner  string `json:"assignerShortName"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA cve5Container   `json:"cna"`
			ADP []cve5Container `json:"adp"`
		} `json:"containers"`
	}
	if json.Unmarshal(data, &body) != nil || !CVEPattern.MatchString(body.Metadata.ID) {
		return Raw{}, errors.New("CVE record is not CVE JSON 5")
	}
	m := body.Metadata
	r := Record{ID: m.ID, Origin: "cve5", Aliases: []string{}, Severity: []Severity{}, References: []Reference{}}
	r.DatabaseSpecific.CVSS, r.DatabaseSpecific.CWE = []CVSS{}, []string{}
	r.DatabaseSpecific.Status, r.DatabaseSpecific.Assigner = m.State, m.Assigner
	parse := func(s string) (time.Time, bool) {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC(), true
		}
		return nvdTime(s)
	}
	r.Modified, _ = parse(firstNonEmpty(m.Updated, m.Rejected, m.Published))
	if t, ok := parse(m.Published); ok {
		r.Published = &t
	}
	if strings.EqualFold(m.State, "REJECTED") {
		withdrawn := r.Modified
		r.Withdrawn = &withdrawn
	}
	cna := body.Containers.CNA
	r.Details = clip(english(cna.Descriptions), 16384)
	r.DatabaseSpecific.Affected = cna.Affected
	cwe := map[string]bool{}
	containers := append([]cve5Container{cna}, body.Containers.ADP...)
	for n, container := range containers {
		source := firstNonEmpty(container.ProviderMetadata.ShortName, m.Assigner)
		for _, metric := range container.Metrics {
			for _, s := range []*cve5Score{metric.V40, metric.V31, metric.V30, metric.V20} {
				if s == nil || s.Vector == "" {
					continue
				}
				r.DatabaseSpecific.CVSS = append(r.DatabaseSpecific.CVSS, CVSS{Version: s.Version, Vector: s.Vector, BaseScore: s.BaseScore, BaseSeverity: strings.ToUpper(s.BaseSeverity), Source: source, Type: map[bool]string{true: "CNA", false: "ADP"}[n == 0]})
				if n == 0 {
					r.Severity = append(r.Severity, Severity{Type: severityType(s.Version), Score: s.Vector})
				}
			}
		}
		for _, p := range container.ProblemTypes {
			for _, d := range p.Descriptions {
				if strings.HasPrefix(d.CWE, "CWE-") && !cwe[d.CWE] {
					cwe[d.CWE] = true
					r.DatabaseSpecific.CWE = append(r.DatabaseSpecific.CWE, d.CWE)
				}
			}
		}
	}
	sort.Strings(r.DatabaseSpecific.CWE)
	for _, raw := range cna.References {
		var ref struct {
			URL  string   `json:"url"`
			Tags []string `json:"tags"`
		}
		if json.Unmarshal(raw, &ref) == nil && ref.URL != "" && len(r.References) < 100 {
			kind := "WEB"
			for _, tag := range ref.Tags {
				if tag == "patch" {
					kind = "FIX"
				} else if tag == "vendor-advisory" || tag == "third-party-advisory" {
					kind = "ADVISORY"
				}
			}
			r.References = append(r.References, Reference{Type: kind, URL: clip(ref.URL, 2048)})
		}
	}
	return Raw{Record: r, Source: json.RawMessage(data)}, nil
}
