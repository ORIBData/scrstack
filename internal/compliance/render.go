package compliance

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Formats are the report formats of CMP-006 (PDF is P2).
var Formats = []string{"json", "csv", "md"}

// ContentType returns the media type of a report format.
func ContentType(format string) string {
	switch format {
	case "csv":
		return "text/csv; charset=utf-8"
	case "md":
		return "text/markdown; charset=utf-8"
	}
	return "application/json"
}

func fmtInt(n int) string { return strconv.Itoa(n) }

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// Render serialises a report.
func Render(r Report, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(r, "", "  ")
	case "csv":
		return renderCSV(r)
	case "md":
		return renderMarkdown(r), nil
	}
	return nil, errors.New("format must be json, csv or md")
}

func stamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func renderCSV(r Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	write := func(fields ...string) { _ = w.Write(fields) }
	write("section", "key", "name", "value", "detail")
	m := r.Meta
	write("meta", "framework", m.Framework.Name+" "+m.Framework.Version, m.Framework.ID, m.Framework.Source)
	write("meta", "scope", m.Scope.Kind, scopeID(m.Scope), m.Scope.Name)
	write("meta", "window", "", m.Since.UTC().Format(time.RFC3339), m.Until.UTC().Format(time.RFC3339))
	write("meta", "data_as_of", "", m.DataAsOf.UTC().Format(time.RFC3339), "")
	write("meta", "scrs_version", "", m.Version, "")
	write("meta", "statement", "", r.Statement, "")
	for _, f := range r.Feeds {
		write("feed", f.Key, f.Name, stamp(f.LastSuccess), strconv.FormatBool(f.Stale))
	}
	for _, a := range r.Assets {
		write("asset", a.ID.String(), a.Locator, stamp(a.LastSBOM), fmt.Sprintf("sbom_revisions_in_window=%d components=%d", a.SBOMs, a.Components))
	}
	for _, g := range r.Gaps {
		write("gap", g.AssetID.String(), g.Locator, g.Reason, "")
	}
	write("totals", "findings_considered", "", strconv.Itoa(r.Totals.Considered), "")
	write("totals", "open", "", strconv.Itoa(r.Totals.Open), "")
	for _, c := range r.Categories {
		severities := []string{}
		for _, s := range severityOrder {
			severities = append(severities, fmt.Sprintf("%s=%d", s, c.BySeverity[s]))
		}
		write("category", c.ID, c.Name, strconv.Itoa(c.Open), fmt.Sprintf("opened_in_window=%d closed_in_window=%d mapped_by_cwe=%d mapped_by_finding_type=%d %s", c.Opened, c.Closed, c.MappedByCWE, c.MappedByType, strings.Join(severities, " ")))
	}
	if u := r.Unmapped; u != nil {
		write("unmapped", "no_cwe", "", strconv.Itoa(u.NoCWE), "")
		write("unmapped", "cwe_outside_pack", "", strconv.Itoa(u.OutsidePack), "")
	}
	for _, req := range r.Requirements {
		metrics, _ := json.Marshal(req.Metrics)
		write("requirement", req.ID, req.Title, req.Evidence, string(metrics))
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func scopeID(s Scope) string {
	if s.ID == nil {
		return ""
	}
	return s.ID.String()
}

func renderMarkdown(r Report) []byte {
	var b strings.Builder
	m := r.Meta
	fmt.Fprintf(&b, "# %s %s evidence report\n\n", m.Framework.Name, m.Framework.Version)
	fmt.Fprintf(&b, "> %s\n\n", r.Statement)
	fmt.Fprintf(&b, "| | |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Scope | %s %s |\n", m.Scope.Kind, firstNonEmpty(m.Scope.Name, scopeID(m.Scope)))
	fmt.Fprintf(&b, "| Window | %s to %s |\n", m.Since.UTC().Format("2006-01-02"), m.Until.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "| Data as of | %s |\n", m.DataAsOf.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "| SCRS version | %s |\n", m.Version)
	fmt.Fprintf(&b, "| Mapping source | %s |\n\n", m.Framework.Source)
	b.WriteString("## Feed freshness\n\n")
	if len(r.Feeds) == 0 {
		b.WriteString("No advisory sources recorded.\n\n")
	} else {
		b.WriteString("| Source | Last success | Stale |\n| --- | --- | --- |\n")
		for _, f := range r.Feeds {
			fmt.Fprintf(&b, "| %s | %s | %v |\n", f.Name, firstNonEmpty(stamp(f.LastSuccess), "never"), f.Stale)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Assets (%d) and SBOM gaps (%d)\n\n", len(r.Assets), len(r.Gaps))
	if len(r.Gaps) == 0 {
		b.WriteString("Every asset in scope has a recent SBOM.\n\n")
	} else {
		b.WriteString("| Asset | Gap |\n| --- | --- |\n")
		for _, g := range r.Gaps {
			fmt.Fprintf(&b, "| %s | %s |\n", escape(g.Locator), g.Reason)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Findings considered: %d (open %d, dismissed %d).", r.Totals.Considered, r.Totals.Open, r.Totals.Dismissed)
	if len(r.Totals.Excluded) > 0 {
		kinds := make([]string, 0, len(r.Totals.Excluded))
		for k, n := range r.Totals.Excluded {
			kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
		}
		sort.Strings(kinds)
		fmt.Fprintf(&b, " Excluded types: %s.", strings.Join(kinds, ", "))
	}
	b.WriteString("\n\n")
	if len(r.Categories) > 0 {
		b.WriteString("## Categories\n\n| Category | Open | Critical | High | Opened | Closed | By CWE | By type |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, c := range r.Categories {
			fmt.Fprintf(&b, "| %s %s | %d | %d | %d | %d | %d | %d | %d |\n", c.ID, escape(c.Name), c.Open, c.BySeverity["critical"], c.BySeverity["high"], c.Opened, c.Closed, c.MappedByCWE, c.MappedByType)
		}
		b.WriteString("\n")
	}
	if u := r.Unmapped; u != nil {
		fmt.Fprintf(&b, "**Unmapped:** %d findings carry no CWE; %d carry CWEs outside this pack.\n\n", u.NoCWE, u.OutsidePack)
	}
	for _, req := range r.Requirements {
		fmt.Fprintf(&b, "## Requirement %s: %s\n\n%s\n\n", req.ID, req.Title, req.Evidence)
		keys := make([]string, 0, len(req.Metrics))
		for k := range req.Metrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			raw, _ := json.Marshal(req.Metrics[k])
			if len(raw) > 400 {
				raw = append(raw[:400], []byte("…")...)
			}
			fmt.Fprintf(&b, "- **%s:** `%s`\n", k, raw)
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func escape(s string) string { return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s) }
