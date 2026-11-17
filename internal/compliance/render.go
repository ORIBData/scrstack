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

// Formats are the report formats of CMP-006.
var Formats = []string{"json", "csv", "md", "pdf"}

// ContentType returns the media type of a report format.
func ContentType(format string) string {
	switch format {
	case "csv":
		return "text/csv; charset=utf-8"
	case "md":
		return "text/markdown; charset=utf-8"
	case "pdf":
		return "application/pdf"
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
	case "pdf":
		return renderPDF(r), nil
	}
	return nil, errors.New("format must be json, csv, md or pdf")
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
		detail := fmt.Sprintf("opened_in_window=%d closed_in_window=%d mapped_by_cwe=%d mapped_by_finding_type=%d %s", c.Opened, c.Closed, c.MappedByCWE, c.MappedByType, strings.Join(severities, " "))
		if c.Evidence != "" {
			detail = fmt.Sprintf("cat=%s evidence=%s %s", strings.ReplaceAll(c.Severity, " ", "_"), c.Evidence, detail)
		}
		write("category", c.ID, c.Name, strconv.Itoa(c.Open), detail)
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
	if st := r.STIG; st != nil {
		fmt.Fprintf(&b, "## STIG: %s\n\n", escape(st.Benchmark.Title))
		fmt.Fprintf(&b, "Benchmark %s, version %s, %s. Rules: %d; with open findings %d; mapped to SCRS evidence with nothing open %d; not evidenced by SCRS (manual review) %d.\n\n", escape(st.Benchmark.ID), escape(st.Benchmark.Version), escape(firstNonEmpty(st.Benchmark.Release, "release not stated")), st.Rules, st.RulesByEvidence["open_findings"], st.RulesByEvidence["no_open_findings"], st.RulesByEvidence["not_evidenced"])
		b.WriteString("| STIG id | CAT | Evidence | Open | Critical | High | Title |\n| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, c := range r.Categories {
			if c.Evidence == "not_evidenced" {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %s |\n", c.ID, c.Severity, c.Evidence, c.Open, c.BySeverity["critical"], c.BySeverity["high"], escape(c.Name))
		}
		b.WriteString("\nRules not evidenced by SCRS scans are listed in the JSON and CSV formats.\n\n")
	} else if len(r.Categories) > 0 {
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
	if r.AISummaryNotice != "" {
		fmt.Fprintf(&b, "## AI-written summaries (unverified)\n\n> %s\n\n", r.AISummaryNotice)
		if len(r.AISummaries) == 0 {
			b.WriteString("No asset in scope has an AI summary yet.\n\n")
		}
		for _, a := range r.AISummaries {
			fmt.Fprintf(&b, "### %s\n\n*%s, %s%s*\n\n%s\n\n", escape(a.Locator), a.CreatedAt.UTC().Format(time.RFC3339), firstNonEmpty(a.Model, "unknown model"), refSuffix(a.Ref), a.Text)
		}
	}
	return []byte(b.String())
}

func refSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return ", ref " + ref
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

// renderPDF lays out the same content as the Markdown report.
func renderPDF(r Report) []byte {
	m := r.Meta
	title := m.Framework.Name + " " + m.Framework.Version + " evidence report"
	d := newPDF(title)
	d.paragraph(title, 16, true)
	d.paragraph(r.Statement, 9, false)
	d.table([]string{"Field", "Value"}, []float64{0.25, 0.75}, [][]string{
		{"Scope", m.Scope.Kind + " " + firstNonEmpty(m.Scope.Name, scopeID(m.Scope))},
		{"Window", m.Since.UTC().Format("2006-01-02") + " to " + m.Until.UTC().Format("2006-01-02")},
		{"Data as of", m.DataAsOf.UTC().Format(time.RFC3339)},
		{"SCRS version", m.Version},
		{"Report id", m.ID.String()},
		{"Mapping source", m.Framework.Source},
	})
	d.heading("Feed freshness", 12)
	if len(r.Feeds) == 0 {
		d.paragraph("No advisory sources recorded.", 9, false)
	} else {
		rows := [][]string{}
		for _, f := range r.Feeds {
			rows = append(rows, []string{f.Name, firstNonEmpty(stamp(f.LastSuccess), "never"), strconv.FormatBool(f.Stale)})
		}
		d.table([]string{"Source", "Last success", "Stale"}, []float64{0.5, 0.35, 0.15}, rows)
	}
	d.heading(fmt.Sprintf("Assets (%d) and SBOM gaps (%d)", len(r.Assets), len(r.Gaps)), 12)
	if len(r.Gaps) == 0 {
		d.paragraph("Every asset in scope has a recent SBOM.", 9, false)
	} else {
		rows := [][]string{}
		for _, g := range r.Gaps {
			rows = append(rows, []string{g.Locator, g.Reason})
		}
		d.table([]string{"Asset", "Gap"}, []float64{0.6, 0.4}, rows)
	}
	totals := fmt.Sprintf("Findings considered: %d (open %d, dismissed %d).", r.Totals.Considered, r.Totals.Open, r.Totals.Dismissed)
	if len(r.Totals.Excluded) > 0 {
		kinds := make([]string, 0, len(r.Totals.Excluded))
		for k, n := range r.Totals.Excluded {
			kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
		}
		sort.Strings(kinds)
		totals += " Excluded types: " + strings.Join(kinds, ", ") + "."
	}
	d.paragraph(totals, 9, false)
	if st := r.STIG; st != nil {
		d.heading("STIG: "+st.Benchmark.Title, 12)
		d.paragraph(fmt.Sprintf("Benchmark %s, version %s, %s. Rules: %d; with open findings %d; mapped to SCRS evidence with nothing open %d; not evidenced by SCRS scans (manual review) %d.", st.Benchmark.ID, st.Benchmark.Version, firstNonEmpty(st.Benchmark.Release, "release not stated"), st.Rules, st.RulesByEvidence["open_findings"], st.RulesByEvidence["no_open_findings"], st.RulesByEvidence["not_evidenced"]), 9, false)
		rows := [][]string{}
		for _, c := range r.Categories {
			if c.Evidence != "not_evidenced" {
				rows = append(rows, []string{c.ID, c.Severity, strings.ReplaceAll(c.Evidence, "_", " "), fmtInt(c.Open), c.Name})
			}
		}
		d.table([]string{"STIG id", "CAT", "Evidence", "Open", "Title"}, []float64{0.17, 0.08, 0.15, 0.07, 0.53}, rows)
		d.paragraph("Rules not evidenced by SCRS scans are listed in the JSON and CSV formats.", 8, false)
	} else if len(r.Categories) > 0 {
		d.heading("Categories", 12)
		rows := [][]string{}
		for _, c := range r.Categories {
			rows = append(rows, []string{c.ID + " " + c.Name, fmtInt(c.Open), fmtInt(c.BySeverity["critical"]), fmtInt(c.BySeverity["high"]), fmtInt(c.Opened), fmtInt(c.Closed), fmtInt(c.MappedByCWE), fmtInt(c.MappedByType)})
		}
		d.table([]string{"Category", "Open", "Critical", "High", "Opened", "Closed", "By CWE", "By type"}, []float64{0.37, 0.09, 0.09, 0.09, 0.09, 0.09, 0.09, 0.09}, rows)
	}
	if u := r.Unmapped; u != nil {
		d.paragraph(fmt.Sprintf("Unmapped: %d findings carry no CWE; %d carry CWEs outside this pack.", u.NoCWE, u.OutsidePack), 9, false)
	}
	for _, req := range r.Requirements {
		d.heading("Requirement "+req.ID+": "+req.Title, 12)
		d.paragraph(req.Evidence, 9, false)
		keys := make([]string, 0, len(req.Metrics))
		for k := range req.Metrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		rows := [][]string{}
		for _, k := range keys {
			raw, _ := json.Marshal(req.Metrics[k])
			if len(raw) > 1200 {
				raw = append(raw[:1200], []byte("...")...)
			}
			rows = append(rows, []string{k, string(raw)})
		}
		if len(rows) > 0 {
			d.table([]string{"Metric", "Value"}, []float64{0.25, 0.75}, rows)
		}
	}
	if r.AISummaryNotice != "" {
		d.heading("AI-written summaries (unverified)", 12)
		d.paragraph(r.AISummaryNotice, 9, false)
		if len(r.AISummaries) == 0 {
			d.paragraph("No asset in scope has an AI summary yet.", 9, false)
		}
		for _, a := range r.AISummaries {
			d.heading(a.Locator, 10)
			d.paragraph(a.CreatedAt.UTC().Format(time.RFC3339)+", "+firstNonEmpty(a.Model, "unknown model")+refSuffix(a.Ref), 8, false)
			for _, line := range strings.Split(a.Text, "\n") {
				if strings.TrimSpace(line) != "" {
					d.paragraph(line, 9, false)
				}
			}
		}
	}
	return d.bytes()
}
