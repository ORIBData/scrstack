package compliance

import (
	"sort"
	"time"

	"github.com/google/uuid"
)

// Statement is printed on every report (AT-30: no compliance verdict).
const Statement = "Evidence for discussion with an assessor. SCRS does not certify compliance, and this report contains no compliance verdict."

// Scope selects the assets a report covers.
type Scope struct {
	Kind string     `json:"kind"`
	ID   *uuid.UUID `json:"id,omitempty"`
	Name string     `json:"name,omitempty"`
}

// Params tune the evidence views.
type Params struct {
	// SBOMMaxAgeDays: an asset without an SBOM this recent is a gap.
	SBOMMaxAgeDays int `json:"sbom_max_age_days"`
	// Patch windows for PCI DSS 6.3.3.
	SLACriticalDays int `json:"sla_critical_days"`
	SLAHighDays     int `json:"sla_high_days"`
}

// DefaultParams are used for unset parameters.
var DefaultParams = Params{SBOMMaxAgeDays: 30, SLACriticalDays: 30, SLAHighDays: 90}

// Asset is one asset in scope.
type Asset struct {
	ID           uuid.UUID  `json:"id"`
	Locator      string     `json:"locator"`
	Type         string     `json:"type"`
	Owner        string     `json:"owner,omitempty"`
	LastAssessed *time.Time `json:"last_assessed_at"`
	LastSBOM     *time.Time `json:"last_sbom_at"`
	// SBOMs counts revisions with an SBOM in the window (6.3.2 history).
	SBOMs      int `json:"sbom_revisions_in_window"`
	Components int `json:"components"`
}

// Finding is the part of a register entry reports use.
type Finding struct {
	ID         uuid.UUID  `json:"id"`
	AssetID    uuid.UUID  `json:"asset_id"`
	Type       string     `json:"type"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	AdvisoryID string     `json:"advisory_id"`
	FirstSeen  time.Time  `json:"first_seen"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	CWEs       []int      `json:"cwes,omitempty"`
	KEV        bool       `json:"kev,omitempty"`
}

// Feed is one advisory source's freshness when the report was built.
type Feed struct {
	Key         string     `json:"key"`
	Name        string     `json:"name"`
	LastSuccess *time.Time `json:"last_success_at"`
	Stale       bool       `json:"stale"`
}

// Input is the data a report is built from.
type Input struct {
	ID       uuid.UUID
	Scope    Scope
	Since    time.Time
	Until    time.Time
	DataAsOf time.Time
	Version  string
	Format   string
	Params   Params
	Assets   []Asset
	Findings []Finding
	Feeds    []Feed
}

// Report is a built evidence report.
type Report struct {
	Meta         Meta                `json:"report"`
	Statement    string              `json:"statement"`
	Feeds        []Feed              `json:"feed_freshness"`
	Assets       []Asset             `json:"assets"`
	Gaps         []Gap               `json:"gaps"`
	Totals       Totals              `json:"totals"`
	Categories   []CategoryResult    `json:"categories,omitempty"`
	Unmapped     *Unmapped           `json:"unmapped,omitempty"`
	Requirements []RequirementResult `json:"requirements,omitempty"`
	STIG         *STIGSummary        `json:"stig,omitempty"`
}

// STIGSummary is the STIG view (CMP-004). Rule evidence is one of
// open_findings, no_open_findings (SCRS scans give evidence for the rule
// and report nothing open) or not_evidenced (manual review needed). It is
// never a STIG checklist status: SCRS does not mark rules "Not a Finding".
type STIGSummary struct {
	Benchmark Benchmark `json:"benchmark"`
	Rules     int       `json:"rules"`
	// RulesByEvidence counts rules per evidence value.
	RulesByEvidence map[string]int `json:"rules_by_evidence"`
	// OpenByCAT counts rules with open findings per severity category.
	OpenByCAT map[string]int `json:"rules_with_open_findings_by_cat"`
}

// Meta records what a report is about and when its data was read (CMP-006).
type Meta struct {
	ID        uuid.UUID `json:"id"`
	Framework PackRef   `json:"framework"`
	Scope     Scope     `json:"scope"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
	DataAsOf  time.Time `json:"data_as_of"`
	Version   string    `json:"scrs_version"`
	Format    string    `json:"format"`
	Params    Params    `json:"params"`
}

// PackRef names the pack a report used.
type PackRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// Gap is an asset without a recent SBOM (CMP-002, AT-30).
type Gap struct {
	AssetID uuid.UUID `json:"asset_id"`
	Locator string    `json:"locator"`
	Reason  string    `json:"reason"`
}

// Totals summarise the findings considered.
type Totals struct {
	Considered int            `json:"findings_considered"`
	Open       int            `json:"open"`
	Excluded   map[string]int `json:"excluded_types"`
	Dismissed  int            `json:"dismissed"`
}

// CategoryResult is one framework category (CMP-003).
type CategoryResult struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Open         int            `json:"open"`
	Opened       int            `json:"opened_in_window"`
	Closed       int            `json:"closed_in_window"`
	BySeverity   map[string]int `json:"open_by_severity"`
	MappedByCWE  int            `json:"mapped_by_cwe"`
	MappedByType int            `json:"mapped_by_finding_type"`
	// STIG rules only.
	Severity string     `json:"severity,omitempty"`
	Evidence string     `json:"evidence,omitempty"`
	CWEs     []CWECount `json:"cwes"`
	Trend    []Point    `json:"trend"`
}

// CWECount counts findings with one CWE.
type CWECount struct {
	CWE   int `json:"cwe"`
	Count int `json:"count"`
}

// Point is one week of the open and closed trend.
type Point struct {
	Week   string `json:"week"`
	Opened int    `json:"opened"`
	Closed int    `json:"closed"`
}

// Unmapped counts findings no category covers (CMP-003).
type Unmapped struct {
	NoCWE       int        `json:"no_cwe"`
	OutsidePack int        `json:"cwe_outside_pack"`
	TopOutside  []CWECount `json:"top_outside_pack"`
}

// RequirementResult is one PCI DSS evidence view.
type RequirementResult struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Evidence string         `json:"evidence"`
	Metrics  map[string]any `json:"metrics"`
}

// reportTypes are the finding types framework views consider; the rest
// (malware, indicator and rule matches, licences, QA, posture) are counted
// as excluded.
var reportTypes = map[string]bool{"vulnerability": true, "malicious_dependency": true, "code": true, "sast": true, "secret": true, "misconfiguration": true, "integrity": true}

var openStatus = map[string]bool{"open": true, "triaged": true, "in_progress": true, "accepted": true}

func (p Params) withDefaults() Params {
	if p.SBOMMaxAgeDays <= 0 {
		p.SBOMMaxAgeDays = DefaultParams.SBOMMaxAgeDays
	}
	if p.SLACriticalDays <= 0 {
		p.SLACriticalDays = DefaultParams.SLACriticalDays
	}
	if p.SLAHighDays <= 0 {
		p.SLAHighDays = DefaultParams.SLAHighDays
	}
	return p
}

// Build computes a report from its input.
func Build(p Pack, in Input) Report {
	in.Params = in.Params.withDefaults()
	r := Report{
		Meta:      Meta{ID: in.ID, Framework: PackRef{ID: p.ID, Name: p.Name, Version: p.Version, Source: p.Source}, Scope: in.Scope, Since: in.Since, Until: in.Until, DataAsOf: in.DataAsOf, Version: in.Version, Format: in.Format, Params: in.Params},
		Statement: Statement,
		Feeds:     in.Feeds,
		Assets:    in.Assets,
		Gaps:      gaps(in),
		Totals:    Totals{Excluded: map[string]int{}},
	}
	if r.Feeds == nil {
		r.Feeds = []Feed{}
	}
	if r.Assets == nil {
		r.Assets = []Asset{}
	}
	considered := []Finding{}
	for _, f := range in.Findings {
		if !reportTypes[f.Type] {
			r.Totals.Excluded[f.Type]++
			continue
		}
		if f.Status == "suppressed" || f.Status == "false_positive" {
			r.Totals.Dismissed++
			continue
		}
		considered = append(considered, f)
		if openStatus[f.Status] {
			r.Totals.Open++
		}
	}
	r.Totals.Considered = len(considered)
	switch p.Kind {
	case KindCWEMapping:
		r.Categories, r.Unmapped = categories(p, in, considered)
	case KindSTIG:
		r.Categories, r.Unmapped = categories(p, in, considered)
		r.STIG = stigSummary(p, r.Categories)
	case KindPCIDSS:
		r.Requirements = pci(p, in, considered, r.Gaps)
	}
	return r
}

func gaps(in Input) []Gap {
	out := []Gap{}
	cutoff := in.Until.Add(-time.Duration(in.Params.SBOMMaxAgeDays) * 24 * time.Hour)
	for _, a := range in.Assets {
		switch {
		case a.LastSBOM == nil:
			out = append(out, Gap{AssetID: a.ID, Locator: a.Locator, Reason: "no SBOM recorded"})
		case a.LastSBOM.Before(cutoff):
			out = append(out, Gap{AssetID: a.ID, Locator: a.Locator, Reason: "newest SBOM is older than " + itoa(in.Params.SBOMMaxAgeDays) + " days"})
		}
	}
	return out
}

func itoa(n int) string {
	return fmtInt(n)
}

func inWindow(t time.Time, in Input) bool { return !t.Before(in.Since) && !t.After(in.Until) }

func weekOf(t time.Time) string {
	y, w := t.ISOWeek()
	return fmtInt(y) + "-W" + pad2(w)
}

func weeks(in Input) []string {
	out := []string{}
	seen := map[string]bool{}
	for t := in.Since; !t.After(in.Until) && len(out) < 60; t = t.Add(24 * time.Hour) {
		if w := weekOf(t); !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}

func categories(p Pack, in Input, findings []Finding) ([]CategoryResult, *Unmapped) {
	byCWE := map[int][]int{}
	results := make([]CategoryResult, len(p.Categories))
	index := map[string]int{}
	weekList := weeks(in)
	for i, c := range p.Categories {
		results[i] = CategoryResult{ID: c.ID, Name: c.Name, BySeverity: map[string]int{}, CWEs: []CWECount{}, Trend: make([]Point, len(weekList))}
		for j, w := range weekList {
			results[i].Trend[j].Week = w
		}
		index[c.ID] = i
		for _, cwe := range c.CWEs {
			byCWE[cwe] = append(byCWE[cwe], i)
		}
	}
	weekIndex := map[string]int{}
	for i, w := range weekList {
		weekIndex[w] = i
	}
	cweCounts := make([]map[int]int, len(results))
	for i := range cweCounts {
		cweCounts[i] = map[int]int{}
	}
	unmapped := &Unmapped{TopOutside: []CWECount{}}
	outside := map[int]int{}
	for _, f := range findings {
		hit := map[int]bool{}
		viaCWE := map[int]bool{}
		for _, cwe := range f.CWEs {
			for _, i := range byCWE[cwe] {
				hit[i], viaCWE[i] = true, true
				cweCounts[i][cwe]++
			}
		}
		if c, ok := p.TypeCategories[f.Type]; ok {
			if i, ok := index[c]; ok {
				hit[i] = true
			}
		}
		if len(hit) == 0 {
			if len(f.CWEs) == 0 {
				unmapped.NoCWE++
			} else {
				unmapped.OutsidePack++
				for _, cwe := range f.CWEs {
					outside[cwe]++
				}
			}
			continue
		}
		for i := range hit {
			c := &results[i]
			if viaCWE[i] {
				c.MappedByCWE++
			} else {
				c.MappedByType++
			}
			if openStatus[f.Status] {
				c.Open++
				c.BySeverity[f.Severity]++
			}
			if inWindow(f.FirstSeen, in) {
				c.Opened++
				if w, ok := weekIndex[weekOf(f.FirstSeen)]; ok {
					c.Trend[w].Opened++
				}
			}
			if f.ClosedAt != nil && inWindow(*f.ClosedAt, in) {
				c.Closed++
				if w, ok := weekIndex[weekOf(*f.ClosedAt)]; ok {
					c.Trend[w].Closed++
				}
			}
		}
	}
	for i := range results {
		results[i].CWEs = sortedCounts(cweCounts[i], 50)
	}
	unmapped.TopOutside = sortedCounts(outside, 20)
	return results, unmapped
}

func sortedCounts(m map[int]int, limit int) []CWECount {
	out := make([]CWECount, 0, len(m))
	for cwe, n := range m {
		out = append(out, CWECount{CWE: cwe, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].CWE < out[j].CWE
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

var severityOrder = []string{"critical", "high", "medium", "low", "unknown"}

func pci(p Pack, in Input, findings []Finding, gapList []Gap) []RequirementResult {
	out := []RequirementResult{}
	locator := map[uuid.UUID]string{}
	for _, a := range in.Assets {
		locator[a.ID] = a.Locator
	}
	for _, req := range p.Requirements {
		r := RequirementResult{ID: req.ID, Title: req.Title, Evidence: req.Evidence, Metrics: map[string]any{}}
		switch req.ID {
		case "6.3.1":
			bySeverity := map[string]int{}
			kev := 0
			perAsset := map[uuid.UUID]map[string]int{}
			for _, f := range findings {
				if !openStatus[f.Status] {
					continue
				}
				bySeverity[f.Severity]++
				if f.KEV {
					kev++
				}
				if perAsset[f.AssetID] == nil {
					perAsset[f.AssetID] = map[string]int{}
				}
				perAsset[f.AssetID][f.Severity]++
			}
			type row struct {
				AssetID uuid.UUID      `json:"asset_id"`
				Locator string         `json:"locator"`
				Open    map[string]int `json:"open_by_severity"`
			}
			rows := []row{}
			for id, counts := range perAsset {
				rows = append(rows, row{AssetID: id, Locator: locator[id], Open: counts})
			}
			sort.Slice(rows, func(i, j int) bool {
				for _, s := range severityOrder {
					if rows[i].Open[s] != rows[j].Open[s] {
						return rows[i].Open[s] > rows[j].Open[s]
					}
				}
				return rows[i].Locator < rows[j].Locator
			})
			if len(rows) > 100 {
				rows = rows[:100]
			}
			r.Metrics["open_by_severity"] = bySeverity
			r.Metrics["open_known_exploited"] = kev
			r.Metrics["assets_ranked"] = rows
		case "6.3.2":
			with := 0
			for _, a := range in.Assets {
				if a.SBOMs > 0 {
					with++
				}
			}
			r.Metrics["assets_in_scope"] = len(in.Assets)
			r.Metrics["assets_with_sbom_in_window"] = with
			r.Metrics["gaps"] = len(gapList)
			r.Metrics["sbom_max_age_days"] = in.Params.SBOMMaxAgeDays
		case "6.3.3":
			windows := map[string]int{"critical": in.Params.SLACriticalDays, "high": in.Params.SLAHighDays}
			stats := map[string]map[string]int{}
			fixDays := map[string][]int{}
			for _, f := range findings {
				limit, tracked := windows[f.Severity]
				if !tracked || (f.Type != "vulnerability" && f.Type != "malicious_dependency") {
					continue
				}
				if stats[f.Severity] == nil {
					stats[f.Severity] = map[string]int{"open_overdue": 0, "open_within_window": 0, "fixed_within_window": 0, "fixed_late": 0}
				}
				s := stats[f.Severity]
				switch {
				case openStatus[f.Status]:
					if in.Until.Sub(f.FirstSeen) > time.Duration(limit)*24*time.Hour {
						s["open_overdue"]++
					} else {
						s["open_within_window"]++
					}
				case f.ClosedAt != nil && inWindow(*f.ClosedAt, in):
					days := int(f.ClosedAt.Sub(f.FirstSeen).Hours() / 24)
					fixDays[f.Severity] = append(fixDays[f.Severity], days)
					if days <= limit {
						s["fixed_within_window"]++
					} else {
						s["fixed_late"]++
					}
				}
			}
			medians := map[string]int{}
			for severity, list := range fixDays {
				sort.Ints(list)
				medians[severity] = list[len(list)/2]
			}
			r.Metrics["patch_window_days"] = windows
			r.Metrics["by_severity"] = stats
			r.Metrics["median_days_to_fix"] = medians
		}
		out = append(out, r)
	}
	return out
}

// stigSummary sets each rule's evidence and counts them.
func stigSummary(p Pack, results []CategoryResult) *STIGSummary {
	s := &STIGSummary{Rules: len(results), RulesByEvidence: map[string]int{"open_findings": 0, "no_open_findings": 0, "not_evidenced": 0}, OpenByCAT: map[string]int{"CAT I": 0, "CAT II": 0, "CAT III": 0}}
	if p.Benchmark != nil {
		s.Benchmark = *p.Benchmark
	}
	typed := map[string]bool{}
	for _, id := range p.TypeCategories {
		typed[id] = true
	}
	for i, c := range p.Categories {
		r := &results[i]
		r.Severity = c.Severity
		switch {
		case r.Open > 0:
			r.Evidence = "open_findings"
			s.OpenByCAT[c.Severity]++
		case len(c.CWEs) > 0 || typed[c.ID]:
			r.Evidence = "no_open_findings"
		default:
			r.Evidence = "not_evidenced"
		}
		s.RulesByEvidence[r.Evidence]++
	}
	return s
}
