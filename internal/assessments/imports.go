package assessments

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ImportSource records that findings came from an external scanner run (Trivy
// or any SARIF producer such as Semgrep or CodeQL), not from SCRS itself.
type ImportSource struct {
	Format      string `json:"format"`
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
}

var severityScore = map[string]int{"critical": 60, "high": 45, "medium": 25, "low": 10, "unknown": 0}

func normalizeSeverity(v string) string {
	v = strings.ToLower(v)
	if v == "moderate" {
		v = "medium"
	}
	if _, ok := severityScore[v]; !ok {
		return "unknown"
	}
	return v
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ParseReport converts a Trivy JSON or SARIF 2.1.0 report into components and
// findings. Secret values and code snippets are never copied into evidence.
func ParseReport(format string, report []byte) (ImportSource, []Component, []Finding, error) {
	switch format {
	case "trivy":
		return parseTrivy(report)
	case "sarif":
		return parseSARIF(report)
	}
	return ImportSource{}, nil, nil, fmt.Errorf("%w: format must be trivy or sarif", ErrInput)
}

func parseTrivy(report []byte) (ImportSource, []Component, []Finding, error) {
	var r struct {
		SchemaVersion int `json:"SchemaVersion"`
		Trivy         struct {
			Version string `json:"Version"`
		} `json:"Trivy"`
		Results []struct {
			Target   string `json:"Target"`
			Type     string `json:"Type"`
			Packages []struct {
				Name       string `json:"Name"`
				Version    string `json:"Version"`
				Identifier struct {
					PURL string `json:"PURL"`
				} `json:"Identifier"`
			} `json:"Packages"`
			Vulnerabilities []struct {
				ID         string `json:"VulnerabilityID"`
				PkgName    string `json:"PkgName"`
				Installed  string `json:"InstalledVersion"`
				Fixed      string `json:"FixedVersion"`
				Severity   string `json:"Severity"`
				Title      string `json:"Title"`
				PrimaryURL string `json:"PrimaryURL"`
				Identifier struct {
					PURL string `json:"PURL"`
				} `json:"PkgIdentifier"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID         string `json:"ID"`
				Title      string `json:"Title"`
				Message    string `json:"Message"`
				Resolution string `json:"Resolution"`
				Severity   string `json:"Severity"`
				Status     string `json:"Status"`
				PrimaryURL string `json:"PrimaryURL"`
			} `json:"Misconfigurations"`
			Secrets []struct {
				RuleID    string `json:"RuleID"`
				Category  string `json:"Category"`
				Severity  string `json:"Severity"`
				Title     string `json:"Title"`
				StartLine int    `json:"StartLine"`
			} `json:"Secrets"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(report, &r); err != nil || r.SchemaVersion != 2 {
		return ImportSource{}, nil, nil, fmt.Errorf("%w: Trivy JSON with SchemaVersion 2 required", ErrInput)
	}
	src := ImportSource{Format: "trivy", Tool: "trivy", ToolVersion: clip(r.Trivy.Version, 64)}
	var components []Component
	var findings []Finding
	seen := map[string]bool{}
	addComponent := func(c Component) {
		key := c.PURL + "\x00" + c.Path + "\x00" + c.Name + "\x00" + c.Version
		if c.Name != "" && !seen[key] {
			seen[key] = true
			components = append(components, c)
		}
	}
	for _, res := range r.Results {
		target := clip(res.Target, 512)
		for _, p := range res.Packages {
			addComponent(Component{Name: clip(p.Name, 256), Version: clip(p.Version, 128), Ecosystem: res.Type, PURL: clip(p.Identifier.PURL, 512), Path: target})
		}
		for _, v := range res.Vulnerabilities {
			c := Component{Name: clip(v.PkgName, 256), Version: clip(v.Installed, 128), Ecosystem: res.Type, PURL: clip(v.Identifier.PURL, 512), Path: target}
			addComponent(c)
			severity := normalizeSeverity(v.Severity)
			evidence, _ := json.Marshal(map[string]any{"source": "trivy", "installed_version": v.Installed, "fixed_version": v.Fixed, "target": target})
			fixed := []string{}
			if v.Fixed != "" {
				fixed = strings.Split(v.Fixed, ", ")
			}
			guidance, _ := json.Marshal(map[string]any{"summary": "Upgrade to a fixed version reported by Trivy and rerun the scan.", "fixed_versions": fixed, "reference": v.PrimaryURL, "automatic_changes": false})
			findings = append(findings, Finding{Type: "vulnerability", AdvisoryID: clip(v.ID, 128), Title: clip(firstOf(v.Title, v.ID), 512), Severity: severity, Score: severityScore[severity], Component: c, Evidence: evidence, Guidance: guidance})
		}
		for _, m := range res.Misconfigurations {
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}
			severity := normalizeSeverity(m.Severity)
			evidence, _ := json.Marshal(map[string]any{"source": "trivy", "message": clip(m.Message, 512), "target": target})
			guidance, _ := json.Marshal(map[string]any{"summary": clip(firstOf(m.Resolution, "Review the misconfiguration and apply the recommended setting."), 1024), "reference": m.PrimaryURL, "automatic_changes": false})
			findings = append(findings, Finding{Type: "misconfiguration", AdvisoryID: clip(m.ID, 128), Title: clip(m.Title, 512), Severity: severity, Score: severityScore[severity], Component: Component{Path: target}, Evidence: evidence, Guidance: guidance})
		}
		for _, sec := range res.Secrets {
			severity := normalizeSeverity(sec.Severity)
			// The matched secret text is deliberately dropped.
			evidence, _ := json.Marshal(map[string]any{"source": "trivy", "category": sec.Category, "line": sec.StartLine, "target": target})
			guidance := json.RawMessage(`{"summary":"Revoke and rotate the exposed credential, then remove it from history. Rotation matters more than deletion.","automatic_changes":false}`)
			findings = append(findings, Finding{Type: "secret", AdvisoryID: clip(sec.RuleID, 128), Title: clip(sec.Title, 512), Severity: severity, Score: severityScore[severity], Component: Component{Path: target + ":" + strconv.Itoa(sec.StartLine)}, Evidence: evidence, Guidance: guidance})
		}
	}
	return src, components, findings, nil
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseSARIF maps SARIF results to "code" findings. Severity comes from the
// rule's security-severity score when present (the GitHub code scanning
// convention), otherwise from the result level.
func parseSARIF(report []byte) (ImportSource, []Component, []Finding, error) {
	type message struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string  `json:"id"`
		ShortDescription message `json:"shortDescription"`
		Properties       struct {
			SecuritySeverity string `json:"security-severity"`
		} `json:"properties"`
		DefaultConfiguration struct {
			Level string `json:"level"`
		} `json:"defaultConfiguration"`
		HelpURI string `json:"helpUri"`
	}
	var r struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"semanticVersion"`
					Rules   []rule `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string  `json:"ruleId"`
				Level     string  `json:"level"`
				Message   message `json:"message"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(report, &r); err != nil || r.Version != "2.1.0" || len(r.Runs) == 0 {
		return ImportSource{}, nil, nil, fmt.Errorf("%w: SARIF 2.1.0 required", ErrInput)
	}
	src := ImportSource{Format: "sarif", Tool: clip(strings.ToLower(r.Runs[0].Tool.Driver.Name), 64), ToolVersion: clip(r.Runs[0].Tool.Driver.Version, 64)}
	var findings []Finding
	for _, run := range r.Runs {
		rules := map[string]rule{}
		for _, ru := range run.Tool.Driver.Rules {
			rules[ru.ID] = ru
		}
		for _, res := range run.Results {
			ru := rules[res.RuleID]
			severity := sarifSeverity(ru.Properties.SecuritySeverity, firstOf(res.Level, ru.DefaultConfiguration.Level))
			path, line := "", 0
			if len(res.Locations) > 0 {
				path, line = res.Locations[0].Physical.Artifact.URI, res.Locations[0].Physical.Region.StartLine
			}
			path = clip(strings.TrimPrefix(path, "file://"), 512)
			evidence, _ := json.Marshal(map[string]any{"source": "sarif", "tool": run.Tool.Driver.Name, "path": path, "line": line, "message": clip(res.Message.Text, 512)})
			guidance, _ := json.Marshal(map[string]any{"summary": "Review the flagged code against the rule documentation and fix or suppress with justification.", "reference": ru.HelpURI, "automatic_changes": false})
			title := firstOf(ru.ShortDescription.Text, res.Message.Text, res.RuleID)
			findings = append(findings, Finding{Type: "code", AdvisoryID: clip(firstOf(res.RuleID, "unnamed-rule"), 128), Title: clip(title, 512), Severity: severity, Score: severityScore[severity], Component: Component{Path: path + ":" + strconv.Itoa(line)}, Evidence: evidence, Guidance: guidance})
		}
	}
	return src, nil, findings, nil
}

func sarifSeverity(score, level string) string {
	if v, err := strconv.ParseFloat(score, 64); err == nil {
		switch {
		case v >= 9:
			return "critical"
		case v >= 7:
			return "high"
		case v >= 4:
			return "medium"
		default:
			return "low"
		}
	}
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	}
	return "low"
}

// Import records an external scanner report as a completed assessment of an
// in-scope asset revision. Imported findings join the risk register and gate
// like SCRS findings, but an import never closes register entries and never
// serves as a baseline: it did not observe the whole revision.
func (s *Store) Import(ctx context.Context, request Request, actor uuid.UUID, name, key, format string, report []byte) (Assessment, bool, error) {
	src, components, findings, err := ParseReport(format, report)
	if err != nil {
		return Assessment{}, false, err
	}
	if len(components) > 20000 || len(findings) > 10000 {
		return Assessment{}, false, fmt.Errorf("%w: report exceeds 20000 components or 10000 findings", ErrInput)
	}
	if !validRevision(request.Target.Commit) {
		return Assessment{}, false, fmt.Errorf("%w: target.commit (git SHA or image digest) required for imports", ErrInput)
	}
	request.Import = &src
	request.Remediation, request.AutoRemediation = nil, false
	request.Trigger.Origin = "import_" + format
	a, replay, err := s.enqueue(ctx, request, actor, name, key, nil)
	if err != nil || replay {
		return a, replay, err
	}
	detail := "Findings imported from " + src.Tool
	if src.ToolVersion != "" {
		detail += " " + src.ToolVersion
	}
	result := Result{Commit: request.Target.Commit, Components: components, Findings: findings, Complete: true, Stages: []Stage{{Name: "import", Status: "ok", Detail: detail + "; SCRS did not scan this revision"}}}
	if err := s.Complete(ctx, a, result); err != nil {
		failCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = s.Fail(failCtx, a, "import could not be recorded", false)
		cancel()
		return a, false, err
	}
	a, err = s.Get(ctx, a.ID)
	return a, false, err
}
