package sast

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var cweText = regexp.MustCompile(`(?i)\bcwe[-_/:\s]?0*([1-9][0-9]{0,4})\b`)

// cwes extracts distinct "CWE-<n>" ids from labels and tags.
func cwes(texts ...string) []string {
	out := []string{}
	for _, t := range texts {
		for _, m := range cweText.FindAllStringSubmatch(t, -1) {
			id := "CWE-" + m[1]
			if !contains(out, id) && len(out) < 10 {
				out = append(out, id)
			}
		}
	}
	return out
}

func severity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "moderate", "warning":
		return "medium"
	case "low", "note":
		return "low"
	}
	return "info"
}

// ParseGosec reads gosec JSON (-fmt=json). Packages gosec could not load
// (type errors, missing modules, cgo) are returned as a coverage gap.
func ParseGosec(data []byte) ([]Finding, error) {
	var out struct {
		Errors map[string][]struct {
			Error string `json:"error"`
		} `json:"Golang errors"`
		Issues []struct {
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			CWE        struct {
				ID string `json:"id"`
			} `json:"cwe"`
			RuleID  string `json:"rule_id"`
			Details string `json:"details"`
			File    string `json:"file"`
			Line    string `json:"line"`
		} `json:"Issues"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("invalid gosec output")
	}
	findings := []Finding{}
	for _, i := range out.Issues {
		start, end := lineRange(i.Line)
		f := Finding{Tool: "gosec", RuleID: i.RuleID, Title: i.Details, Message: i.Details, Severity: severity(i.Severity), Confidence: strings.ToLower(i.Confidence), Path: i.File, StartLine: start, EndLine: end, CWE: []string{}, Help: "https://securego.io/docs/rules/" + strings.ToLower(i.RuleID)}
		if i.CWE.ID != "" {
			f.CWE = []string{"CWE-" + i.CWE.ID}
		}
		findings = append(findings, f)
	}
	if len(out.Errors) > 0 {
		dirs := make([]string, 0, len(out.Errors))
		for dir := range out.Errors {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		detail := "load error"
		if errs := out.Errors[dirs[0]]; len(errs) > 0 {
			detail = firstLine(errs[0].Error)
		}
		return findings, &PartialError{Detail: fmt.Sprintf("%d Go package(s) could not be loaded, for example %s: %s", len(dirs), dirs[0], detail)}
	}
	return findings, nil
}

// PartialError reports findings from an analyzer that covered only part of
// the workspace; the run is "partial", so the assessment is incomplete.
type PartialError struct{ Detail string }

func (e *PartialError) Error() string { return e.Detail }

// lineRange parses "13" or "13-15".
func lineRange(s string) (int, int) {
	a, b, ranged := strings.Cut(s, "-")
	start, _ := strconv.Atoi(strings.TrimSpace(a))
	end := start
	if ranged {
		end, _ = strconv.Atoi(strings.TrimSpace(b))
	}
	return start, end
}

// ParseBandit reads Bandit JSON (-f json).
func ParseBandit(data []byte) ([]Finding, error) {
	var out struct {
		Results []struct {
			Filename   string `json:"filename"`
			TestID     string `json:"test_id"`
			TestName   string `json:"test_name"`
			IssueText  string `json:"issue_text"`
			Severity   string `json:"issue_severity"`
			Confidence string `json:"issue_confidence"`
			CWE        struct {
				ID int `json:"id"`
			} `json:"issue_cwe"`
			Line      int    `json:"line_number"`
			LineRange []int  `json:"line_range"`
			MoreInfo  string `json:"more_info"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("invalid Bandit output")
	}
	findings := []Finding{}
	for _, r := range out.Results {
		f := Finding{Tool: "bandit", RuleID: r.TestID, Title: r.TestName, Message: r.IssueText, Severity: severity(r.Severity), Confidence: strings.ToLower(r.Confidence), Path: r.Filename, StartLine: r.Line, EndLine: r.Line, CWE: []string{}, Help: r.MoreInfo}
		if n := len(r.LineRange); n > 0 {
			f.EndLine = r.LineRange[n-1]
		}
		if r.CWE.ID > 0 {
			f.CWE = []string{"CWE-" + strconv.Itoa(r.CWE.ID)}
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// RuleMeta supplements SARIF rules (Bearer keeps CWEs and severity in its
// rule files, not in SARIF).
type RuleMeta struct {
	Severity string
	CWE      []string
}

// ParseSARIF reads a SARIF 2.1.0 run (OpenGrep, Bearer), with data-flow
// steps from codeFlows (SAST-008).
func ParseSARIF(tool string, data []byte, extra map[string]RuleMeta) ([]Finding, error) {
	type location struct {
		Physical struct {
			Artifact struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						HelpURI              string `json:"helpUri"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Properties struct {
							Tags             []string `json:"tags"`
							Precision        string   `json:"precision"`
							SecuritySeverity string   `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []location `json:"locations"`
				CodeFlows []struct {
					ThreadFlows []struct {
						Locations []struct {
							Location location `json:"location"`
						} `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != "2.1.0" {
		return nil, errors.New("invalid " + tool + " SARIF output")
	}
	findings := []Finding{}
	for _, run := range doc.Runs {
		type ruleInfo struct {
			title, help, level, confidence string
			cwe                            []string
		}
		rules := map[string]ruleInfo{}
		for _, r := range run.Tool.Driver.Rules {
			info := ruleInfo{title: r.ShortDescription.Text, help: r.HelpURI, level: r.DefaultConfiguration.Level, cwe: cwes(r.Properties.Tags...)}
			for _, tag := range r.Properties.Tags {
				if c, ok := strings.CutSuffix(strings.ToUpper(tag), " CONFIDENCE"); ok {
					info.confidence = strings.ToLower(c)
				}
			}
			rules[r.ID] = info
		}
		for _, res := range run.Results {
			if len(res.Locations) == 0 {
				continue
			}
			info := rules[res.RuleID]
			loc := res.Locations[0].Physical
			f := Finding{Tool: tool, RuleID: res.RuleID, Title: info.title, Message: res.Message.Text, Confidence: info.confidence, CWE: info.cwe, Help: info.help, Path: loc.Artifact.URI, StartLine: loc.Region.StartLine, EndLine: loc.Region.EndLine}
			level := res.Level
			if level == "" {
				level = info.level
			}
			f.Severity = severity(level)
			if m, ok := extra[res.RuleID]; ok {
				if m.Severity != "" {
					f.Severity = severity(m.Severity)
				}
				if len(m.CWE) > 0 {
					f.CWE = m.CWE
				}
			}
			if f.Title == "" {
				f.Title = firstLine(res.Message.Text)
			}
			if len(res.CodeFlows) > 0 && len(res.CodeFlows[0].ThreadFlows) > 0 {
				for _, step := range res.CodeFlows[0].ThreadFlows[0].Locations {
					p := step.Location.Physical
					if p.Artifact.URI == "" || len(f.Flow) >= 50 {
						continue
					}
					f.Flow = append(f.Flow, Step{Path: p.Artifact.URI, Line: p.Region.StartLine})
				}
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

var (
	bearerID       = regexp.MustCompile(`(?m)^\s*id:\s*"?([A-Za-z0-9_.-]+)"?\s*$`)
	bearerSeverity = regexp.MustCompile(`(?m)^severity:\s*"?([a-z]+)"?\s*$`)
	bearerCWE      = regexp.MustCompile(`(?m)^\s*cwe_id:\s*\n((?:\s*-\s*"?[0-9]+"?\s*\n?)+)`)
	digits         = regexp.MustCompile(`[0-9]+`)
)

// BearerRules reads severity and CWE ids from Bearer's rule files.
func BearerRules(dir string) map[string]RuleMeta {
	out := map[string]RuleMeta{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yml") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || len(data) > 1<<20 {
			return nil
		}
		ids := bearerID.FindAllSubmatch(data, -1)
		if len(ids) == 0 {
			return nil
		}
		// The metadata id is the last id in the file.
		id := string(ids[len(ids)-1][1])
		meta := RuleMeta{}
		if m := bearerSeverity.FindSubmatch(data); m != nil {
			meta.Severity = string(m[1])
		}
		if m := bearerCWE.FindSubmatch(data); m != nil {
			for _, n := range digits.FindAll(m[1], -1) {
				meta.CWE = append(meta.CWE, "CWE-"+string(n))
			}
		}
		out[id] = meta
		return nil
	})
	return out
}
