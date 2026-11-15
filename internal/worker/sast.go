package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/sast"
	"github.com/ORIBData/scrstack/internal/scanner"
)

// Reachability score weights (REA-004); KEV entries keep a high score.
const (
	DefaultReachableWeight    = 10
	DefaultNotReachableWeight = -15
)

// analyzeSource sends the repository archive to scrs-sast when SAST or
// reachability applies to the asset, adds SAST entries and sets the
// reachability of vulnerability entries (M9).
func (w Worker) analyzeSource(ctx context.Context, a *assessments.Assessment, archive []byte, output *scanner.Output, result *assessments.Result) ([]assessments.Stage, error) {
	if w.SAST == nil {
		return nil, nil
	}
	settings, err := w.Store.EffectiveSASTSettings(ctx, a.AssetID, w.SASTDefaults)
	if err != nil || (!settings.Enabled && !settings.Reachability) {
		return nil, nil
	}
	req := sast.Request{Analyzers: settings.Analyzers, DisabledRules: settings.DisabledRules, Excludes: settings.Excludes, CustomRules: settings.CustomRules, Reachability: settings.Reachability, Timeout: w.SASTTimeout}
	if !settings.Enabled {
		// Reachability only: no analyzer is selected.
		req.Analyzers, req.CustomRules = []string{"none"}, nil
	}
	// Analyzer budgets outlast the assessment lease: renew it meanwhile.
	renewCtx, stopRenew := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				_ = w.Store.RenewLease(renewCtx, *a)
			}
		}
	}()
	// A busy service serves another assessment: wait for a slot for up to
	// three minutes, then requeue the job without spending an attempt.
	var resp sast.Response
	for wait := time.Now().Add(3 * time.Minute); ; {
		resp, err = w.SAST.Analyze(ctx, archive, req)
		if !errors.Is(err, sast.ErrBusy) || time.Now().After(wait) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		if ctx.Err() != nil {
			break
		}
	}
	stopRenew()
	if errors.Is(err, sast.ErrBusy) {
		return nil, errScannerBusy
	}
	stages := []assessments.Stage{}
	if err != nil {
		if settings.Enabled {
			stages = append(stages, assessments.Stage{Name: "sast", Status: "failed", Detail: err.Error()})
		}
		if settings.Reachability {
			applyReachability(output.Findings, &sast.Reachability{Status: "failed", Detail: err.Error()}, w.weights())
			stages = append(stages, assessments.Stage{Name: "reachability", Status: "failed", Detail: "analysis unavailable; vulnerability entries are unknown"})
		}
		return stages, nil
	}
	if settings.Enabled {
		added := 0
		for _, f := range resp.Findings {
			if len(output.Findings) >= 10000 {
				break
			}
			output.Findings = append(output.Findings, sastFinding(f))
			added++
		}
		stages = append(stages, sastStage(resp, added))
		result.SASTDisabledRules, result.SASTExcludes = settings.DisabledRules, settings.Excludes
		for _, run := range resp.Runs {
			if run.Status == "ok" {
				result.SASTTools = append(result.SASTTools, run.Analyzer)
			}
		}
	}
	if settings.Reachability {
		r := resp.Reachability
		if r == nil {
			r = &sast.Reachability{Status: "failed", Detail: "no reachability result"}
		}
		counts := applyReachability(output.Findings, r, w.weights())
		status := r.Status
		if status == "skipped" {
			status = "ok"
		}
		stages = append(stages, assessments.Stage{Name: "reachability", Status: status, Detail: fmt.Sprintf("%s %s: reachable %d, imported only %d, not reachable %d, unknown %d, unsupported %d", r.Tool, r.Version, counts[sast.Reachable], counts[sast.ImportedOnly], counts[sast.NotReachable], counts[sast.Unknown], counts[sast.Unsupported])})
	}
	return stages, nil
}

// sastDeadline bounds a repository job with SAST: the scan, every analyzer
// at its budget, reachability, and enrichment, within one hour.
func sastDeadline(budget time.Duration) time.Duration {
	if budget <= 0 {
		budget = sast.DefaultTimeout
	}
	return min(5*time.Minute+5*budget+2*time.Minute, time.Hour)
}

func (w Worker) weights() [2]int {
	reach, not := DefaultReachableWeight, DefaultNotReachableWeight
	if w.ReachabilityWeights != nil {
		reach, not = w.ReachabilityWeights[0], w.ReachabilityWeights[1]
	}
	return [2]int{reach, not}
}

// sastStage summarises the analyzer runs. Analyzers skipped because they
// do not apply are fine; a failure or a breached budget is not.
func sastStage(resp sast.Response, added int) assessments.Stage {
	status := "ok"
	parts := []string{}
	for _, r := range resp.Runs {
		if r.Status == "skipped" && !strings.Contains(r.Detail, "budget") {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s %s (%d)", r.Analyzer, r.Version, r.Status, r.Findings))
		switch r.Status {
		case "failed":
			status = "failed"
		case "skipped", "partial":
			if status == "ok" {
				status = "partial"
			}
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no files in a supported language")
	}
	detail := strings.Join(parts, "; ") + fmt.Sprintf("; %d entries", added)
	if len(resp.Unsupported) > 0 {
		detail += "; no analyzer for " + strings.Join(resp.Unsupported, ", ")
	}
	return assessments.Stage{Name: "sast", Status: status, Detail: detail}
}

var sastScore = map[string]int{"critical": 60, "high": 45, "medium": 25, "low": 10, "info": 0}

// sastFinding maps an analyzer result to a register entry (SAST-005). The
// path carries the code hash so line shifts keep one entry; no code
// snippet is stored.
func sastFinding(f sast.Finding) assessments.Finding {
	advisory := f.Tool + ":" + f.RuleID
	if len(advisory) > 128 {
		advisory = advisory[:128]
	}
	title := f.Title
	if title == "" {
		title = f.Message
	}
	if len(title) > 512 {
		title = title[:512]
	}
	message := f.Message
	if len(message) > 1024 {
		message = message[:1024]
	}
	evidence, _ := json.Marshal(map[string]any{
		"source": "scrs-sast", "tool": f.Tool, "tool_version": f.ToolVersion, "rule_id": f.RuleID, "cwe": f.CWE,
		"confidence": f.Confidence, "path": f.Path, "start_line": f.StartLine, "end_line": f.EndLine, "message": message,
		"code_hash": f.CodeHash, "suppressed_in_code": f.SuppressedInCode, "suppression": f.Suppression,
		"flow": f.Flow, "also_reported_by": f.AlsoReportedBy,
	})
	guidance, _ := json.Marshal(map[string]any{"summary": "Review the flagged code against the rule documentation; fix it, or suppress it inline with a justification (inline suppressions are recorded).", "reference": f.Help, "automatic_changes": false})
	severity := f.Severity
	if _, ok := sastScore[severity]; !ok {
		severity = "info"
	}
	return assessments.Finding{Type: "sast", AdvisoryID: advisory, Title: title, Severity: severity, Score: sastScore[severity], Component: assessments.Component{Path: f.Path + "#" + f.CodeHash[:min(16, len(f.CodeHash))]}, Evidence: evidence, Guidance: guidance}
}

var goAdvisory = regexp.MustCompile(`^GO-\d{4}-\d+$`)

// applyReachability sets evidence.reachability on every vulnerability
// entry (REA-001) and moves its score (REA-004). Go entries take the
// govulncheck verdict for their advisory and module; a Go entry without a
// verdict, or from a failed analysis, is unknown; other ecosystems are
// unsupported. Nothing is closed because it is unreachable.
func applyReachability(findings []assessments.Finding, r *sast.Reachability, weights [2]int) map[string]int {
	counts := map[string]int{}
	verdicts := map[string]sast.Verdict{}
	for _, v := range r.Verdicts {
		verdicts[v.Advisory+"\x00"+v.Module] = v
	}
	analysed := r.Status == "ok" || r.Status == "partial"
	for i := range findings {
		f := &findings[i]
		if f.Type != "vulnerability" {
			continue
		}
		result := map[string]any{"tool": r.Tool, "version": r.Version}
		status, method := sast.Unsupported, "none"
		var trace []sast.Step
		if strings.HasPrefix(f.Component.Ecosystem, "Go") {
			status = sast.Unknown
			if f.Component.Name == "stdlib" || f.Component.Name == "toolchain" {
				result["detail"] = "standard library: analysed against the scanner's toolchain, not the repository's Go version"
			} else if analysed {
				for _, id := range advisoryIDs(*f) {
					if v, ok := verdicts[id+"\x00"+f.Component.Name]; ok {
						status, method, trace = v.Status, v.Method, v.Trace
						break
					}
				}
			} else {
				result["detail"] = r.Detail
			}
		}
		result["status"], result["method"] = status, method
		if len(trace) > 0 {
			result["trace"] = trace
		}
		result["confidence"] = map[string]string{sast.Reachable: "high", sast.NotReachable: "medium", sast.ImportedOnly: "medium"}[status]
		counts[status]++
		var evidence map[string]any
		if json.Unmarshal(f.Evidence, &evidence) != nil || evidence == nil {
			evidence = map[string]any{}
		}
		evidence["reachability"] = result
		if raw, err := json.Marshal(evidence); err == nil {
			f.Evidence = raw
		}
		switch status {
		case sast.Reachable:
			f.Score += weights[0]
		case sast.NotReachable:
			f.Score += weights[1]
		}
		var guidance struct {
			KEV bool `json:"kev"`
		}
		_ = json.Unmarshal(f.Guidance, &guidance)
		if guidance.KEV {
			f.Score = max(f.Score, 45)
		}
		f.Score = min(max(f.Score, 0), 100)
	}
	return counts
}

// advisoryIDs are the entry's advisory id and its Go aliases.
func advisoryIDs(f assessments.Finding) []string {
	ids := []string{f.AdvisoryID}
	var g struct {
		Aliases []string `json:"aliases"`
	}
	_ = json.Unmarshal(f.Guidance, &g)
	var e struct {
		Aliases []string `json:"aliases"`
	}
	_ = json.Unmarshal(f.Evidence, &e)
	for _, a := range append(g.Aliases, e.Aliases...) {
		if goAdvisory.MatchString(a) {
			ids = append(ids, a)
		}
	}
	return ids
}
