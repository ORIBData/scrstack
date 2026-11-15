package sast

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Engine runs the enabled analyzers over one workspace.
type Engine struct {
	Analyzers []Analyzer
	Reacher   *Reacher
	// Enabled is the deployment-wide allow-list (SCRS_SAST_ANALYZERS).
	Enabled map[string]bool
}

// DefaultTimeout is the per-analyzer budget (SAST-011).
const DefaultTimeout = 10 * time.Minute

// New builds the engine from the bundled tool paths.
func New(p Paths, feed, proxy string, enabled []string) *Engine {
	e := &Engine{Analyzers: []Analyzer{Gosec{Bin: p.Gosec, Proxy: proxy}, Bandit{Bin: p.Bandit}, &OpenGrep{Bin: p.OpenGrep, RuleDir: p.OpenGrepRules}, &Bearer{Bin: p.Bearer, RuleDir: p.BearerRules}}, Enabled: map[string]bool{}}
	if p.Govulncheck != "" {
		e.Reacher = &Reacher{Bin: p.Govulncheck, GoBin: p.Go, Feed: feed, Proxy: proxy}
	}
	for _, name := range enabled {
		if name = strings.TrimSpace(name); name != "" {
			e.Enabled[name] = true
		}
	}
	return e
}

// Analyze runs every applicable analyzer the request and deployment allow.
// A timeout or failure marks that analyzer's run, never the others'.
func (e *Engine) Analyze(ctx context.Context, root, scratch string, req Request) Response {
	resp := Response{Runs: []Run{}, Findings: []Finding{}, Unsupported: []string{}}
	ws, truncated, err := NewWorkspace(root, req.Excludes)
	if err != nil {
		resp.Runs = append(resp.Runs, Run{Analyzer: "workspace", Status: "failed", Detail: "source walk failed"})
		return resp
	}
	resp.Languages, resp.Truncated = ws.Languages, truncated
	timeout := req.Timeout
	if timeout <= 0 || timeout > time.Hour {
		timeout = DefaultTimeout
	}
	requested := map[string]bool{}
	for _, a := range req.Analyzers {
		requested[a] = true
	}
	custom := ""
	if len(req.CustomRules) > 0 {
		custom = filepath.Join(scratch, "custom-rules")
		_ = os.MkdirAll(custom, 0o700)
		for name, body := range req.CustomRules {
			_ = os.WriteFile(filepath.Join(custom, safeName(name)+".yaml"), []byte(body), 0o600)
		}
	}
	covered := map[string]bool{}
	for _, a := range e.Analyzers {
		m := a.Meta()
		run := Run{Analyzer: m.Name, Version: a.Version(ctx)}
		switch {
		case !e.Enabled[m.Name]:
			run.Status, run.Detail = "skipped", "not enabled in this deployment (SCRS_SAST_ANALYZERS)"
		case len(requested) > 0 && !requested[m.Name]:
			run.Status, run.Detail = "skipped", "not selected for this asset"
		case !a.Applies(ws):
			run.Status, run.Detail = "skipped", "no files in its languages"
		}
		if run.Status != "" {
			resp.Runs = append(resp.Runs, run)
			continue
		}
		for _, l := range m.Languages {
			covered[l] = true
		}
		dir := filepath.Join(scratch, m.Name)
		_ = os.MkdirAll(dir, 0o700)
		started := time.Now()
		actx, cancel := context.WithTimeout(ctx, timeout)
		findings, err := a.Run(actx, ws, Options{Scratch: dir, CustomRules: map[bool]string{true: custom}[m.Name == "opengrep"]})
		cancel()
		run.Seconds = time.Since(started).Seconds()
		var partial *PartialError
		switch {
		case errors.As(err, &partial):
			// Findings are kept; the coverage gap makes the assessment incomplete.
			run.Status, run.Detail = "partial", partial.Detail
		case actx.Err() == context.DeadlineExceeded:
			// A breached budget is skipped, so the verdict is incomplete (SAST-011).
			run.Status, run.Detail = "skipped", fmt.Sprintf("time budget of %s exceeded", timeout)
			findings = nil
		case err != nil:
			run.Status, run.Detail = "failed", err.Error()
			findings = nil
		default:
			run.Status = "ok"
		}
		for i := range findings {
			f := &findings[i]
			f.ToolVersion = run.Version
			ws.locate(f)
			for j := range f.Flow {
				f.Flow[j].Path = cleanPath(ws.Root, f.Flow[j].Path)
				f.Flow[j].ThirdParty = thirdParty(f.Flow[j].Path)
			}
			if ws.Excluded(f.Path) || ruleDisabled(req.DisabledRules, *f) {
				continue
			}
			resp.Findings = append(resp.Findings, *f)
			run.Findings++
		}
		resp.Runs = append(resp.Runs, run)
	}
	if truncated {
		for i := range resp.Runs {
			if resp.Runs[i].Status == "ok" {
				resp.Runs[i].Status, resp.Runs[i].Detail = "partial", fmt.Sprintf("only the first %d files were analysed", MaxFiles)
			}
		}
	}
	for lang := range ws.Languages {
		if !covered[lang] && lang != "html" && lang != "bash" && lang != "c" {
			resp.Unsupported = append(resp.Unsupported, lang)
		}
	}
	sort.Strings(resp.Unsupported)
	correlate(resp.Findings)
	if req.Reachability && e.Reacher != nil {
		dir := filepath.Join(scratch, "govulncheck")
		_ = os.MkdirAll(dir, 0o700)
		rctx, cancel := context.WithTimeout(ctx, timeout)
		resp.Reachability = e.Reacher.Analyze(rctx, ws, dir)
		cancel()
	}
	return resp
}

func safeName(s string) string {
	out := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// Info describes one analyzer for GET /sast/analyzers (SAST-009).
type Info struct {
	Meta
	Version string `json:"version"`
	Rules   int    `json:"rule_count"`
	Enabled bool   `json:"enabled"`
}

// Describe lists the bundled analyzers.
func (e *Engine) Describe(ctx context.Context) ([]Info, *Info) {
	out := []Info{}
	for _, a := range e.Analyzers {
		out = append(out, Info{Meta: a.Meta(), Version: a.Version(ctx), Rules: a.Rules(), Enabled: e.Enabled[a.Meta().Name]})
	}
	var reach *Info
	if e.Reacher != nil {
		reach = &Info{Meta: Meta{Name: "govulncheck", Languages: []string{"go"}, License: "BSD-3-Clause", Redistributable: true, NeedsNetwork: e.Reacher.Proxy != ""}, Version: e.Reacher.Version(ctx), Rules: -1, Enabled: true}
	}
	return out, reach
}
