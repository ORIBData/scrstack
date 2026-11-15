package sast

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reachability statuses (REA-001). A failed, skipped or unsupported
// analysis is never not_reachable (REA-003).
const (
	Reachable    = "reachable"
	NotReachable = "not_reachable"
	ImportedOnly = "imported_only"
	Unknown      = "unknown"
	Unsupported  = "unsupported"
)

// Verdict is the reachability of one advisory in one Go module.
type Verdict struct {
	Advisory string `json:"advisory"`
	Module   string `json:"module"`
	Status   string `json:"status"`
	Method   string `json:"method"`
	// Trace is the call path from the project's code to the vulnerable
	// symbol, file and line only.
	Trace []Step `json:"trace,omitempty"`
}

// Reachability is the Go call-graph result of one workspace (REA-002).
type Reachability struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Status   string    `json:"status"`
	Detail   string    `json:"detail,omitempty"`
	Modules  []string  `json:"modules"`
	Verdicts []Verdict `json:"verdicts"`
	// Failed lists module directories whose analysis did not finish; their
	// advisories are unknown.
	Failed []string `json:"failed,omitempty"`
}

// Reacher runs govulncheck against a vulnerability database built from
// the OSV Go feed that scrs-feed-sync keeps. Module sources come through
// the allow-listed egress proxy (proxy.golang.org, sum.golang.org); build,
// generate and cgo steps never run.
type Reacher struct {
	Bin, GoBin string
	// Feed is the feed snapshot root (osv-scalibr/Go/all.zip inside).
	Feed string
	// Proxy is the HTTPS proxy URL for module downloads; empty means only
	// vendored or cached modules can be analysed.
	Proxy string
	mu    sync.Mutex
	dbs   map[string]string
}

// database writes (once per feed snapshot) the govulncheck file database:
// index/db.json, index/modules.json, index/vulns.json and ID/<id>.json.
func (r *Reacher) database(scratchRoot string) (string, error) {
	archive := filepath.Join(r.Feed, "osv-scalibr", "Go", "all.zip")
	info, err := os.Stat(archive)
	if err != nil {
		return "", errors.New("Go advisory feed not synced")
	}
	key := info.ModTime().UTC().Format("20060102T150405") + "-" + strconv.FormatInt(info.Size(), 10)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dbs == nil {
		r.dbs = map[string]string{}
	}
	if dir, ok := r.dbs[key]; ok {
		if _, err := os.Stat(filepath.Join(dir, "index", "db.json")); err == nil {
			return dir, nil
		}
	}
	dir := filepath.Join(scratchRoot, "vulndb-"+key)
	if err := writeVulnDB(archive, dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	r.dbs[key] = dir
	return dir, nil
}

func writeVulnDB(archive, dir string) error {
	z, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer z.Close()
	if err := os.MkdirAll(filepath.Join(dir, "ID"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "index"), 0o700); err != nil {
		return err
	}
	type moduleVuln struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
		Fixed    string    `json:"fixed,omitempty"`
	}
	type vulnMeta struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
		Aliases  []string  `json:"aliases,omitempty"`
	}
	modules := map[string][]moduleVuln{}
	vulns := []vulnMeta{}
	latest := time.Time{}
	for _, f := range z.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 2<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(rc, 2<<20))
		rc.Close()
		if err != nil {
			return err
		}
		var rec struct {
			ID       string    `json:"id"`
			Modified time.Time `json:"modified"`
			Aliases  []string  `json:"aliases"`
			Affected []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Ranges []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		}
		if json.Unmarshal(data, &rec) != nil || rec.ID == "" || strings.ContainsAny(rec.ID, "/\\") {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "ID", rec.ID+".json"), data, 0o600); err != nil {
			return err
		}
		vulns = append(vulns, vulnMeta{ID: rec.ID, Modified: rec.Modified, Aliases: rec.Aliases})
		if rec.Modified.After(latest) {
			latest = rec.Modified
		}
		for _, a := range rec.Affected {
			if a.Package.Ecosystem != "Go" || a.Package.Name == "" {
				continue
			}
			fixed := ""
			for _, rg := range a.Ranges {
				for _, e := range rg.Events {
					if e.Fixed != "" {
						fixed = e.Fixed
					}
				}
			}
			modules[a.Package.Name] = append(modules[a.Package.Name], moduleVuln{ID: rec.ID, Modified: rec.Modified, Fixed: fixed})
		}
	}
	type moduleMeta struct {
		Path  string       `json:"path"`
		Vulns []moduleVuln `json:"vulns"`
	}
	list := make([]moduleMeta, 0, len(modules))
	for path, v := range modules {
		list = append(list, moduleMeta{Path: path, Vulns: v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	write := func(name string, v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "index", name), raw, 0o600)
	}
	if err := write("modules.json", list); err != nil {
		return err
	}
	if err := write("vulns.json", vulns); err != nil {
		return err
	}
	return write("db.json", map[string]time.Time{"modified": latest})
}

// Analyze classifies every advisory govulncheck knows for each Go module
// in the workspace (up to ten modules).
func (r *Reacher) Analyze(ctx context.Context, ws *Workspace, scratch string) *Reachability {
	out := &Reachability{Tool: "govulncheck", Version: r.Version(ctx), Status: "ok", Modules: []string{}, Verdicts: []Verdict{}}
	modules := moduleDirs(ws, "go.mod", 10)
	if len(modules) == 0 {
		out.Status, out.Detail = "skipped", "no Go modules"
		return out
	}
	db, err := r.database(filepath.Dir(scratch))
	if err != nil {
		out.Status, out.Detail, out.Failed = "failed", err.Error(), modules
		return out
	}
	env := isolatedEnv(scratch)
	if r.Proxy != "" {
		// Only module downloads leave the sandbox, through the egress proxy.
		env = append(env, "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org", "HTTPS_PROXY="+r.Proxy, "https_proxy="+r.Proxy, "NO_PROXY=", "GOFLAGS=-mod=mod")
	}
	for _, dir := range modules {
		out.Modules = append(out.Modules, dir)
		data, stderr, err := execute(ctx, filepath.Join(ws.Root, dir), env, []int{0, 3}, r.Bin, "-format", "json", "-db", "file://"+db, "./...")
		if err != nil {
			out.Failed = append(out.Failed, dir)
			out.Detail = firstLine(string(stderr))
			continue
		}
		verdicts, err := ParseGovulncheck(data, dir)
		if err != nil {
			out.Failed = append(out.Failed, dir)
			continue
		}
		out.Verdicts = append(out.Verdicts, verdicts...)
	}
	if len(out.Failed) > 0 {
		out.Status = "partial"
		if len(out.Failed) == len(modules) {
			out.Status = "failed"
		}
	}
	return out
}

// Version is the govulncheck version.
func (r *Reacher) Version(ctx context.Context) string {
	out, _, err := execute(ctx, os.TempDir(), isolatedEnv(os.TempDir()), []int{0}, r.Bin, "-version")
	if err != nil {
		return "unavailable"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Scanner: govulncheck@"); ok {
			return v
		}
	}
	return "unknown"
}

// ParseGovulncheck reads govulncheck's JSON message stream. A trace that
// ends in a function is reachable; one that ends in a package is imported
// only; a module-level finding means the vulnerable code is not imported.
// Standard-library findings are left out: they describe the analyzer's
// own toolchain, not the repository.
func ParseGovulncheck(data []byte, moduleDir string) ([]Verdict, error) {
	type frame struct {
		Module   string `json:"module"`
		Package  string `json:"package"`
		Function string `json:"function"`
		Position *struct {
			Filename string `json:"filename"`
			Line     int    `json:"line"`
		} `json:"position"`
	}
	var message struct {
		Config *struct {
			Mode string `json:"scan_mode"`
		} `json:"config"`
		Finding *struct {
			OSV   string  `json:"osv"`
			Trace []frame `json:"trace"`
		} `json:"finding"`
	}
	rank := map[string]int{NotReachable: 1, ImportedOnly: 2, Reachable: 3}
	best := map[string]Verdict{}
	order := []string{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	sawConfig := false
	for {
		message.Config, message.Finding = nil, nil
		if err := decoder.Decode(&message); err == io.EOF {
			break
		} else if err != nil {
			return nil, errors.New("invalid govulncheck output")
		}
		if message.Config != nil {
			sawConfig = true
		}
		f := message.Finding
		if f == nil || len(f.Trace) == 0 {
			continue
		}
		vuln := f.Trace[0]
		if vuln.Module == "stdlib" || vuln.Module == "toolchain" {
			continue
		}
		v := Verdict{Advisory: f.OSV, Module: vuln.Module, Method: "call_graph", Status: NotReachable}
		switch {
		case vuln.Function != "":
			v.Status = Reachable
			// Frames run from the vulnerable symbol back to the caller.
			main := ""
			if last := f.Trace[len(f.Trace)-1]; last.Module != "" {
				main = last.Module
			}
			for _, fr := range f.Trace {
				if fr.Position == nil {
					continue
				}
				step := Step{Path: fr.Position.Filename, Line: fr.Position.Line, ThirdParty: fr.Module != main}
				if !step.ThirdParty {
					step.Path = filepath.ToSlash(filepath.Join(moduleDir, fr.Position.Filename))
				}
				v.Trace = append(v.Trace, step)
			}
		case vuln.Package != "":
			v.Status, v.Method = ImportedOnly, "import_graph"
		}
		key := f.OSV + "\x00" + vuln.Module
		prev, ok := best[key]
		if !ok {
			order = append(order, key)
		}
		if !ok || rank[v.Status] > rank[prev.Status] {
			best[key] = v
		}
	}
	if !sawConfig {
		return nil, errors.New("govulncheck output has no config message")
	}
	out := make([]Verdict, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out, nil
}
