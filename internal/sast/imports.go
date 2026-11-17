package sast

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Import-level reachability (REA-005): for npm and PyPI, which packages the
// repository's own source imports. It is a fallback for ecosystems without a
// call graph, so it can say "imported" and never "not reachable": a package
// the project does not import itself may still be reached through another
// dependency.

// Imports lists, per ecosystem, the packages the workspace's own source
// imports with the first few places each is imported.
type Imports struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	// Status is ok, partial (some files could not be read) or skipped (no
	// JavaScript, TypeScript or Python source).
	Status string `json:"status"`
	Files  int    `json:"files"`
	// NPM and PyPI map a package name to up to maxImportSteps places.
	NPM  map[string][]Step `json:"npm"`
	PyPI map[string][]Step `json:"pypi"`
}

const (
	maxImportSteps    = 5
	maxImportPackages = 20000
	importsToolName   = "scrs-imports"
)

var (
	jsExt = map[string]bool{".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true, ".vue": true, ".svelte": true}
	// require('x'), import('x'), import x from 'x', import 'x', export ... from 'x'.
	jsImport = regexp.MustCompile(`(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+(?:[\w*\s{},$]+\s+from\s+)?|\bexport\s+(?:[\w*\s{},$]+\s+)?from\s+)['"]([^'"\n]+)['"]`)
	pyImport = regexp.MustCompile(`^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)`)
	pyFrom   = regexp.MustCompile(`^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b`)
	// nodeBuiltins are never packages.
	nodeBuiltins = map[string]bool{"assert": true, "async_hooks": true, "buffer": true, "child_process": true, "cluster": true, "console": true, "crypto": true, "dgram": true, "dns": true, "events": true, "fs": true, "http": true, "http2": true, "https": true, "net": true, "os": true, "path": true, "perf_hooks": true, "process": true, "querystring": true, "readline": true, "stream": true, "string_decoder": true, "timers": true, "tls": true, "url": true, "util": true, "v8": true, "vm": true, "worker_threads": true, "zlib": true}
)

// npmPackage names the package a module specifier refers to: `lodash/fp` is
// lodash, `@scope/pkg/sub` is `@scope/pkg`. Relative paths, absolute paths,
// `node:` built-ins and URLs are not packages.
func npmPackage(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") || strings.Contains(spec, "://") || strings.HasPrefix(spec, "#") || strings.HasPrefix(spec, "~") {
		return "", false
	}
	parts := strings.Split(spec, "/")
	name := parts[0]
	if strings.HasPrefix(name, "@") {
		if len(parts) < 2 || parts[1] == "" {
			return "", false
		}
		name = parts[0] + "/" + parts[1]
	} else if nodeBuiltins[name] {
		return "", false
	}
	if len(name) > 214 || strings.ContainsAny(name, " \t\\") {
		return "", false
	}
	return strings.ToLower(name), true
}

// ScanImports reads the workspace's JavaScript, TypeScript and Python source
// and records what it imports. Dependency and build directories are already
// outside the workspace.
func ScanImports(ws *Workspace) *Imports {
	out := &Imports{Tool: importsToolName, Version: "1", Status: "ok", NPM: map[string][]Step{}, PyPI: map[string][]Step{}}
	add := func(into map[string][]Step, name, file string, line int) {
		steps, known := into[name]
		if !known && len(into) >= maxImportPackages {
			return
		}
		if len(steps) < maxImportSteps {
			into[name] = append(steps, Step{Path: file, Line: line})
		} else if !known {
			into[name] = steps
		}
	}
	for _, rel := range ws.Files {
		ext := strings.ToLower(path.Ext(rel))
		isJS, isPy := jsExt[ext], ext == ".py"
		if !isJS && !isPy {
			continue
		}
		data, err := os.ReadFile(filepath.Join(ws.Root, filepath.FromSlash(rel)))
		if err != nil || len(data) > maxFileSize {
			out.Status = "partial"
			continue
		}
		out.Files++
		for i, line := range strings.Split(string(data), "\n") {
			if len(line) > 2000 {
				continue // minified or generated; not worth scanning
			}
			switch {
			case isJS:
				for _, m := range jsImport.FindAllStringSubmatch(line, -1) {
					if name, ok := npmPackage(m[1]); ok {
						add(out.NPM, name, rel, i+1)
					}
				}
			case isPy:
				if m := pyFrom.FindStringSubmatch(line); m != nil {
					add(out.PyPI, strings.ToLower(strings.SplitN(m[1], ".", 2)[0]), rel, i+1)
				} else if m := pyImport.FindStringSubmatch(line); m != nil {
					for _, item := range strings.Split(m[1], ",") {
						module := strings.Fields(strings.TrimSpace(item))
						if len(module) > 0 {
							add(out.PyPI, strings.ToLower(strings.SplitN(module[0], ".", 2)[0]), rel, i+1)
						}
					}
				}
			}
		}
	}
	if out.Files == 0 {
		out.Status = "skipped"
	}
	return out
}

// pypiImportNames maps a PyPI distribution (normalised) to the top-level
// module names it installs, for the common cases where they differ.
var pypiImportNames = map[string][]string{
	"beautifulsoup4": {"bs4"}, "pyyaml": {"yaml"}, "pillow": {"pil"}, "scikit-learn": {"sklearn"}, "opencv-python": {"cv2"},
	"opencv-python-headless": {"cv2"}, "python-dateutil": {"dateutil"}, "pycryptodome": {"crypto"}, "pycryptodomex": {"cryptodome"},
	"protobuf": {"google"}, "attrs": {"attr", "attrs"}, "python-dotenv": {"dotenv"}, "pyjwt": {"jwt"}, "msgpack-python": {"msgpack"},
	"setuptools": {"setuptools", "pkg_resources"}, "scikit-image": {"skimage"}, "pymysql": {"pymysql"}, "psycopg2-binary": {"psycopg2"},
	"mysqlclient": {"mysqldb"}, "python-jose": {"jose"}, "python-multipart": {"multipart"}, "ruamel.yaml": {"ruamel"}, "pyopenssl": {"openssl"},
	"typing-extensions": {"typing_extensions"}, "google-api-python-client": {"googleapiclient"}, "slackclient": {"slack"}, "pytest": {"pytest", "_pytest"},
}

// PyPIModules lists the top-level module names a PyPI distribution may be
// imported as: its own name with `-`, `.` folded to `_`, and the known
// differing names.
func PyPIModules(distribution string) []string {
	norm := strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(distribution))
	names := map[string]bool{strings.ReplaceAll(norm, "-", "_"): true}
	for _, n := range pypiImportNames[norm] {
		names[strings.ToLower(n)] = true
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ImportedSteps returns where the repository imports a package, empty when it
// does not. For PyPI it tries every module name the distribution may use.
func (i *Imports) ImportedSteps(ecosystem, name string) []Step {
	if i == nil || i.Status == "skipped" {
		return nil
	}
	base := strings.ToLower(strings.SplitN(ecosystem, ":", 2)[0])
	switch base {
	case "npm":
		return i.NPM[strings.ToLower(name)]
	case "pypi":
		for _, module := range PyPIModules(name) {
			if steps := i.PyPI[module]; len(steps) > 0 {
				return steps
			}
		}
	}
	return nil
}
