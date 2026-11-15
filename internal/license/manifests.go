package license

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/textproto"
	"strings"
)

// Declared licence parsers (LIC-001, source "declared"). Each returns the
// declared text as found and its normalised expression.

// Package is a declared licence for one package.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
	// Declared is the text as found; License its normalised form.
	Declared string
	License  Normalized
	// Source is the package's source name where it differs (Debian
	// binary packages, Alpine subpackages).
	Source string
}

// Any normalises each alternative separately and joins them with OR, so
// text such as "GNU Library or Lesser General Public License" is never
// split inside one item.
func Any(items ...string) Normalized { return combine("OR", items) }

// All normalises each item separately and joins them with AND.
func All(items ...string) Normalized { return combine("AND", items) }

func combine(op string, items []string) Normalized {
	out := Normalized{Exact: true}
	var n *Node
	seen := map[string]bool{}
	for _, item := range items {
		part := Normalize(item)
		out.Exact = out.Exact && part.Exact
		for ref, text := range part.Refs {
			if out.Refs == nil {
				out.Refs = map[string]string{}
			}
			out.Refs[ref] = text
		}
		if part.Expression == NoAssertion || seen[part.Expression] {
			continue
		}
		seen[part.Expression] = true
		next, err := Parse(part.Expression)
		if err != nil {
			continue
		}
		if n == nil {
			n = next
		} else {
			n = &Node{Op: op, Left: n, Right: next}
		}
	}
	out.Expression = n.String()
	if n == nil {
		out.Exact = false
	}
	return out
}

// npmLicense reads package.json "license" (string or {type}) or the
// legacy "licenses" array, whose entries are alternatives.
func npmLicense(license json.RawMessage, list []json.RawMessage) (string, Normalized) {
	var s string
	if json.Unmarshal(license, &s) == nil && s != "" {
		return s, Normalize(s)
	}
	var typed struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(license, &typed) == nil && typed.Type != "" {
		return typed.Type, Normalize(typed.Type)
	}
	parts := []string{}
	for _, raw := range list {
		if json.Unmarshal(raw, &s) == nil && s != "" {
			parts = append(parts, s)
		} else if json.Unmarshal(raw, &typed) == nil && typed.Type != "" {
			parts = append(parts, typed.Type)
		}
	}
	return strings.Join(parts, " OR "), Any(parts...)
}

// NPMPackageJSON reads an installed package's package.json.
func NPMPackageJSON(data []byte) (Package, bool) {
	var p struct {
		Name     string            `json:"name"`
		Version  string            `json:"version"`
		License  json.RawMessage   `json:"license"`
		Licenses []json.RawMessage `json:"licenses"`
	}
	if json.Unmarshal(data, &p) != nil || p.Name == "" {
		return Package{}, false
	}
	declared, normalized := npmLicense(p.License, p.Licenses)
	return Package{Ecosystem: "npm", Name: p.Name, Version: p.Version, Declared: declared, License: normalized}, declared != ""
}

// NPMLock reads the "license" fields npm 7+ writes into package-lock.json
// (lockfileVersion 2 and 3).
func NPMLock(data []byte) []Package {
	var lock struct {
		Packages map[string]struct {
			Name     string            `json:"name"`
			Version  string            `json:"version"`
			License  json.RawMessage   `json:"license"`
			Licenses []json.RawMessage `json:"licenses"`
			Link     bool              `json:"link"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	out := []Package{}
	for key, p := range lock.Packages {
		if key == "" || p.Link {
			continue
		}
		name := p.Name
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			name = key[i+len("node_modules/"):]
		}
		declared, normalized := npmLicense(p.License, p.Licenses)
		if name != "" && declared != "" {
			out = append(out, Package{Ecosystem: "npm", Name: name, Version: p.Version, Declared: declared, License: normalized})
		}
	}
	return out
}

// PythonMetadata reads a wheel's or installed distribution's METADATA:
// License-Expression (PEP 639), then License classifiers, then a short
// License field. A long License field is licence text, left to detection.
func PythonMetadata(data []byte) (Package, bool) {
	header, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(bytes.TrimRight(data, "\n"), '\n', '\n')))).ReadMIMEHeader()
	if err != nil && len(header) == 0 {
		return Package{}, false
	}
	p := Package{Ecosystem: "PyPI", Name: header.Get("Name"), Version: header.Get("Version")}
	if p.Name == "" {
		return p, false
	}
	if e := strings.TrimSpace(header.Get("License-Expression")); e != "" {
		p.Declared, p.License = e, Normalize(e)
		return p, true
	}
	classifiers := []string{}
	for _, c := range header.Values("Classifier") {
		if strings.HasPrefix(c, "License ::") && c != "License :: OSI Approved" {
			classifiers = append(classifiers, c)
		}
	}
	if len(classifiers) > 0 {
		// Several licence classifiers mean the distribution is offered under each.
		p.Declared, p.License = strings.Join(classifiers, "; "), Any(classifiers...)
		return p, true
	}
	if l := strings.TrimSpace(header.Get("License")); l != "" && len(l) <= 100 && !strings.Contains(l, "\n") && !strings.EqualFold(l, "UNKNOWN") {
		p.Declared, p.License = l, Normalize(l)
		return p, true
	}
	return p, false
}

// APKInstalled reads Alpine's lib/apk/db/installed. Packages are keyed by
// origin (o:), the source package name the vulnerability inventory uses.
func APKInstalled(data []byte) []Package {
	out := []Package{}
	var p Package
	flush := func() {
		if p.Name != "" && p.Declared != "" {
			if p.Source == "" {
				p.Source = p.Name
			}
			p.License = Normalize(p.Declared)
			out = append(out, p)
		}
		p = Package{}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		value := line[2:]
		switch line[0] {
		case 'P':
			p.Ecosystem, p.Name = "Alpine", value
		case 'V':
			p.Version = value
		case 'L':
			p.Declared = value
		case 'o':
			p.Source = value
		}
	}
	flush()
	return out
}

// DpkgStatus maps Debian binary packages to their source package and
// version from var/lib/dpkg/status.
func DpkgStatus(data []byte) map[string]Package {
	out := map[string]Package{}
	for _, stanza := range bytes.Split(data, []byte("\n\n")) {
		header, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(bytes.TrimSpace(stanza), '\n', '\n')))).ReadMIMEHeader()
		name := header.Get("Package")
		if name == "" || !strings.Contains(header.Get("Status"), "installed") {
			continue
		}
		source, version := header.Get("Source"), header.Get("Version")
		if source == "" {
			source = name
		} else if i := strings.Index(source, " ("); i > 0 {
			// "Source: glibc (2.36-9)": the binary was built from that source version.
			version = strings.TrimSuffix(source[i+2:], ")")
			source = source[:i]
		}
		out[name] = Package{Ecosystem: "Debian", Name: name, Version: version, Source: source}
	}
	return out
}

// DEP5 reads a machine-readable Debian copyright file and returns the
// conjunction of its License stanzas: the package as a whole carries every
// licence its files do. ok is false for free-form files, which are left to
// text detection.
func DEP5(data []byte) (declared string, normalized Normalized, ok bool) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("Format:")) {
		return "", Normalized{}, false
	}
	seen := map[string]bool{}
	parts := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "License:") {
			continue
		}
		short := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		if short == "" || seen[short] {
			continue
		}
		seen[short] = true
		parts = append(parts, short)
	}
	if len(parts) == 0 {
		return "", Normalized{}, false
	}
	return strings.Join(parts, "; "), All(parts...), true
}

// ComposerLock reads composer.lock or vendor/composer/installed.json.
func ComposerLock(data []byte) []Package {
	type entry struct {
		Name    string   `json:"name"`
		Version string   `json:"version"`
		License []string `json:"license"`
	}
	var lock struct {
		Packages    []entry `json:"packages"`
		PackagesDev []entry `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lock) != nil {
		// installed.json in Composer 1 is a bare array.
		var list []entry
		if json.Unmarshal(data, &list) != nil {
			return nil
		}
		lock.Packages = list
	}
	out := []Package{}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if p.Name != "" && len(p.License) > 0 {
			// Composer lists alternatives: "(MIT or GPL)" style dual licensing.
			out = append(out, Package{Ecosystem: "Packagist", Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), Declared: strings.Join(p.License, " OR "), License: Any(p.License...)})
		}
	}
	return out
}
