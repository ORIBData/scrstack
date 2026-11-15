package scanner

import (
	"path"
	"regexp"
	"strings"
	"unicode"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/license"
)

// licenseCollector gathers licence evidence (LIC-001) while the content
// walk reads each file: declared licences from lockfiles, manifests and OS
// package databases, and detected licences from licence files next to the
// package they belong to. apply attaches the evidence to the inventory.
type licenseCollector struct {
	image    bool
	declared map[string]licenseEvidence
	detected map[string]licenseEvidence
	// Debian: binary package -> source package, and copyright evidence per
	// binary package (usr/share/doc/<binary>/copyright).
	dpkg      map[string]license.Package
	debian    map[string]licenseEvidence
	project   *assessments.ComponentLicense
	entries   int
	truncated bool
}

type licenseEvidence struct {
	license.Normalized
	source, declaredText, evidence string
	confidence                     float64
	copyright                      []string
}

// maxLicenseEntries bounds the evidence kept for one scan.
const maxLicenseEntries = 200000

func newLicenseCollector(image bool) *licenseCollector {
	return &licenseCollector{image: image, declared: map[string]licenseEvidence{}, detected: map[string]licenseEvidence{}, dpkg: map[string]license.Package{}, debian: map[string]licenseEvidence{}}
}

// pep503 normalises a Python distribution name.
var pep503Separators = regexp.MustCompile(`[-_.]+`)

func packageKey(ecosystem, name string) string {
	ecosystem, _, _ = strings.Cut(ecosystem, ":")
	switch ecosystem {
	case "PyPI":
		name = pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
	case "Packagist", "Alpine", "Debian":
		name = strings.ToLower(name)
	}
	return ecosystem + "|" + name
}

func (l *licenseCollector) put(m map[string]licenseEvidence, ecosystem, name, version string, e licenseEvidence) {
	if l.entries >= maxLicenseEntries {
		l.truncated = true
		return
	}
	l.entries++
	key := packageKey(ecosystem, name)
	if version != "" {
		m[key+"|"+version] = e
	}
	// The unversioned key keeps the first evidence seen; versioned keys
	// distinguish several installed versions of one package.
	if _, ok := m[key]; !ok {
		m[key] = e
	}
}

func declaredEvidence(p license.Package, evidence string) licenseEvidence {
	return licenseEvidence{Normalized: p.License, source: "declared", declaredText: p.Declared, evidence: evidence}
}

var (
	nodeModule  = regexp.MustCompile(`(?:^|/)node_modules/((?:@[^/]+/)?[^/@][^/]*)$`)
	distInfo    = regexp.MustCompile(`(?:^|/)([^/]+?)-[^/-]+\.(?:dist-info|egg-info)(?:/licenses|/LICENSES)?$`)
	goVendor    = regexp.MustCompile(`(?:^|/)vendor/([a-z0-9.-]+\.[a-z]{2,}/[^/]+(?:/[^/]+)?)$`)
	goModCache  = regexp.MustCompile(`(?:^|/)pkg/mod/([^@]+)@([^/]+)$`)
	debianDoc   = regexp.MustCompile(`^usr/share/doc/([^/]+)/copyright$`)
	dpkgStatusD = regexp.MustCompile(`^var/lib/dpkg/status\.d/[^/]+$`)
)

// observe inspects one file the content walk has read.
func (l *licenseCollector) observe(name string, data []byte) {
	if l == nil || len(data) == 0 || len(data) > 8<<20 {
		return
	}
	base, dir := path.Base(name), path.Dir(name)
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		for _, p := range license.NPMLock(data) {
			l.put(l.declared, "npm", p.Name, p.Version, declaredEvidence(p, name))
		}
		return
	case base == "package.json" && nodeModule.MatchString(dir):
		if p, ok := license.NPMPackageJSON(data); ok {
			l.put(l.declared, "npm", p.Name, p.Version, declaredEvidence(p, name))
		}
		return
	case base == "composer.lock" || (base == "installed.json" && strings.HasSuffix(dir, "vendor/composer")):
		for _, p := range license.ComposerLock(data) {
			l.put(l.declared, "Packagist", p.Name, p.Version, declaredEvidence(p, name))
		}
		return
	case (base == "METADATA" && strings.HasSuffix(dir, ".dist-info")) || (base == "PKG-INFO" && strings.HasSuffix(dir, ".egg-info")):
		if p, ok := license.PythonMetadata(data); ok {
			l.put(l.declared, "PyPI", p.Name, p.Version, declaredEvidence(p, name))
		}
		return
	case name == "lib/apk/db/installed":
		for _, p := range license.APKInstalled(data) {
			e := declaredEvidence(p, name)
			l.put(l.declared, "Alpine", p.Source, p.Version, e)
		}
		return
	case name == "var/lib/dpkg/status" || dpkgStatusD.MatchString(name):
		for binary, p := range license.DpkgStatus(data) {
			l.dpkg[binary] = p
		}
		return
	}
	if m := debianDoc.FindStringSubmatch(name); m != nil {
		if declared, normalized, ok := license.DEP5(data); ok {
			l.debian[m[1]] = licenseEvidence{Normalized: normalized, source: "declared", declaredText: declared, evidence: name, copyright: license.Copyrights(data)}
		} else if d, ok := license.Detect(data); ok {
			l.debian[m[1]] = licenseEvidence{Normalized: license.Normalized{Expression: d.Expression}, source: "detected", evidence: name, confidence: d.Confidence, copyright: d.Copyright}
		}
		return
	}
	if !license.IsLicenseFile(base) {
		return
	}
	detect := func(ecosystem, pkg, version string) {
		if d, ok := license.Detect(data); ok {
			l.put(l.detected, ecosystem, pkg, version, licenseEvidence{Normalized: license.Normalized{Expression: d.Expression}, source: "detected", evidence: name, confidence: d.Confidence, copyright: d.Copyright})
		}
	}
	if m := nodeModule.FindStringSubmatch(dir); m != nil {
		detect("npm", m[1], "")
	} else if m := distInfo.FindStringSubmatch(dir); m != nil {
		detect("PyPI", m[1], "")
	} else if m := goModCache.FindStringSubmatch(dir); m != nil {
		detect("Go", unescapeModule(m[1]), m[2])
	} else if m := goVendor.FindStringSubmatch(dir); m != nil {
		detect("Go", m[1], "")
	} else if dir == "." && !l.image {
		if d, ok := license.Detect(data); ok && l.project == nil {
			l.project = &assessments.ComponentLicense{Expression: d.Expression, Source: "detected", Confidence: d.Confidence, Evidence: name, Copyright: d.Copyright}
		}
	}
}

// unescapeModule reverses the module cache's case encoding ("!b" -> "B").
func unescapeModule(p string) string {
	var b strings.Builder
	upper := false
	for _, r := range p {
		if r == '!' {
			upper = true
			continue
		}
		if upper {
			r = unicode.ToUpper(r)
			upper = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// usable reports evidence whose expression names a recognised licence.
func (e licenseEvidence) usable() bool {
	if e.Expression == "" || e.Expression == license.NoAssertion {
		return false
	}
	return len(e.Refs) == 0
}

func (l *licenseCollector) lookup(m map[string]licenseEvidence, c assessments.Component) (licenseEvidence, bool) {
	key := packageKey(c.Ecosystem, c.Name)
	if e, ok := m[key+"|"+c.Version]; ok {
		return e, true
	}
	e, ok := m[key]
	return e, ok
}

// debianEvidence combines the copyright files of every binary package
// built from one source package.
func (l *licenseCollector) debianEvidence(source string) (licenseEvidence, bool) {
	declared, detected := []string{}, []string{}
	out := licenseEvidence{}
	files := []string{}
	for binary, p := range l.dpkg {
		if !strings.EqualFold(p.Source, source) {
			continue
		}
		e, ok := l.debian[binary]
		if !ok {
			continue
		}
		files = append(files, e.evidence)
		out.copyright = append(out.copyright, e.copyright...)
		if e.source == "declared" {
			declared = append(declared, e.Expression)
			for ref, text := range e.Refs {
				if out.Refs == nil {
					out.Refs = map[string]string{}
				}
				out.Refs[ref] = text
			}
		} else {
			detected = append(detected, e.Expression)
			out.confidence = max(out.confidence, e.confidence)
		}
	}
	if len(files) == 0 {
		return out, false
	}
	if len(out.copyright) > 10 {
		out.copyright = out.copyright[:10]
	}
	out.evidence = files[0]
	if len(declared) > 0 {
		out.source, out.Expression = "declared", license.And(declared...)
	} else {
		out.source, out.Expression = "detected", license.And(detected...)
	}
	return out, out.Expression != license.NoAssertion
}

// apply sets each component's licence: a recognised declared licence
// first, then a detected one, then declared text SCRS could not identify.
// Components left without evidence get their licence from package
// metadata in the worker.
func (l *licenseCollector) apply(components []assessments.Component) {
	if l == nil {
		return
	}
	for i := range components {
		c := &components[i]
		var declared, detected licenseEvidence
		var hasDeclared, hasDetected bool
		if strings.HasPrefix(c.Ecosystem, "Debian") {
			e, ok := l.debianEvidence(c.Name)
			if ok && e.source == "declared" {
				declared, hasDeclared = e, true
			} else if ok {
				detected, hasDetected = e, true
			}
		} else {
			declared, hasDeclared = l.lookup(l.declared, *c)
			detected, hasDetected = l.lookup(l.detected, *c)
		}
		var chosen licenseEvidence
		switch {
		case hasDeclared && declared.usable():
			chosen = declared
		case hasDetected && detected.usable() && detected.confidence >= license.MinConfidence:
			chosen = detected
			if hasDeclared {
				chosen.declaredText = declared.declaredText
			}
		case hasDeclared && declared.Expression != "" && declared.Expression != license.NoAssertion:
			chosen = declared
		default:
			continue
		}
		if len(chosen.copyright) == 0 && hasDetected {
			chosen.copyright = detected.copyright
		}
		cl := &assessments.ComponentLicense{Expression: chosen.Expression, Source: chosen.source, Confidence: chosen.confidence, Evidence: chosen.evidence, Copyright: chosen.copyright, Refs: chosen.Refs}
		if chosen.declaredText != chosen.Expression {
			cl.Declared = chosen.declaredText
		}
		c.License = cl
	}
}
