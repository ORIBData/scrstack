package license

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"MIT":                                    "MIT",
		"mit":                                    "MIT",
		"MIT License":                            "MIT",
		"The MIT License (MIT)":                  "MIT",
		"Expat":                                  "MIT",
		"Apache-2.0":                             "Apache-2.0",
		"Apache License, Version 2.0":            "Apache-2.0",
		"Apache 2.0":                             "Apache-2.0",
		"Apache-2":                               "Apache-2.0",
		"ASL 2.0":                                "Apache-2.0",
		"GPL-2.0":                                "GPL-2.0-only",
		"GPL-2.0+":                               "GPL-2.0-or-later",
		"GPLv2":                                  "GPL-2.0-only",
		"GPLv3+":                                 "GPL-3.0-or-later",
		"GPL-2+":                                 "GPL-2.0-or-later",
		"LGPL-2.1+":                              "LGPL-2.1-or-later",
		"LGPLv3":                                 "LGPL-3.0-only",
		"AGPL-3.0":                               "AGPL-3.0-only",
		"GNU Affero General Public License v3":   "AGPL-3.0-only",
		"License :: OSI Approved :: MIT License": "MIT",
		"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
		"License :: OSI Approved :: BSD License":                                     "LicenseRef-scrs-bsd-unversioned",
		"BSD-3-clause":                                                               "BSD-3-Clause",
		"New BSD License":                                                            "BSD-3-Clause",
		"Simplified BSD":                                                             "BSD-2-Clause",
		"(MIT OR Apache-2.0)":                                                        "MIT OR Apache-2.0",
		"MIT or Apache-2.0":                                                          "MIT OR Apache-2.0",
		"mit and isc":                                                                "MIT AND ISC",
		"MIT/X11":                                                                    "MIT",
		"MIT OR (Apache-2.0 AND BSD-2-Clause)":                                       "MIT OR Apache-2.0 AND BSD-2-Clause",
		"(MIT OR ISC) AND Zlib":                                                      "(MIT OR ISC) AND Zlib",
		"GPL-2.0-only WITH Classpath-exception-2.0":                                  "GPL-2.0-only WITH Classpath-exception-2.0",
		"GPL-2.0 with classpath exception":                                           "GPL-2.0-only WITH Classpath-exception-2.0",
		"Public Domain":                                                              "LicenseRef-scrs-public-domain",
		"UNLICENSED":                                                                 "LicenseRef-scrs-proprietary",
		"Unlicense":                                                                  "Unlicense",
		"CC0 1.0 Universal":                                                          "CC0-1.0",
		"Creative Commons Attribution 4.0 International":                             "CC-BY-4.0",
		"CC BY-NC 4.0":                                                               "CC-BY-NC-4.0",
		"Mozilla Public License 2.0":                                                 "MPL-2.0",
		"EPL 2.0":                                                                    "EPL-2.0",
		"Eclipse Public License 2.0":                                                 "EPL-2.0",
		"Business Source License":                                                    "BUSL-1.1",
		"":                                                                           NoAssertion,
		"NOASSERTION":                                                                NoAssertion,
		"UNKNOWN":                                                                    NoAssertion,
	}
	for in, want := range cases {
		if got := Normalize(in).Expression; got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
	unknown := Normalize("SEE LICENSE IN LICENSE.txt")
	if !strings.HasPrefix(unknown.Expression, "LicenseRef-scrs-") || unknown.Refs[unknown.Expression] != "SEE LICENSE IN LICENSE.txt" || unknown.Exact {
		t.Fatalf("unrecognised text: %+v", unknown)
	}
	if DefaultCatalog().Category(unknown.Expression) != Unknown {
		t.Fatal("invented LicenseRef must be unknown")
	}
	if n := Normalize("MIT OR Apache-2.0"); !n.Exact {
		t.Fatal("valid expression not marked exact")
	}
	for _, bad := range []string{"MIT AND", "(MIT", "MIT WITH Nonexistent-exception", "AND MIT", strings.Repeat("(", 30) + "MIT" + strings.Repeat(")", 30)} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	// Combining keeps classifier items whole even when they contain "or".
	if got := Any("License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)", "MIT License").Expression; got != "LicenseRef-scrs-lgpl-unversioned OR MIT" {
		t.Fatalf("Any = %q", got)
	}
	if got := All("GPL-2+", "LGPL-2.1+", "GPL-2+"); got.Expression != "GPL-2.0-or-later AND LGPL-2.1-or-later" {
		t.Fatalf("All = %q", got.Expression)
	}
	if ListVersion() != "3.29.0" {
		t.Fatalf("SPDX list version %q", ListVersion())
	}
}

func TestCategories(t *testing.T) {
	c := DefaultCatalog()
	cases := map[string]string{
		"MIT": Permissive, "Apache-2.0": Permissive, "BSD-3-Clause": Permissive, "ISC": Permissive, "0BSD": PublicDomain, "CC0-1.0": PublicDomain,
		"LGPL-2.1-only": WeakCopyleft, "MPL-2.0": WeakCopyleft, "EPL-2.0": WeakCopyleft,
		"GPL-2.0-only": StrongCopyleft, "GPL-3.0-or-later": StrongCopyleft, "EUPL-1.2": StrongCopyleft,
		"AGPL-3.0-only": NetworkCopyleft, "OSL-3.0": NetworkCopyleft,
		"SSPL-1.0": SourceAvailableRestricted, "BUSL-1.1": SourceAvailableRestricted, "Elastic-2.0": SourceAvailableRestricted,
		"CC-BY-NC-4.0": NonCommercial, "PolyForm-Noncommercial-1.0.0": NonCommercial,
		"LicenseRef-scrs-proprietary": Proprietary, "LicenseRef-other": Unknown,
	}
	for id, want := range cases {
		if got := c.Category(id); got != want {
			t.Errorf("Category(%s) = %s, want %s", id, got, want)
		}
	}
	n, _ := Parse("GPL-2.0-only WITH Classpath-exception-2.0")
	if c.LeafCategory(n) != WeakCopyleft {
		t.Fatal("Classpath exception should weaken strong copyleft")
	}
	n, _ = Parse("GPL-2.0-only WITH openvpn-openssl-exception")
	if c.LeafCategory(n) != StrongCopyleft {
		t.Fatal("an OpenSSL linking permission is not a general linking exception")
	}
	overridden, err := NewCatalog(3, map[string]string{"MPL-2.0": Permissive, "LicenseRef-acme-eula": Proprietary})
	if err != nil || overridden.Category("MPL-2.0") != Permissive || overridden.Category("LicenseRef-acme-eula") != Proprietary || overridden.Revision != 3 {
		t.Fatalf("overrides: %v %+v", err, overridden)
	}
	for _, bad := range []map[string]string{{"Not-A-License": Permissive}, {"MIT": "copyleft"}} {
		if _, err := NewCatalog(1, bad); err == nil {
			t.Errorf("override %v accepted", bad)
		}
	}
	counts := c.Counts()
	if counts[Unknown] != 0 || counts[Permissive] < 400 {
		t.Fatalf("category counts %v", counts)
	}
}

func TestCorporateDefault(t *testing.T) {
	p := CorporateDefault()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	c := DefaultCatalog()
	asset := uuid.New()
	decide := func(expression, distribution string) Decision {
		return p.Evaluate(c, Subject{Expression: expression, Distribution: distribution, Asset: asset, PURL: "pkg:npm/x@1", Path: "package-lock.json"})
	}
	// AT-25: AGPL in a SaaS asset is denied, MIT allowed, no licence reviewed.
	if d := decide("AGPL-3.0-only", SaaS); d.Effect != Deny || d.Category != NetworkCopyleft || d.Basis != "matrix:network_copyleft/saas" {
		t.Fatalf("AGPL saas: %+v", d)
	}
	if d := decide("MIT", SaaS); d.Effect != Allow {
		t.Fatalf("MIT: %+v", d)
	}
	if d := decide(NoAssertion, SaaS); d.Effect != Review || d.Category != Unknown {
		t.Fatalf("no licence: %+v", d)
	}
	if d := decide("GPL-3.0-only", Distributed); d.Effect != Review {
		t.Fatalf("GPL distributed: %+v", d)
	}
	if d := decide("GPL-3.0-only", SaaS); d.Effect != Allow {
		t.Fatalf("GPL saas: %+v", d)
	}
	// OR takes the most lenient choice, AND the strictest member.
	if d := decide("AGPL-3.0-only OR MIT", SaaS); d.Effect != Allow || d.Licenses[0] != "MIT" {
		t.Fatalf("dual licence: %+v", d)
	}
	if d := decide("MIT AND AGPL-3.0-only", SaaS); d.Effect != Deny || d.Licenses[0] != "AGPL-3.0-only" {
		t.Fatalf("conjunction: %+v", d)
	}
	if d := decide("CC-BY-NC-4.0", Internal); d.Effect != Deny {
		t.Fatalf("non-commercial: %+v", d)
	}
	if p.SeverityFor(Deny) != "high" || p.SeverityFor(Review) != "medium" || p.Enforcing {
		t.Fatal("default severities or enforcement")
	}
}

func TestPolicyRules(t *testing.T) {
	raw := `{"name":"acme","default":"review","enforcing":true,"matrix":{"permissive":{"saas":"allow"},"network_copyleft":{"saas":"deny"}},"rules":[
	 {"effect":"allow","categories":["network_copyleft"],"scope":"dev","reason":"build tooling only"},
	 {"effect":"allow","packages":["pkg:npm/legacy-agpl-lib"],"reason":"counsel approved 2026-10"},
	 {"effect":"deny","licenses":["WTFPL"],"paths":["services/**/package-lock.json"]},
	 {"effect":"review","licenses":["NOASSERTION"],"distributions":["saas"]}]}`
	p, err := ParsePolicy([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultCatalog()
	if d := p.Evaluate(c, Subject{Expression: "AGPL-3.0-only", Distribution: SaaS, Dev: true}); d.Effect != Allow || d.Basis != "rule:0" || d.Reason != "build tooling only" {
		t.Fatalf("dev scope rule: %+v", d)
	}
	if d := p.Evaluate(c, Subject{Expression: "AGPL-3.0-only", Distribution: SaaS, PURL: "pkg:npm/legacy-agpl-lib@2.0.0"}); d.Effect != Allow || d.Basis != "rule:1" {
		t.Fatalf("package rule: %+v", d)
	}
	if d := p.Evaluate(c, Subject{Expression: "AGPL-3.0-only", Distribution: SaaS, PURL: "pkg:npm/other@1"}); d.Effect != Deny {
		t.Fatalf("matrix: %+v", d)
	}
	if d := p.Evaluate(c, Subject{Expression: "WTFPL", Distribution: SaaS, Path: "services/api/package-lock.json"}); d.Effect != Deny || d.Basis != "rule:2" {
		t.Fatalf("path rule: %+v", d)
	}
	if d := p.Evaluate(c, Subject{Expression: "WTFPL", Distribution: SaaS, Path: "tools/package-lock.json"}); d.Effect != Review || d.Basis != "default" {
		t.Fatalf("path rule must not match elsewhere: %+v", d)
	}
	for _, bad := range []string{
		`{"name":"x","default":"maybe","matrix":{}}`,
		`{"name":"x","default":"allow","matrix":{"copyleft":{"saas":"allow"}}}`,
		`{"name":"x","default":"allow","matrix":{},"rules":[{"effect":"deny"}]}`,
		`{"name":"x","default":"allow","matrix":{},"rules":[{"effect":"deny","licenses":["Nope-1.0"]}]}`,
		`{"name":"x","default":"allow","matrix":{},"unexpected":1}`,
		`{"name":"Bad Name","default":"allow","matrix":{}}`,
		`{"name":"x","default":"allow","matrix":{},"rules":[{"effect":"deny","licenses":["MIT"],"scope":"test"}]}`,
	} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if !globMatch("**/vendor/**", "a/b/vendor/x/go.mod") || !globMatch("go.mod", "go.mod") || globMatch("*.json", "a/b.json") {
		t.Fatal("glob semantics")
	}
}

// The published schema accepts corporate-default and rejects what
// ParsePolicy rejects.
func TestPolicySchema(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("policy.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("policy.json")
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := data.ReadFile("data/corporate-default.json")
	instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader(valid))
	if err := schema.Validate(instance); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"name":"x","default":"maybe","matrix":{}}`, `{"name":"x","default":"allow","matrix":{},"rules":[{"effect":"deny"}]}`} {
		instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(bad))
		if schema.Validate(instance) == nil {
			t.Errorf("schema accepted %s", bad)
		}
	}
	var p Policy
	_ = json.Unmarshal(valid, &p)
	if p.Name != "corporate-default" {
		t.Fatal("corporate-default name")
	}
}

func TestDetect(t *testing.T) {
	mit := []byte(`MIT License

Copyright (c) 2024 Example Corp
Copyright (c) 2025 Another Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`)
	d, ok := Detect(mit)
	if !ok || d.Expression != "MIT" || d.Confidence < 0.9 || len(d.Copyright) != 2 || d.Copyright[0] != "Copyright (c) 2024 Example Corp" {
		t.Fatalf("MIT detection: %+v %v", d, ok)
	}
	if _, ok := Detect([]byte("This project is great. Contact us for terms.")); ok {
		t.Fatal("non-licence text detected as a licence")
	}
	if !IsLicenseFile("LICENSE.md") || !IsLicenseFile("COPYING") || !IsLicenseFile("license-mit") || IsLicenseFile("README.md") {
		t.Fatal("licence file names")
	}
}

func TestManifests(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app","license":"UNLICENSED"},
	 "node_modules/express":{"version":"4.21.2","license":"MIT"},
	 "node_modules/@scope/pkg":{"version":"1.0.0","license":"(MIT OR Apache-2.0)"},
	 "node_modules/a/node_modules/b":{"version":"2.0.0","licenses":[{"type":"BSD"},"MIT"]},
	 "node_modules/linked":{"link":true}}}`
	got := map[string]Package{}
	for _, p := range NPMLock([]byte(lock)) {
		got[p.Name+"@"+p.Version] = p
	}
	if len(got) != 3 || got["express@4.21.2"].License.Expression != "MIT" || got["@scope/pkg@1.0.0"].License.Expression != "MIT OR Apache-2.0" || got["b@2.0.0"].License.Expression != "LicenseRef-scrs-bsd-unversioned OR MIT" {
		t.Fatalf("npm lock: %+v", got)
	}
	if p, ok := NPMPackageJSON([]byte(`{"name":"left-pad","version":"1.3.0","license":{"type":"WTFPL"}}`)); !ok || p.License.Expression != "WTFPL" {
		t.Fatalf("package.json: %+v", p)
	}
	metadata := "Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\nLicense: Apache-2.0\nClassifier: License :: OSI Approved :: Apache Software License\nClassifier: Programming Language :: Python\n\nlong description\n"
	if p, ok := PythonMetadata([]byte(metadata)); !ok || p.Name != "requests" || p.License.Expression != "Apache-2.0" {
		t.Fatalf("METADATA classifiers: %+v", p)
	}
	if p, ok := PythonMetadata([]byte("Metadata-Version: 2.4\nName: x\nVersion: 1\nLicense-Expression: MIT OR BSD-3-Clause\n")); !ok || p.License.Expression != "MIT OR BSD-3-Clause" {
		t.Fatalf("PEP 639: %+v", p)
	}
	apk := "C:Q1\nP:libcrypto3\nV:3.1.4-r0\no:openssl\nL:Apache-2.0\n\nP:musl\nV:1.2.4-r2\nL:MIT\n\n"
	pkgs := APKInstalled([]byte(apk))
	if len(pkgs) != 2 || pkgs[0].Source != "openssl" || pkgs[0].License.Expression != "Apache-2.0" || pkgs[1].Source != "musl" {
		t.Fatalf("apk: %+v", pkgs)
	}
	status := "Package: libc6\nStatus: install ok installed\nSource: glibc (2.36-9+deb12u4)\nVersion: 2.36-9+deb12u4\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b2\n\nPackage: gone\nStatus: deinstall ok config-files\n"
	binaries := DpkgStatus([]byte(status))
	if len(binaries) != 2 || binaries["libc6"].Source != "glibc" || binaries["libc6"].Version != "2.36-9+deb12u4" || binaries["bash"].Source != "bash" {
		t.Fatalf("dpkg: %+v", binaries)
	}
	dep5 := "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nCopyright: 1989 FSF\nLicense: GPL-3+\n\nFiles: lib/*\nLicense: LGPL-2.1+ or Artistic\n\nLicense: GPL-3+\n On Debian systems...\n"
	if _, n, ok := DEP5([]byte(dep5)); !ok || n.Expression != "GPL-3.0-or-later AND (LGPL-2.1-or-later OR LicenseRef-scrs-artistic)" {
		t.Fatalf("DEP-5: %+v %v", n, ok)
	}
	if _, _, ok := DEP5([]byte("This is free software; see GPL.\n")); ok {
		t.Fatal("free-form copyright parsed as DEP-5")
	}
	composer := `{"packages":[{"name":"monolog/monolog","version":"3.5.0","license":["MIT"]}],"packages-dev":[{"name":"phpunit/phpunit","version":"v10.0.0","license":["BSD-3-Clause"]}]}`
	if c := ComposerLock([]byte(composer)); len(c) != 2 || c[1].Version != "10.0.0" || c[1].License.Expression != "BSD-3-Clause" {
		t.Fatalf("composer: %+v", c)
	}
}
