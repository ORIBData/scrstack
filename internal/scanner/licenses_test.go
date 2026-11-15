package scanner

import (
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
)

const mitText = `MIT License

Copyright (c) 2020 Jane Developer

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
`

func TestLicenseCollectorImageLayers(t *testing.T) {
	l := newLicenseCollector(true)
	files := map[string]string{
		"lib/apk/db/installed":             "P:libcrypto3\nV:3.1.4-r0\no:openssl\nL:Apache-2.0\n\nP:busybox\nV:1.36.1-r5\nL:GPL-2.0-only\n\n",
		"var/lib/dpkg/status":              "Package: libc6\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9\n\nPackage: libc-bin\nStatus: install ok installed\nSource: glibc\nVersion: 2.36-9\n\nPackage: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n",
		"usr/share/doc/libc6/copyright":    "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nLicense: LGPL-2.1+\n",
		"usr/share/doc/libc-bin/copyright": "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nLicense: GPL-2+\n",
		"usr/share/doc/zlib1g/copyright":   "This is zlib.\n\n" + mitText,
		"usr/lib/python3.12/site-packages/Flask_Cors-4.0.1.dist-info/METADATA": "Metadata-Version: 2.1\nName: Flask-Cors\nVersion: 4.0.1\nLicense: MIT\n",
		"usr/lib/python3.12/site-packages/six-1.16.0.dist-info/LICENSE":        mitText,
		"usr/local/lib/node_modules/npm/node_modules/abbrev/package.json":      `{"name":"abbrev","version":"2.0.0","license":"ISC"}`,
		"usr/local/lib/node_modules/npm/node_modules/@npmcli/fs/LICENSE.md":    mitText,
		"root/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/COPYING":          mitText,
		"LICENSE": mitText,
	}
	for name, body := range files {
		l.observe(name, []byte(body))
	}
	components := []assessments.Component{
		{Name: "openssl", Version: "3.1.4-r0", Ecosystem: "Alpine:v3.18"},
		{Name: "busybox", Version: "1.36.1-r5", Ecosystem: "Alpine:v3.18"},
		{Name: "glibc", Version: "2.36-9", Ecosystem: "Debian:12"},
		{Name: "zlib", Version: "1:1.2.13.dfsg-1", Ecosystem: "Debian:12"},
		{Name: "flask-cors", Version: "4.0.1", Ecosystem: "PyPI"},
		{Name: "six", Version: "1.16.0", Ecosystem: "PyPI"},
		{Name: "abbrev", Version: "2.0.0", Ecosystem: "npm"},
		{Name: "@npmcli/fs", Version: "3.1.0", Ecosystem: "npm"},
		{Name: "github.com/BurntSushi/toml", Version: "v1.3.2", Ecosystem: "Go"},
		{Name: "unlisted", Version: "1.0.0", Ecosystem: "npm"},
	}
	l.apply(components)
	want := map[string][2]string{
		"openssl":                    {"Apache-2.0", "declared"},
		"busybox":                    {"GPL-2.0-only", "declared"},
		"glibc":                      {"LGPL-2.1-or-later AND GPL-2.0-or-later", "declared"},
		"zlib":                       {"MIT", "detected"},
		"flask-cors":                 {"MIT", "declared"},
		"six":                        {"MIT", "detected"},
		"abbrev":                     {"ISC", "declared"},
		"@npmcli/fs":                 {"MIT", "detected"},
		"github.com/BurntSushi/toml": {"MIT", "detected"},
	}
	for _, c := range components {
		w, ok := want[c.Name]
		if !ok {
			if c.License != nil {
				t.Errorf("%s: unexpected licence %+v", c.Name, c.License)
			}
			continue
		}
		if c.License == nil {
			t.Errorf("%s: no licence", c.Name)
			continue
		}
		// glibc's binaries may be combined in either order.
		if c.Name == "glibc" && c.License.Expression == "GPL-2.0-or-later AND LGPL-2.1-or-later" {
			c.License.Expression = w[0]
		}
		if c.License.Expression != w[0] || c.License.Source != w[1] {
			t.Errorf("%s: %+v, want %v", c.Name, c.License, w)
		}
	}
	if components[5].License.Confidence < 0.9 || len(components[5].License.Copyright) != 1 {
		t.Fatalf("detected licence detail: %+v", components[5].License)
	}
	// Image layers never set a project licence.
	if l.project != nil {
		t.Fatal("project licence from an image")
	}
	repo := newLicenseCollector(false)
	repo.observe("LICENSE", []byte(mitText))
	if repo.project == nil || repo.project.Expression != "MIT" {
		t.Fatalf("project licence: %+v", repo.project)
	}
}
