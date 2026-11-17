package sast

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) *Workspace {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ws, _, err := NewWorkspace(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

func keys(m map[string][]Step) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestScanImportsJavaScript(t *testing.T) {
	ws := writeTree(t, map[string]string{
		"src/a.js":                      "const _ = require('lodash');\nconst fp = require(\"lodash/fp\");\nconst fs = require('fs');\nconst rel = require('./local');\n",
		"src/b.ts":                      "import React from 'react';\nimport { x, y } from '@scope/pkg/sub';\nimport 'core-js/stable';\nimport * as path from 'node:path';\nexport { z } from 'rxjs/operators';\nconst lazy = await import('chalk');\n",
		"src/c.jsx":                     "import Foo from './Foo';\nimport bar from \"../bar\";\nimport type { T } from 'type-fest';\n",
		"node_modules/leftpad/index.js": "require('should-not-appear');\n",
		"README.md":                     "require('not-source')\n",
		"src/min.js":                    strings.Repeat("require('minified-skipped');", 200),
	})
	got := ScanImports(ws)
	if got.Status != "ok" || got.Files != 4 {
		t.Fatalf("scan: %+v", got)
	}
	if want := "@scope/pkg,chalk,core-js,lodash,react,rxjs,type-fest"; keys(got.NPM) != want {
		t.Fatalf("npm packages %q, want %q", keys(got.NPM), want)
	}
	if steps := got.NPM["lodash"]; len(steps) != 2 || steps[0].Path != "src/a.js" || steps[0].Line != 1 || steps[1].Line != 2 {
		t.Fatalf("lodash steps: %+v", steps)
	}
	if len(got.PyPI) != 0 {
		t.Fatalf("pypi: %v", got.PyPI)
	}
}

func TestScanImportsPythonAndLimits(t *testing.T) {
	body := "import os, sys\nimport requests\nimport yaml as y\nfrom bs4 import BeautifulSoup\nfrom django.db import models\nfrom . import sibling\nfrom .pkg import thing\n  import indented.module.sub\n# import commented\nx = 'import notcode'\n"
	ws := writeTree(t, map[string]string{"app/main.py": body, "app/other.py": "import requests\n"})
	got := ScanImports(ws)
	if want := "bs4,django,indented,os,requests,sys,yaml"; keys(got.PyPI) != want {
		t.Fatalf("python modules %q, want %q", keys(got.PyPI), want)
	}
	if len(got.PyPI["requests"]) != 2 {
		t.Fatalf("requests steps: %+v", got.PyPI["requests"])
	}
	// Each package keeps at most a handful of places.
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, "import many")
	}
	if steps := ScanImports(writeTree(t, map[string]string{"m.py": strings.Join(lines, "\n")})).PyPI["many"]; len(steps) != maxImportSteps {
		t.Fatalf("steps are not capped: %d", len(steps))
	}
	// No source: skipped, and nothing is answered.
	empty := ScanImports(writeTree(t, map[string]string{"main.go": "package main"}))
	if empty.Status != "skipped" || empty.ImportedSteps("npm", "lodash") != nil {
		t.Fatalf("no JS or Python source: %+v", empty)
	}
}

func TestImportedStepsMatchesDistributionsToModules(t *testing.T) {
	ws := writeTree(t, map[string]string{
		"a.py": "import bs4\nimport yaml\nimport PIL\nimport my_package\nfrom dateutil import parser\nimport google.protobuf\n",
		"a.js": "require('Lodash');\nrequire('@scope/Pkg');\n",
	})
	imports := ScanImports(ws)
	for _, tc := range []struct {
		ecosystem, name string
		want            bool
	}{
		{"PyPI", "beautifulsoup4", true}, {"PyPI", "PyYAML", true}, {"PyPI", "Pillow", true}, {"PyPI", "my-package", true},
		{"PyPI", "My.Package", true}, {"PyPI", "python-dateutil", true}, {"PyPI", "protobuf", true}, {"PyPI", "requests", false},
		{"npm", "lodash", true}, {"npm", "@scope/pkg", true}, {"npm", "express", false}, {"Go", "lodash", false}, {"Maven", "x", false},
		{"npm:registry", "lodash", true},
	} {
		if got := len(imports.ImportedSteps(tc.ecosystem, tc.name)) > 0; got != tc.want {
			t.Errorf("%s %s imported = %v, want %v", tc.ecosystem, tc.name, got, tc.want)
		}
	}
	var nilImports *Imports
	if nilImports.ImportedSteps("npm", "lodash") != nil {
		t.Fatal("a nil result must answer nothing")
	}
}
