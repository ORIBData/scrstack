package assessments

import "testing"

func TestCIFile(t *testing.T) {
	for path, want := range map[string]bool{
		".github/workflows/ci.yml": true, ".gitlab-ci.yml": true, "Makefile": true, "sub/Dockerfile": true, "Dockerfile.prod": true,
		"app.dockerfile": true, "package.json": true, "web/package.json": true, "pom.xml": true, "Jenkinsfile": true,
		"src/main.go": false, "README.md": false, "docs/makefile.md": false, "package-lock.json": false,
	} {
		if got := ciFile(path); got != want {
			t.Errorf("ciFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestSizeFindings(t *testing.T) {
	prior := []FileEvidence{{Path: "Makefile", Size: 1000}, {Path: "src/a.go", Size: 500}, {Path: "package.json", Size: 2000}}
	current := []FileEvidence{{Path: "Makefile", Size: 60000}, {Path: "src/a.go", Size: 90000}, {Path: "package.json", Size: 2100}, {Path: "assets/blob.bin", Size: 5 << 20}, {Path: "assets/small.png", Size: 4000}}
	policy := IntegrityPolicy{LargeFileBytes: 1 << 20, CIGrowthBytes: 10000}
	byAdvisory := func(findings []Finding) map[string]Finding {
		out := map[string]Finding{}
		for _, f := range findings {
			out[f.AdvisoryID+" "+f.Component.Path] = f
		}
		return out
	}
	got := byAdvisory(sizeFindings(policy, prior, current, true, false))
	if len(got) != 2 || got["SCRS-LARGE-NEW-FILE assets/blob.bin"].Severity != "medium" || got["SCRS-CI-FILE-GROWTH Makefile"].Severity != "medium" {
		t.Fatalf("findings %v", got)
	}
	// Growth of a source file is not a CI file; a small CI change is under the threshold.
	if _, ok := got["SCRS-CI-FILE-GROWTH src/a.go"]; ok {
		t.Fatal("a source file is not a CI file")
	}
	// A first-time author's large new file is high.
	if f := byAdvisory(sizeFindings(policy, prior, current, true, true))["SCRS-LARGE-NEW-FILE assets/blob.bin"]; f.Severity != "high" || f.Score != 60 {
		t.Fatalf("first-time author: %+v", f)
	}
	// An earlier inventory that was not a whole walk cannot say a path is new.
	if got := byAdvisory(sizeFindings(policy, prior, current, false, false)); len(got) != 1 {
		t.Fatalf("partial prior walk: %v", got)
	}
	// With nothing earlier to compare against, nothing is new.
	if got := sizeFindings(policy, nil, current, true, false); len(got) != 0 {
		t.Fatalf("no baseline: %v", got)
	}
	// Each check is off at zero.
	if got := sizeFindings(IntegrityPolicy{}, prior, current, true, false); len(got) != 0 {
		t.Fatalf("policy off: %v", got)
	}
	if got := byAdvisory(sizeFindings(IntegrityPolicy{CIGrowthBytes: 10000}, prior, current, true, false)); len(got) != 1 || got["SCRS-CI-FILE-GROWTH Makefile"].Title == "" {
		t.Fatalf("growth only: %v", got)
	}
}
