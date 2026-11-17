package assessments

import (
	"errors"
	"strings"
	"testing"
)

func TestUploadTargetValidation(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	ok := Request{Target: Target{Type: "upload", Repository: "Upload/Vendor-Drop", Commit: strings.ToUpper(commit)}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Target.Repository != "upload/vendor-drop" || ok.Target.Commit != commit || ok.Target.Ref != "upload" {
		t.Fatalf("not normalised: %+v", ok.Target)
	}
	if types := ok.Target.assetTypes(); len(types) != 1 || types[0] != "uploaded" {
		t.Fatalf("asset types %v", types)
	}
	for name, target := range map[string]Target{
		"not an upload locator": {Type: "upload", Repository: "org/repo", Commit: commit},
		"no commit":             {Type: "upload", Repository: "upload/x"},
		"short commit":          {Type: "upload", Repository: "upload/x", Commit: commit[:39]},
		"a provider":            {Type: "upload", Repository: "upload/x", Commit: commit, Provider: "github"},
		"a platform":            {Type: "upload", Repository: "upload/x", Commit: commit, Platform: "linux/amd64"},
		"a pull request":        {Type: "upload", Repository: "upload/x", Commit: commit, PullRequest: &PullRequest{Number: 1, BaseRef: "main"}},
		"a bad label":           {Type: "upload", Repository: "upload/x", Commit: commit, Ref: "a b"},
	} {
		request := Request{Target: target}
		if err := request.Validate(); !errors.Is(err, ErrInput) {
			t.Errorf("%s was accepted: %v", name, err)
		}
	}
	// A git target is not an upload: the upload locator is not a repository path.
	git := Request{Target: Target{Type: "git", Repository: "upload/x"}}
	if err := git.Validate(); err != nil {
		t.Fatalf("a repository may be called upload/x: %v", err)
	}
	if types := git.Target.assetTypes(); len(types) != 2 {
		t.Fatalf("git types %v", types)
	}
}

// Suspicious-dependency entries close by absence only when the policy stage
// completed, so a failed deps.dev lookup never reads as a fix.
func TestSuspiciousDependenciesCloseOnlyWhenTheirStageCompleted(t *testing.T) {
	base := []Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "inventory", Status: "ok"}}
	has := func(stages []Stage) bool {
		for _, kind := range closableTypes(stages) {
			if kind == "suspicious_dependency" {
				return true
			}
		}
		return false
	}
	if has(base) {
		t.Fatal("closable without a dependency_policy stage")
	}
	if has(append(append([]Stage{}, base...), Stage{Name: "dependency_policy", Status: "partial"})) {
		t.Fatal("closable after a partial run")
	}
	if !has(append(append([]Stage{}, base...), Stage{Name: "dependency_policy", Status: "ok"})) {
		t.Fatal("not closable after a complete run")
	}
}
