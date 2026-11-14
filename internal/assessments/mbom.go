package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// buildDefinition reports whether a repository file defines how the software
// is built or delivered: CI workflows, container and build scripts, and the
// dependency lockfiles that pin build inputs.
func buildDefinition(p string) bool {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(p, ".github/workflows/"), p == ".gitlab-ci.yml", strings.HasPrefix(p, ".gitlab/ci/"),
		strings.HasPrefix(p, ".circleci/"), p == "Jenkinsfile", p == "azure-pipelines.yml", p == "bitbucket-pipelines.yml":
		return true
	case base == "Dockerfile", strings.HasPrefix(base, "Dockerfile."), strings.HasSuffix(base, ".Dockerfile"), base == "Containerfile",
		base == "docker-compose.yml", base == "docker-compose.yaml", base == "compose.yaml", base == "compose.yml":
		return true
	case base == "Makefile", strings.HasSuffix(base, ".mk"), base == "build.gradle", base == "build.gradle.kts", base == "pom.xml",
		base == "go.mod", base == "go.sum", base == "package.json", base == "package-lock.json", base == "yarn.lock",
		base == "pnpm-lock.yaml", base == "requirements.txt", base == "poetry.lock", base == "Cargo.lock", base == "Gemfile.lock":
		return true
	}
	return false
}

// MBOM exports a CycloneDX 1.6 Manufacturing Bill of Materials for one
// assessment: what was produced (the repository revision or image digest),
// from which build definitions and pinned inputs (with SHA-256 digests), and
// which tools verified it. It is built from what SCRS observed in the
// assessed revision; SCRS does not observe the CI run itself, so this is a
// declared formulation, not build provenance (use SLSA attestations for that).
func (s *Store) MBOM(ctx context.Context, id uuid.UUID) (json.RawMessage, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Status != "succeeded" || a.Commit == "" {
		return nil, ErrConflict
	}
	var files []FileEvidence
	var raw []byte
	err = s.pool.QueryRow(ctx, `SELECT body FROM `+s.schema+`.assessment_files WHERE assessment_id=$1`, id).Scan(&raw)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &files); err != nil {
			return nil, err
		}
	}
	t := a.Request.Target
	var assetType string
	if err := s.pool.QueryRow(ctx, `SELECT type FROM `+s.schema+`.assets WHERE id=$1`, a.AssetID).Scan(&assetType); err != nil {
		return nil, err
	}
	subject := map[string]any{"bom-ref": "subject", "name": t.Repository, "version": a.Commit}
	switch {
	case t.Type == "image":
		name := t.Repository[strings.LastIndex(t.Repository, "/")+1:]
		subject["type"] = "container"
		subject["purl"] = "pkg:oci/" + name + "@" + strings.Replace(a.Commit, ":", "%3A", 1) + "?repository_url=" + t.Repository + "&platform=" + strings.ReplaceAll(t.Platform, "/", "%2F")
	default:
		subject["type"] = "application"
		host := "github"
		if assetType == "gitlab_repo" {
			host = "gitlab"
		}
		subject["purl"] = "pkg:" + host + "/" + t.Repository + "@" + a.Commit
		subject["externalReferences"] = []map[string]any{{"type": "vcs", "url": t.Repository, "comment": "ref " + t.Ref}}
	}
	inputs := []map[string]any{}
	refs := []map[string]any{}
	for _, f := range files {
		if !buildDefinition(f.Path) || f.SHA256 == "" {
			continue
		}
		ref := "file:" + f.Path
		inputs = append(inputs, map[string]any{"bom-ref": ref, "type": "file", "name": f.Path, "hashes": []map[string]string{{"alg": "SHA-256", "content": f.SHA256}}})
		refs = append(refs, map[string]any{"ref": ref})
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i]["name"].(string) < inputs[j]["name"].(string) })
	properties := []map[string]string{{"name": "scrs:verdict", "value": a.Verdict}, {"name": "scrs:assessment_id", "value": a.ID.String()}, {"name": "scrs:ref", "value": t.Ref}}
	for _, st := range a.Stages {
		properties = append(properties, map[string]string{"name": "scrs:stage:" + st.Name, "value": st.Status})
	}
	tools := []map[string]any{{"type": "application", "name": "SCRS", "publisher": "SCRS"}}
	if a.SBOMSHA256 != "" {
		tools = append(tools, map[string]any{"type": "application", "name": "osv-scanner"})
	}
	for _, st := range a.Stages {
		if st.Name == "malware" && strings.HasPrefix(st.Detail, "ClamAV ") {
			tools = append(tools, map[string]any{"type": "application", "name": "ClamAV", "version": strings.SplitN(strings.TrimPrefix(st.Detail, "ClamAV "), "/", 2)[0]})
		}
		if st.Name == "import" && a.Request.Import != nil {
			tools = append(tools, map[string]any{"type": "application", "name": a.Request.Import.Tool, "version": a.Request.Import.ToolVersion})
		}
	}
	timestamp := a.CreatedAt
	if a.CompletedAt != nil {
		timestamp = *a.CompletedAt
	}
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:mbom:"+a.ID.String())).String(),
		"version":      1,
		"metadata": map[string]any{
			"timestamp":  timestamp.UTC().Format(time.RFC3339),
			"lifecycles": []map[string]string{{"phase": "build"}},
			"tools":      map[string]any{"components": tools},
			"component":  subject,
			"properties": properties,
		},
		"components": inputs,
		"formulation": []map[string]any{{
			"bom-ref":    "formula",
			"components": []map[string]any{{"bom-ref": "formula-subject", "type": subject["type"], "name": t.Repository, "version": a.Commit}},
			"workflows": []map[string]any{{
				"bom-ref":            "assessed-build",
				"uid":                a.ID.String(),
				"name":               "Declared build of " + t.Repository,
				"description":        "Build definitions and pinned inputs observed in the assessed revision. Declared, not observed: SCRS did not watch the CI run.",
				"taskTypes":          []string{"build"},
				"resourceReferences": refs,
			}},
		}},
	}
	if a.SBOMSHA256 != "" {
		doc["externalReferences"] = []map[string]any{{"type": "bom", "url": notify.Link("/assessments/" + a.ID.String() + "/sbom"), "comment": "Component SBOM for the same revision", "hashes": []map[string]string{{"alg": "SHA-256", "content": a.SBOMSHA256}}}}
	}
	return json.Marshal(doc)
}
