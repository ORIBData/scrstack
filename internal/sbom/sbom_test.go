package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validator(t *testing.T, root string, files ...string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	var rootID string
	for _, f := range files {
		raw, err := os.ReadFile("testdata/" + f)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		id := doc.(map[string]any)["$id"].(string)
		if f == root {
			rootID = id
		}
		if err := compiler.AddResource(id, doc); err != nil {
			t.Fatal(err)
		}
	}
	compiler.AssertFormat()
	schema, err := compiler.Compile(rootID)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func sample() (Meta, []assessments.Component) {
	m := Meta{AssessmentID: uuid.MustParse("6f1c1d1e-3c55-4c7f-9a07-6a5c6e1f0001"), Asset: "acme/payments", Kind: "git", Revision: "0123456789abcdef0123456789abcdef01234567", Ref: "main", Version: "1.4.0", Generated: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	components := []assessments.Component{
		{Name: "express", Version: "4.21.2", Ecosystem: "npm", PURL: "pkg:npm/express@4.21.2", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "MIT", Source: "declared", Copyright: []string{"Copyright (c) 2009-2014 TJ Holowaychuk"}}},
		// The same package found in a second lockfile is one SBOM entry.
		{Name: "express", Version: "4.21.2", Ecosystem: "npm", PURL: "pkg:npm/express@4.21.2", Path: "web/package-lock.json"},
		{Name: "jest-util", Version: "29.0.0", Ecosystem: "npm", PURL: "pkg:npm/jest-util@29.0.0", Path: "package-lock.json", Groups: []string{"dev"}, License: &assessments.ComponentLicense{Expression: "MIT", Source: "metadata", Evidence: "deps.dev"}},
		{Name: "org.apache.commons:commons-text", Version: "1.10.0", Ecosystem: "Maven", PURL: "pkg:maven/org.apache.commons/commons-text@1.10.0", Path: "pom.xml", License: &assessments.ComponentLicense{Expression: "Apache-2.0", Source: "metadata"}},
		{Name: "agpl-thing", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/agpl-thing@1.0.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "AGPL-3.0-only OR LicenseRef-scrs-proprietary", Source: "declared"}},
		{Name: "mystery", Version: "0.1.0", Ecosystem: "npm", PURL: "pkg:npm/mystery@0.1.0", Path: "package-lock.json", License: &assessments.ComponentLicense{Expression: "LicenseRef-scrs-0123456789ab", Source: "declared", Refs: map[string]string{"LicenseRef-scrs-0123456789ab": "SEE LICENSE IN EULA.txt"}}},
		{Name: "nolicense", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/nolicense@2.0.0", Path: "package-lock.json"},
	}
	return m, components
}

// AT-26: SPDX JSON and CycloneDX JSON both pass their validators, list the
// same number of components, and the SPDX file carries licences.
func TestExportsValidateAndAgree(t *testing.T) {
	m, components := sample()
	cyclone, err := CycloneDX(m, components, false)
	if err != nil {
		t.Fatal(err)
	}
	spdx, err := SPDX(m, components)
	if err != nil {
		t.Fatal(err)
	}
	cdxSchema := validator(t, "bom-1.6.schema.json", "bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
	instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader(cyclone))
	if err := cdxSchema.Validate(instance); err != nil {
		t.Fatalf("CycloneDX invalid: %v", err)
	}
	spdxSchema := validator(t, "spdx-2.3.schema.json", "spdx-2.3.schema.json")
	instance, _ = jsonschema.UnmarshalJSON(bytes.NewReader(spdx))
	if err := spdxSchema.Validate(instance); err != nil {
		t.Fatalf("SPDX invalid: %v", err)
	}
	// The validators reject broken documents.
	broken, _ := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"bad id"}]}`)))
	if spdxSchema.Validate(broken) == nil {
		t.Fatal("SPDX validator accepted an invalid document")
	}
	broken, _ = jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"x","licenses":[{"expression":"MIT","license":{"id":"MIT"}}]}]}`)))
	if cdxSchema.Validate(broken) == nil {
		t.Fatal("CycloneDX validator accepted an invalid document")
	}
	var doc spdxDocument
	if err := json.Unmarshal(spdx, &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := len(doc.Packages)-1, ComponentCount(cyclone); got != want || want != 6 {
		t.Fatalf("SPDX packages %d, CycloneDX components %d", got, want)
	}
	byName := map[string]spdxPackage{}
	for _, p := range doc.Packages {
		byName[p.Name] = p
	}
	if p := byName["express"]; p.LicenseDeclared != "MIT" || p.LicenseConcluded != "MIT" || p.CopyrightText != "Copyright (c) 2009-2014 TJ Holowaychuk" || p.ExternalRefs[0].Locator != "pkg:npm/express@4.21.2" || p.SourceInfo != "Found in: package-lock.json, web/package-lock.json" {
		t.Fatalf("express: %+v", p)
	}
	if p := byName["jest-util"]; p.LicenseDeclared != "NOASSERTION" || p.LicenseConcluded != "MIT" {
		t.Fatalf("metadata licence is concluded, not declared: %+v", p)
	}
	if p := byName["nolicense"]; p.LicenseConcluded != "NOASSERTION" {
		t.Fatalf("no licence: %+v", p)
	}
	extracted := map[string]string{}
	for _, e := range doc.Extracted {
		extracted[e.LicenseID] = e.Text
	}
	if extracted["LicenseRef-scrs-0123456789ab"] != "SEE LICENSE IN EULA.txt" || extracted["LicenseRef-scrs-proprietary"] == "" {
		t.Fatalf("extracted licensing info: %v", extracted)
	}
	devRelations := 0
	for _, r := range doc.Relationships {
		if r.Type == "DEV_DEPENDENCY_OF" {
			devRelations++
		}
	}
	if devRelations != 1 {
		t.Fatalf("dev relationships: %d", devRelations)
	}
	var bom struct {
		Metadata struct {
			Tools struct {
				Components []struct{ Name, Version string } `json:"components"`
			} `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			Group    string `json:"group"`
			Name     string `json:"name"`
			Licenses []struct {
				Expression      string `json:"expression"`
				Acknowledgement string `json:"acknowledgement"`
			} `json:"licenses"`
		} `json:"components"`
	}
	_ = json.Unmarshal(cyclone, &bom)
	if bom.Metadata.Tools.Components[0].Name != "scrs" || bom.Metadata.Tools.Components[0].Version != "1.4.0" {
		t.Fatalf("tools: %+v", bom.Metadata.Tools)
	}
	if c := bom.Components[0]; c.Licenses[0].Expression != "MIT" || c.Licenses[0].Acknowledgement != "declared" {
		t.Fatalf("CycloneDX licence: %+v", c)
	}
	if c := bom.Components[2]; c.Group != "org.apache.commons" || c.Name != "commons-text" || c.Licenses[0].Acknowledgement != "concluded" {
		t.Fatalf("Maven component: %+v", c)
	}
	// XML: generated directly and converted from stored JSON.
	direct, err := CycloneDX(m, components, true)
	if err != nil || xml.Unmarshal(direct, new(any)) != nil || !bytes.Contains(direct, []byte(`http://cyclonedx.org/schema/bom/1.6`)) {
		t.Fatalf("XML: %v %.300s", err, direct)
	}
	converted, err := ToXML(cyclone)
	if err != nil || !bytes.Contains(converted, []byte("<expression")) {
		t.Fatalf("converted XML: %v %.300s", err, converted)
	}
	if _, err := ToXML([]byte("not json")); err == nil {
		t.Fatal("invalid stored SBOM converted")
	}
	again, _ := CycloneDX(m, components, false)
	if !bytes.Equal(again, cyclone) {
		t.Fatal("CycloneDX output not deterministic for the same assessment")
	}
}
