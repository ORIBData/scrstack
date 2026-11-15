// Package sbom generates SBOM documents from SCRS's own component model:
// CycloneDX 1.6 JSON and XML (SBM-001, via cyclonedx-go) and SPDX 2.3 JSON
// (SBM-010). Both formats list the same packages, so their component counts
// agree (AT-26).
package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/license"
	"github.com/google/uuid"
)

// Formats are the export formats of SBM-011.
var Formats = []string{"cyclonedx-json", "cyclonedx-xml", "spdx-json"}

// ContentType returns the media type of an export format.
func ContentType(format string) string {
	switch format {
	case "cyclonedx-xml":
		return "application/vnd.cyclonedx+xml"
	case "spdx-json":
		return "application/spdx+json"
	}
	return "application/vnd.cyclonedx+json"
}

// Meta describes the assessed revision a document is about.
type Meta struct {
	AssessmentID uuid.UUID
	// Asset is the repository path or image locator; Kind "git" or "image".
	Asset, Kind string
	// Revision is the commit or image digest; Ref the branch, tag or PR.
	Revision, Ref string
	Version       string
	Generated     time.Time
}

// Package is one SBOM entry: a component identity with every path it was
// found at.
type Package struct {
	assessments.Component
	Paths []string
}

// Packages groups components by package URL (one entry per identity),
// keeping first-seen order.
func Packages(components []assessments.Component) []Package {
	index := map[string]int{}
	out := []Package{}
	for _, c := range components {
		key := c.PURL
		if key == "" {
			key = c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version
		}
		if i, ok := index[key]; ok {
			if !contains(out[i].Paths, c.Path) && c.Path != "" {
				out[i].Paths = append(out[i].Paths, c.Path)
			}
			// A package that is a runtime dependency anywhere is not dev-only.
			if !c.Dev() {
				out[i].Groups = nil
			}
			if out[i].License == nil && c.License != nil {
				out[i].License = c.License
			}
			continue
		}
		index[key] = len(out)
		p := Package{Component: c}
		if c.Path != "" {
			p.Paths = []string{c.Path}
		}
		out = append(out, p)
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func serial(m Meta, format string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:"+format+":"+m.AssessmentID.String()+":"+m.Revision)).String()
}

// CycloneDX builds a CycloneDX 1.6 document (JSON or XML).
func CycloneDX(m Meta, components []assessments.Component, xml bool) ([]byte, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + serial(m, "cyclonedx")
	rootType := cdx.ComponentTypeApplication
	if m.Kind == "image" {
		rootType = cdx.ComponentTypeContainer
	}
	root := cdx.Component{BOMRef: "scrs-asset", Type: rootType, Name: m.Asset, Version: m.Revision}
	if m.Ref != "" {
		root.Properties = &[]cdx.Property{{Name: "scrs:ref", Value: m.Ref}}
	}
	bom.Metadata = &cdx.Metadata{
		Timestamp: m.Generated.UTC().Format(time.RFC3339),
		Tools:     &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "scrs", Version: m.Version, Publisher: "SCRS"}}},
		Component: &root,
		Properties: &[]cdx.Property{
			{Name: "scrs:assessment_id", Value: m.AssessmentID.String()},
			{Name: "scrs:generated_at", Value: m.Generated.UTC().Format(time.RFC3339)},
			{Name: "scrs:version", Value: m.Version},
		},
	}
	list := []cdx.Component{}
	refs := []string{}
	for _, p := range Packages(components) {
		c := cdx.Component{BOMRef: p.PURL, Type: cdx.ComponentTypeLibrary, Name: p.Name, Version: p.Version, PackageURL: p.PURL}
		if c.BOMRef == "" {
			c.BOMRef = "scrs-" + shortHash(p.Ecosystem+p.Name+p.Version)
		}
		if p.Ecosystem == "Maven" {
			if group, artifact, ok := strings.Cut(p.Name, ":"); ok {
				c.Group, c.Name = group, artifact
			}
		}
		if l := p.License; l != nil && l.Expression != license.NoAssertion && l.Expression != "" {
			ack := cdx.LicenseAcknowledgementConcluded
			if l.Source == "declared" {
				ack = cdx.LicenseAcknowledgementDeclared
			}
			// The expression form accepts every SPDX id and LicenseRef; the
			// id form is limited to the licence list CycloneDX 1.6 shipped.
			c.Licenses = &cdx.Licenses{{Expression: l.Expression, Acknowledgement: &ack}}
			if len(l.Copyright) > 0 {
				c.Copyright = strings.Join(l.Copyright, "\n")
			}
		}
		props := []cdx.Property{{Name: "scrs:ecosystem", Value: p.Ecosystem}}
		if p.Dev() {
			props = append(props, cdx.Property{Name: "scrs:dependency_group", Value: "dev"})
		}
		if l := p.License; l != nil {
			props = append(props, cdx.Property{Name: "scrs:license_source", Value: l.Source})
			if l.Confidence > 0 {
				props = append(props, cdx.Property{Name: "scrs:license_confidence", Value: fmt.Sprintf("%.2f", l.Confidence)})
			}
		}
		c.Properties = &props
		if len(p.Paths) > 0 {
			occurrences := make([]cdx.EvidenceOccurrence, len(p.Paths))
			for i, path := range p.Paths {
				occurrences[i] = cdx.EvidenceOccurrence{Location: path}
			}
			c.Evidence = &cdx.Evidence{Occurrences: &occurrences}
		}
		list = append(list, c)
		refs = append(refs, c.BOMRef)
	}
	bom.Components = &list
	bom.Dependencies = &[]cdx.Dependency{{Ref: "scrs-asset", Dependencies: &refs}}
	return encode(bom, xml)
}

func encode(bom *cdx.BOM, xml bool) ([]byte, error) {
	var buf bytes.Buffer
	format := cdx.BOMFileFormatJSON
	if xml {
		format = cdx.BOMFileFormatXML
	}
	if err := cdx.NewBOMEncoder(&buf, format).SetPretty(false).EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ToXML converts a stored CycloneDX JSON document to XML.
func ToXML(document []byte) ([]byte, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(document), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, errors.New("stored SBOM is not valid CycloneDX JSON")
	}
	version := bom.SpecVersion
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatXML).SetPretty(false).EncodeVersion(&bom, version); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ComponentCount returns the number of components in a CycloneDX JSON
// document.
func ComponentCount(document []byte) int {
	var bom struct {
		Components []json.RawMessage `json:"components"`
	}
	if json.Unmarshal(document, &bom) != nil {
		return -1
	}
	return len(bom.Components)
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

var spdxIDUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// SPDX document types (SPDX 2.3 JSON).
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreation       `json:"creationInfo"`
	Comment           string             `json:"comment,omitempty"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
	Extracted         []spdxExtracted    `json:"hasExtractedLicensingInfos,omitempty"`
}

type spdxCreation struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
}

type spdxPackage struct {
	SPDXID           string       `json:"SPDXID"`
	Name             string       `json:"name"`
	VersionInfo      string       `json:"versionInfo,omitempty"`
	DownloadLocation string       `json:"downloadLocation"`
	FilesAnalyzed    bool         `json:"filesAnalyzed"`
	LicenseConcluded string       `json:"licenseConcluded"`
	LicenseDeclared  string       `json:"licenseDeclared"`
	CopyrightText    string       `json:"copyrightText"`
	SourceInfo       string       `json:"sourceInfo,omitempty"`
	Comment          string       `json:"comment,omitempty"`
	Purpose          string       `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs     []spdxExtRef `json:"externalRefs,omitempty"`
}

type spdxExtRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type spdxExtracted struct {
	LicenseID string `json:"licenseId"`
	Text      string `json:"extractedText"`
	Name      string `json:"name,omitempty"`
}

// SPDX builds an SPDX 2.3 JSON document from the component model (SBM-010),
// with declared and concluded licences and package URLs.
func SPDX(m Meta, components []assessments.Component) ([]byte, error) {
	name := m.Asset
	if m.Revision != "" {
		name += "@" + m.Revision
	}
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "https://spdx.org/spdxdocs/scrs-" + strings.Trim(spdxIDUnsafe.ReplaceAllString(m.Asset, "-"), "-") + "-" + serial(m, "spdx"),
		CreationInfo:      spdxCreation{Created: m.Generated.UTC().Format(time.RFC3339), Creators: []string{"Tool: scrs-" + m.Version}, LicenseListVersion: license.ListVersion()},
		Comment:           "Generated by SCRS from assessment " + m.AssessmentID.String() + ". Licence data is a policy aid, not legal advice.",
		Packages:          []spdxPackage{},
		Relationships:     []spdxRelationship{},
	}
	purpose := "APPLICATION"
	if m.Kind == "image" {
		purpose = "CONTAINER"
	}
	doc.Packages = append(doc.Packages, spdxPackage{SPDXID: "SPDXRef-Asset", Name: m.Asset, VersionInfo: m.Revision, DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Purpose: purpose})
	doc.Relationships = append(doc.Relationships, spdxRelationship{Element: "SPDXRef-DOCUMENT", Type: "DESCRIBES", Related: "SPDXRef-Asset"})
	extracted := map[string]string{}
	for i, p := range Packages(components) {
		id := fmt.Sprintf("SPDXRef-Package-%d-%s", i+1, shortHash(p.PURL + p.Name + p.Version)[:8])
		pkg := spdxPackage{SPDXID: id, Name: p.Name, VersionInfo: p.Version, DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Purpose: "LIBRARY"}
		if pkg.Name == "" {
			pkg.Name = "unnamed"
		}
		if p.PURL != "" {
			pkg.ExternalRefs = []spdxExtRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: p.PURL}}
		}
		if len(p.Paths) > 0 {
			pkg.SourceInfo = "Found in: " + strings.Join(p.Paths, ", ")
		}
		if l := p.License; l != nil && l.Expression != "" && l.Expression != license.NoAssertion {
			if _, err := license.Parse(l.Expression); err == nil {
				pkg.LicenseConcluded = l.Expression
				if l.Source == "declared" {
					pkg.LicenseDeclared = l.Expression
				}
				for _, ref := range license.IDs(l.Expression) {
					if strings.HasPrefix(ref, "LicenseRef-") {
						text := l.Refs[ref]
						if text == "" {
							if info, ok := license.Lookup(ref); ok {
								text = info.Name
							} else {
								text = "Licence text not recorded by SCRS"
							}
						}
						extracted[ref] = text
					}
				}
				pkg.Comment = "SCRS licence source: " + l.Source
				if l.Confidence > 0 {
					pkg.Comment += fmt.Sprintf(" (confidence %.2f)", l.Confidence)
				}
				if l.Evidence != "" {
					pkg.Comment += "; evidence: " + l.Evidence
				}
			}
			if len(l.Copyright) > 0 {
				pkg.CopyrightText = strings.Join(l.Copyright, "\n")
			}
		}
		doc.Packages = append(doc.Packages, pkg)
		relation := spdxRelationship{Element: "SPDXRef-Asset", Type: "DEPENDS_ON", Related: id}
		if p.Dev() {
			relation = spdxRelationship{Element: id, Type: "DEV_DEPENDENCY_OF", Related: "SPDXRef-Asset"}
		}
		doc.Relationships = append(doc.Relationships, relation)
	}
	refs := make([]string, 0, len(extracted))
	for ref := range extracted {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		e := spdxExtracted{LicenseID: ref, Text: extracted[ref]}
		if info, ok := license.Lookup(ref); ok {
			e.Name = info.Name
		}
		doc.Extracted = append(doc.Extracted, e)
	}
	return json.Marshal(doc)
}
