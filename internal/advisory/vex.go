package advisory

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Vendor and maintainer statements (VUL-009): OpenVEX, CycloneDX VEX and
// CSAF 2.0 VEX documents become one statement per vulnerability and
// product. Statements are attributed inputs; SCRS shows them beside
// findings and never closes an entry because of one.

// Statement statuses, in OpenVEX terms.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Statement is one vendor statement about a vulnerability in a product.
type Statement struct {
	Vulnerability string `json:"vulnerability"`
	PURL          string `json:"purl,omitempty"`
	Product       string `json:"product,omitempty"`
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
	Impact        string `json:"impact,omitempty"`
	Action        string `json:"action,omitempty"`
}

// Document is a parsed VEX document.
type Document struct {
	Format     string      `json:"format"`
	Publisher  string      `json:"publisher"`
	Title      string      `json:"title,omitempty"`
	IssuedAt   *time.Time  `json:"issued_at,omitempty"`
	Statements []Statement `json:"statements"`
}

// MaxVEXBytes and MaxStatements bound one document.
const (
	MaxVEXBytes   = 16 << 20
	MaxStatements = 20000
)

// ParseVEX detects the format and reads the statements.
func ParseVEX(data []byte) (Document, error) {
	if len(data) > MaxVEXBytes {
		return Document{}, errors.New("VEX document is over 16 MiB")
	}
	var probe struct {
		Context   any             `json:"@context"`
		BOMFormat string          `json:"bomFormat"`
		Document  json.RawMessage `json:"document"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return Document{}, errors.New("VEX document is not JSON")
	}
	var doc Document
	var err error
	switch {
	case strings.Contains(strings.ToLower(asString(probe.Context)), "openvex"):
		doc, err = parseOpenVEX(data)
	case probe.BOMFormat == "CycloneDX":
		doc, err = parseCycloneDXVEX(data)
	case len(probe.Document) > 0:
		doc, err = parseCSAF(data)
	default:
		return Document{}, errors.New("not an OpenVEX, CycloneDX VEX or CSAF document")
	}
	if err != nil {
		return doc, err
	}
	kept := doc.Statements[:0]
	for _, s := range doc.Statements {
		s.Vulnerability = strings.TrimSpace(s.Vulnerability)
		if s.Vulnerability == "" || len(s.Vulnerability) > 128 || (s.PURL == "" && s.Product == "") {
			continue
		}
		s.PURL, s.Product = clip(s.PURL, 1024), clip(s.Product, 512)
		s.Justification, s.Impact, s.Action = clip(s.Justification, 256), clip(s.Impact, 4096), clip(s.Action, 4096)
		kept = append(kept, s)
	}
	doc.Statements = kept
	if len(doc.Statements) == 0 {
		return doc, errors.New("VEX document has no statement naming a vulnerability and a product")
	}
	if len(doc.Statements) > MaxStatements {
		return doc, errors.New("VEX document has more than 20000 statements")
	}
	doc.Publisher, doc.Title = clip(doc.Publisher, 256), clip(doc.Title, 512)
	return doc, nil
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var parts []string
		for _, p := range t {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func timePtr(raw string) *time.Time {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		t = t.UTC()
		return &t
	}
	return nil
}

func parseOpenVEX(data []byte) (Document, error) {
	var body struct {
		Author     string `json:"author"`
		ID         string `json:"@id"`
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			Vulnerability json.RawMessage   `json:"vulnerability"`
			Products      []json.RawMessage `json:"products"`
			Status        string            `json:"status"`
			Justification string            `json:"justification"`
			Impact        string            `json:"impact_statement"`
			Action        string            `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return Document{}, errors.New("invalid OpenVEX document")
	}
	doc := Document{Format: "openvex", Publisher: body.Author, Title: body.ID, IssuedAt: timePtr(body.Timestamp)}
	for _, s := range body.Statements {
		var name string
		if json.Unmarshal(s.Vulnerability, &name) != nil {
			var v struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(s.Vulnerability, &v)
			name = v.Name
		}
		status := strings.ToLower(s.Status)
		if status != StatusNotAffected && status != StatusAffected && status != StatusFixed && status != StatusUnderInvestigation {
			continue
		}
		for _, p := range s.Products {
			var id string
			if json.Unmarshal(p, &id) != nil {
				var product struct {
					ID          string `json:"@id"`
					Identifiers struct {
						PURL string `json:"purl"`
					} `json:"identifiers"`
				}
				_ = json.Unmarshal(p, &product)
				id = firstNonEmpty(product.Identifiers.PURL, product.ID)
			}
			st := Statement{Vulnerability: name, Status: status, Justification: s.Justification, Impact: s.Impact, Action: s.Action}
			if strings.HasPrefix(id, "pkg:") {
				st.PURL = id
			} else {
				st.Product = id
			}
			doc.Statements = append(doc.Statements, st)
		}
	}
	return doc, nil
}

// cyclonedxState maps CycloneDX analysis states to statement statuses.
var cyclonedxState = map[string]string{"not_affected": StatusNotAffected, "false_positive": StatusNotAffected, "exploitable": StatusAffected, "resolved": StatusFixed, "resolved_with_pedigree": StatusFixed, "in_triage": StatusUnderInvestigation}

func parseCycloneDXVEX(data []byte) (Document, error) {
	var body struct {
		Metadata struct {
			Timestamp string `json:"timestamp"`
			Supplier  struct {
				Name string `json:"name"`
			} `json:"supplier"`
			Manufacture struct {
				Name string `json:"name"`
			} `json:"manufacture"`
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Ref  string `json:"bom-ref"`
			PURL string `json:"purl"`
			Name string `json:"name"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Detail        string   `json:"detail"`
				Response      []string `json:"response"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return Document{}, errors.New("invalid CycloneDX VEX document")
	}
	refs := map[string][2]string{}
	for _, c := range body.Components {
		refs[c.Ref] = [2]string{c.PURL, c.Name}
	}
	doc := Document{Format: "cyclonedx", Publisher: firstNonEmpty(body.Metadata.Supplier.Name, body.Metadata.Manufacture.Name), Title: body.Metadata.Component.Name, IssuedAt: timePtr(body.Metadata.Timestamp)}
	for _, v := range body.Vulnerabilities {
		status, ok := cyclonedxState[v.Analysis.State]
		if !ok {
			continue
		}
		for _, a := range v.Affects {
			st := Statement{Vulnerability: v.ID, Status: status, Justification: v.Analysis.Justification, Impact: v.Analysis.Detail, Action: strings.Join(v.Analysis.Response, ", ")}
			switch component, known := refs[a.Ref]; {
			case strings.HasPrefix(a.Ref, "pkg:"):
				st.PURL = a.Ref
			case known && component[0] != "":
				st.PURL = component[0]
			case known:
				st.Product = component[1]
			default:
				st.Product = a.Ref
			}
			doc.Statements = append(doc.Statements, st)
		}
	}
	return doc, nil
}

type csafProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    struct {
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafBranch struct {
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

func parseCSAF(data []byte) (Document, error) {
	var body struct {
		Document struct {
			Category  string `json:"category"`
			Title     string `json:"title"`
			Publisher struct {
				Name string `json:"name"`
			} `json:"publisher"`
			Tracking struct {
				Current string `json:"current_release_date"`
			} `json:"tracking"`
		} `json:"document"`
		ProductTree struct {
			Branches      []csafBranch  `json:"branches"`
			FullNames     []csafProduct `json:"full_product_names"`
			Relationships []struct {
				Product csafProduct `json:"full_product_name"`
			} `json:"relationships"`
		} `json:"product_tree"`
		Vulnerabilities []struct {
			CVE string `json:"cve"`
			IDs []struct {
				Text string `json:"text"`
			} `json:"ids"`
			Status struct {
				NotAffected   []string `json:"known_not_affected"`
				Fixed         []string `json:"fixed"`
				Affected      []string `json:"known_affected"`
				Investigation []string `json:"under_investigation"`
			} `json:"product_status"`
			Flags []struct {
				Label    string   `json:"label"`
				Products []string `json:"product_ids"`
			} `json:"flags"`
			Threats []struct {
				Category string   `json:"category"`
				Details  string   `json:"details"`
				Products []string `json:"product_ids"`
			} `json:"threats"`
			Remediations []struct {
				Details  string   `json:"details"`
				Products []string `json:"product_ids"`
			} `json:"remediations"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return Document{}, errors.New("invalid CSAF document")
	}
	if body.Document.Category != "csaf_vex" && body.Document.Category != "csaf_security_advisory" {
		return Document{}, errors.New("CSAF document category must be csaf_vex or csaf_security_advisory")
	}
	products := map[string]csafProduct{}
	var walk func([]csafBranch)
	walk = func(branches []csafBranch) {
		for _, b := range branches {
			if b.Product != nil {
				products[b.Product.ProductID] = *b.Product
			}
			walk(b.Branches)
		}
	}
	walk(body.ProductTree.Branches)
	for _, p := range body.ProductTree.FullNames {
		products[p.ProductID] = p
	}
	for _, r := range body.ProductTree.Relationships {
		products[r.Product.ProductID] = r.Product
	}
	doc := Document{Format: "csaf", Publisher: body.Document.Publisher.Name, Title: body.Document.Title, IssuedAt: timePtr(body.Document.Tracking.Current)}
	for _, v := range body.Vulnerabilities {
		id := v.CVE
		if id == "" && len(v.IDs) > 0 {
			id = v.IDs[0].Text
		}
		about := func(list []string, product string) bool {
			for _, p := range list {
				if p == product {
					return true
				}
			}
			return false
		}
		emit := func(list []string, status string) {
			for _, pid := range list {
				p := products[pid]
				st := Statement{Vulnerability: id, Status: status, PURL: p.Helper.PURL, Product: firstNonEmpty(p.Name, pid)}
				if st.PURL != "" {
					st.Product = ""
				}
				for _, f := range v.Flags {
					if about(f.Products, pid) {
						st.Justification = f.Label
					}
				}
				for _, t := range v.Threats {
					if t.Category == "impact" && about(t.Products, pid) {
						st.Impact = t.Details
					}
				}
				for _, r := range v.Remediations {
					if about(r.Products, pid) {
						st.Action = r.Details
					}
				}
				doc.Statements = append(doc.Statements, st)
			}
		}
		emit(v.Status.NotAffected, StatusNotAffected)
		emit(v.Status.Fixed, StatusFixed)
		emit(v.Status.Affected, StatusAffected)
		emit(v.Status.Investigation, StatusUnderInvestigation)
	}
	return doc, nil
}
