package advisory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nvdResponse follows the NVD CVE API 2.0 response shape.
const nvdResponse = `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{
 "id":"CVE-2021-44228","sourceIdentifier":"security@apache.org","published":"2021-12-10T10:15:09.143","lastModified":"2025-02-04T15:15:13.773","vulnStatus":"Analyzed",
 "descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints."},{"lang":"es","value":"..."}],
 "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0,"baseSeverity":"CRITICAL"}}],
  "cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:C/I:C/A:C","baseScore":9.3},"baseSeverity":"HIGH"}]},
 "weaknesses":[{"source":"security@apache.org","type":"Primary","description":[{"lang":"en","value":"CWE-917"},{"lang":"en","value":"CWE-20"}]},{"source":"nvd@nist.gov","type":"Secondary","description":[{"lang":"en","value":"CWE-917"}]}],
 "references":[{"url":"https://logging.apache.org/log4j/2.x/security.html","source":"security@apache.org","tags":["Vendor Advisory"]},{"url":"https://github.com/apache/logging-log4j2/pull/608","tags":["Patch"]}]}}]}`

const cve5Record = `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2021-44228","assignerShortName":"apache","state":"PUBLISHED","datePublished":"2021-12-10T00:00:00.000Z","dateUpdated":"2025-02-04T14:25:37.215Z"},
 "containers":{"cna":{"providerMetadata":{"shortName":"apache"},"descriptions":[{"lang":"en","value":"Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features..."}],
  "problemTypes":[{"descriptions":[{"cweId":"CWE-502","description":"CWE-502 Deserialization of Untrusted Data","lang":"en","type":"CWE"}]}],
  "metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10,"baseSeverity":"CRITICAL"}}],
  "affected":[{"vendor":"Apache Software Foundation","product":"Apache Log4j2","versions":[{"version":"2.0-beta9","lessThan":"2.15.0","status":"affected","versionType":"maven"}]}],
  "references":[{"url":"https://logging.apache.org/log4j/2.x/security.html","tags":["vendor-advisory"]}]},
 "adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-917"}]}]}]}}`

func TestNVDClientAndConversion(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		if r.Header.Get("apiKey") != "nvd-key" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Query().Get("cveId") == "CVE-2099-0001" {
			fmt.Fprint(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`)
			return
		}
		fmt.Fprint(w, nvdResponse)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL + "/rest/json/cves/2.0", APIKey: "nvd-key"}
	raw, err := client.NVDCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	r := raw.Record
	if r.ID != "CVE-2021-44228" || r.Origin != "nvd" || !strings.HasPrefix(r.Details, "Apache Log4j2") || r.Published == nil || r.Withdrawn != nil {
		t.Fatalf("record %+v", r)
	}
	if len(r.DatabaseSpecific.CVSS) != 2 || r.DatabaseSpecific.CVSS[0].BaseSeverity != "CRITICAL" || r.DatabaseSpecific.CVSS[1].BaseSeverity != "HIGH" || len(r.Severity) != 2 || r.Severity[0].Type != "CVSS_V3" {
		t.Fatalf("severity %+v %+v", r.DatabaseSpecific.CVSS, r.Severity)
	}
	if strings.Join(r.DatabaseSpecific.CWE, ",") != "CWE-20,CWE-917" || r.References[0].Type != "ADVISORY" || r.References[1].Type != "FIX" || len(raw.Source) == 0 {
		t.Fatalf("cwe/references %+v %+v", r.DatabaseSpecific.CWE, r.References)
	}
	if _, err := client.NVDCVE(context.Background(), "CVE-2099-0001"); err != ErrNotFound {
		t.Fatal("missing CVE", err)
	}
	if _, err := (Client{BaseURL: server.URL}).NVDCVE(context.Background(), "CVE-2021-44228"); err != ErrRateLimited {
		t.Fatal("keyless 403 is the NVD rate limit", err)
	}
	if _, err := client.NVDModified(context.Background(), r.Modified.AddDate(0, 0, -1), r.Modified, 0); err != nil || !strings.Contains(queries[len(queries)-1], "lastModStartDate=2025-02-03T15%3A15%3A13.773Z") {
		t.Fatal("modified window", queries, err)
	}
	rejected := strings.Replace(nvdResponse, `"Analyzed"`, `"Rejected"`, 1)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, rejected) })
	if raw, err := client.NVDCVE(context.Background(), "CVE-2021-44228"); err != nil || raw.Record.Withdrawn == nil {
		t.Fatal("rejected record not withdrawn", err)
	}
}

func TestCVE5Conversion(t *testing.T) {
	raw, err := ParseCVE5([]byte(cve5Record))
	if err != nil {
		t.Fatal(err)
	}
	r := raw.Record
	if r.Origin != "cve5" || r.DatabaseSpecific.Assigner != "apache" || strings.Join(r.DatabaseSpecific.CWE, ",") != "CWE-502,CWE-917" || len(r.DatabaseSpecific.CVSS) != 2 || r.DatabaseSpecific.CVSS[1].Source != "CISA-ADP" || len(r.Severity) != 1 || len(r.DatabaseSpecific.Affected) == 0 {
		t.Fatalf("%+v", r)
	}
	rejected := strings.Replace(cve5Record, `"PUBLISHED"`, `"REJECTED"`, 1)
	if raw, err := ParseCVE5([]byte(rejected)); err != nil || raw.Record.Withdrawn == nil {
		t.Fatal("rejected CVE not withdrawn", err)
	}
	if _, err := ParseCVE5([]byte(`{"cveMetadata":{"cveId":"nope"}}`)); err == nil {
		t.Fatal("invalid record accepted")
	}
}

func TestParseVEX(t *testing.T) {
	openvex := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme.example/vex/1","author":"Acme Security","timestamp":"2026-11-01T00:00:00Z",
 "statements":[{"vulnerability":{"name":"CVE-2021-44228"},"products":[{"@id":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path","impact_statement":"JNDI lookups disabled"},
  {"vulnerability":"CVE-2022-1","products":["pkg:npm/lodash"],"status":"fixed"},{"vulnerability":{"name":"CVE-2022-2"},"products":["x"],"status":"bogus"}]}`
	doc, err := ParseVEX([]byte(openvex))
	if err != nil || doc.Format != "openvex" || doc.Publisher != "Acme Security" || len(doc.Statements) != 2 || doc.Statements[0].Justification != "vulnerable_code_not_in_execute_path" || doc.Statements[1].PURL != "pkg:npm/lodash" || doc.IssuedAt == nil {
		t.Fatalf("openvex %+v %v", doc, err)
	}
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"supplier":{"name":"Acme"},"component":{"name":"api"}},
 "components":[{"bom-ref":"c1","purl":"pkg:npm/express@4.18.2","name":"express"},{"bom-ref":"c2","name":"internal-lib"}],
 "vulnerabilities":[{"id":"CVE-2024-29041","analysis":{"state":"false_positive","detail":"not reachable"},"affects":[{"ref":"c1"},{"ref":"c2"}]},
  {"id":"CVE-2024-1","analysis":{"state":"resolved","response":["update"]},"affects":[{"ref":"pkg:npm/qs@6.11.0"}]}]}`
	doc, err = ParseVEX([]byte(cdx))
	if err != nil || doc.Format != "cyclonedx" || len(doc.Statements) != 3 || doc.Statements[0].Status != StatusNotAffected || doc.Statements[0].PURL != "pkg:npm/express@4.18.2" || doc.Statements[1].Product != "internal-lib" || doc.Statements[2].Status != StatusFixed || doc.Statements[2].Action != "update" {
		t.Fatalf("cyclonedx %+v %v", doc, err)
	}
	csaf := `{"document":{"category":"csaf_vex","title":"Acme VEX","publisher":{"name":"Acme PSIRT"},"tracking":{"current_release_date":"2026-11-02T00:00:00Z"}},
 "product_tree":{"branches":[{"branches":[{"product":{"product_id":"P1","name":"Acme API 2.0","product_identification_helper":{"purl":"pkg:oci/acme-api@sha256:abc"}}}]}],"full_product_names":[{"product_id":"P2","name":"Acme CLI"}]},
 "vulnerabilities":[{"cve":"CVE-2023-4863","product_status":{"known_not_affected":["P1"],"known_affected":["P2"]},"flags":[{"label":"component_not_present","product_ids":["P1"]}],"remediations":[{"category":"vendor_fix","details":"upgrade to 2.1","product_ids":["P2"]}]}]}`
	doc, err = ParseVEX([]byte(csaf))
	if err != nil || doc.Format != "csaf" || doc.Publisher != "Acme PSIRT" || len(doc.Statements) != 2 || doc.Statements[0].PURL != "pkg:oci/acme-api@sha256:abc" || doc.Statements[0].Justification != "component_not_present" || doc.Statements[1].Product != "Acme CLI" || doc.Statements[1].Action != "upgrade to 2.1" {
		t.Fatalf("csaf %+v %v", doc, err)
	}
	for _, bad := range []string{`[]`, `{"bomFormat":"SPDX"}`, `{"@context":"https://openvex.dev/ns","statements":[]}`, `{"document":{"category":"csaf_base"}}`} {
		if _, err := ParseVEX([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
