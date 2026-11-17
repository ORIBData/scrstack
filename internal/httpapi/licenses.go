package httpapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/buildinfo"
	"github.com/ORIBData/scrstack/internal/compliance"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/license"
	"github.com/google/uuid"
)

// licenseHandler serves licence policy (LIC-004, LIC-005), categories
// (LIC-003), inventories, reports and notices (LIC-007, LIC-009).
type licenseHandler struct{ store *assessments.Store }

func licenseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, license.ErrPolicy), errors.Is(err, license.ErrCategory), errors.Is(err, compliance.ErrPack):
		writeError(w, 400, err.Error())
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "revision is stale; read the current document and retry")
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "not found")
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid request")
	default:
		writeError(w, 500, "licence operation failed")
	}
}

// gatePolicy documents the fixed default gate (TRG-006); it is not
// configurable in this release.
var gatePolicy = map[string]any{
	"name":         "scrs-default-gate",
	"configurable": false,
	"rules": []string{
		"Malicious content (malware, malicious dependency, blocking indicator or YARA match) fails, new or existing; a waiver lowers it to warn, never pass.",
		"A new critical or high integrity entry fails; a new medium or an existing serious one warns.",
		"A new critical vulnerability fails; a new high, or an existing critical, warns.",
		"Licence entries follow the licence policy: report-only, a deny warns; enforcing, deny fails and review warns.",
		"Suspicious-dependency entries (a name that resembles a popular package, a very new release) are medium and never change the verdict; they are off until the dependency policy enables them.",
		"Hunt-mode indicators and rules, E2E QA findings and vendor statements never gate.",
		"Partial coverage makes the verdict incomplete unless something already fails.",
	},
}

func (h licenseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath)
	switch {
	case path == "/policies/gate" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"kind": "gate", "policy": gatePolicy, "builtin": true})
	case path == "/policies/license" && r.Method == http.MethodGet:
		record, err := h.store.LicensePolicy(ctx)
		if err != nil {
			licenseError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(record.Revision, 10)+`"`)
		writeJSON(w, 200, record)
	case path == "/policies/license" && r.Method == http.MethodPut:
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		expected, ok := ifMatch(w, r)
		if !ok {
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			writeError(w, 413, "policy too large")
			return
		}
		p, err := license.ParsePolicy(raw)
		if err != nil {
			licenseError(w, err)
			return
		}
		record, err := h.store.SetLicensePolicy(ctx, p, expected, principal.ID)
		if err != nil {
			licenseError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(record.Revision, 10)+`"`)
		writeJSON(w, 200, record)
	case path == "/policies/license:evaluate" && r.Method == http.MethodPost:
		h.evaluate(ctx, w, r)
	case path == "/licenses/categories" && r.Method == http.MethodGet:
		catalog, at, err := h.store.LicenseCatalog(ctx)
		if err != nil {
			licenseError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(catalog.Revision, 10)+`"`)
		writeJSON(w, 200, map[string]any{"version": catalog.Version, "source": catalog.Source, "spdx_license_list_version": license.ListVersion(), "revision": catalog.Revision, "updated_at": at, "counts": catalog.Counts(), "categories": catalog.Entries(), "overrides": catalog.Overrides, "builtin_refs": license.BuiltinRefs(), "category_names": license.CategoryNames})
	case path == "/licenses/categories" && r.Method == http.MethodPut:
		if !principal.Allows("admin") {
			writeError(w, 403, "admin scope required")
			return
		}
		expected, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var input struct {
			Overrides map[string]string `json:"overrides"`
			Note      string            `json:"note"`
		}
		if !readBody(w, r, &input) {
			return
		}
		catalog, err := h.store.SetLicenseCategories(ctx, input.Overrides, input.Note, expected, principal.ID)
		if err != nil {
			licenseError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatInt(catalog.Revision, 10)+`"`)
		writeJSON(w, 200, map[string]any{"version": catalog.Version, "revision": catalog.Revision, "overrides": catalog.Overrides, "counts": catalog.Counts()})
	case path == "/licenses/categories/history" && r.Method == http.MethodGet:
		items, err := h.store.LicenseCategoryHistory(ctx)
		if err != nil {
			licenseError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/reports/licenses" && r.Method == http.MethodGet:
		h.report(ctx, w, r)
	case strings.HasPrefix(path, "/assets/") && r.Method == http.MethodGet:
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, 404, "not found")
			return
		}
		inventory, err := h.store.AssetLicenses(ctx, id, r.URL.Query().Get("ref"))
		if err != nil {
			licenseError(w, err)
			return
		}
		if strings.HasSuffix(path, "/notices") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="THIRD-PARTY-NOTICES.txt"`)
			_, _ = w.Write(notices(inventory, r.URL.Query().Get("include_dev") == "true"))
			return
		}
		writeJSON(w, 200, inventory)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// evaluate is a dry run: it normalises an expression and decides it under
// the active policy for a distribution model, without recording anything.
func (h licenseHandler) evaluate(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var input struct {
		Expression   string     `json:"expression"`
		Distribution string     `json:"distribution"`
		AssetID      *uuid.UUID `json:"asset_id"`
		PURL         string     `json:"purl"`
		Path         string     `json:"path"`
		Dev          bool       `json:"dev"`
		// ProjectLicense, when set, adds the outbound check (LIC-005).
		ProjectLicense string `json:"project_license"`
	}
	if !readBody(w, r, &input) {
		return
	}
	if input.Distribution == "" {
		input.Distribution = license.SaaS
	}
	if !license.ValidDistribution(input.Distribution) || len(input.Expression) > 2000 || len(input.ProjectLicense) > 2000 || len(input.PURL) > 512 || len(input.Path) > 512 {
		writeError(w, 400, "distribution must be internal, saas or distributed; fields are bounded")
		return
	}
	record, err := h.store.LicensePolicy(ctx)
	if err != nil {
		licenseError(w, err)
		return
	}
	catalog, _, err := h.store.LicenseCatalog(ctx)
	if err != nil {
		licenseError(w, err)
		return
	}
	normalized := license.Normalize(input.Expression)
	subject := license.Subject{Expression: normalized.Expression, Distribution: input.Distribution, PURL: input.PURL, Path: input.Path, Dev: input.Dev}
	if input.AssetID != nil {
		subject.Asset = *input.AssetID
	}
	result := map[string]any{"normalized": normalized, "policy": record.Policy.Name, "policy_revision": record.Revision, "enforcing": record.Policy.Enforcing, "decision": record.Policy.Evaluate(catalog, subject)}
	if input.ProjectLicense != "" {
		project := license.Normalize(input.ProjectLicense).Expression
		if !license.OutboundApplies(catalog, project) {
			writeError(w, 400, "project_license must be an SPDX expression of open-source licences")
			return
		}
		result["outbound"] = license.Outbound(catalog, project, normalized.Expression)
	}
	writeJSON(w, 200, result)
}

// report serves GET /reports/licenses (LIC-007): one asset with asset_id,
// otherwise every assessed asset.
func (h licenseHandler) report(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	asset := uuid.Nil
	if raw := r.URL.Query().Get("asset_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, 400, "invalid asset_id")
			return
		}
		asset = parsed
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" && format != "md" {
		writeError(w, 400, "format must be json, csv or md")
		return
	}
	inventories, err := h.store.LicenseReport(ctx, asset)
	if err != nil {
		licenseError(w, err)
		return
	}
	generated := time.Now().UTC().Format(time.RFC3339)
	w.Header().Set("X-SCRS-Version", buildinfo.Version())
	switch format {
	case "json":
		writeJSON(w, 200, map[string]any{"generated_at": generated, "scrs_version": buildinfo.Version(), "statement": "Licence data is a policy aid, not legal advice.", "assets": inventories})
	case "csv":
		var buf bytes.Buffer
		out := csv.NewWriter(&buf)
		_ = out.Write([]string{"asset", "asset_id", "distribution", "assessment_id", "component", "version", "ecosystem", "purl", "path", "dev", "expression", "category", "source", "confidence", "policy_result", "policy_basis", "status", "waiver_until"})
		for _, inv := range inventories {
			for _, row := range inv.Items {
				until := ""
				if row.WaiverUntil != nil {
					until = row.WaiverUntil.UTC().Format(time.RFC3339)
				}
				confidence := ""
				if row.Confidence > 0 {
					confidence = strconv.FormatFloat(row.Confidence, 'f', 2, 64)
				}
				_ = out.Write([]string{csvSafe(inv.Asset), inv.AssetID.String(), inv.Distribution, row.AssessmentID.String(), csvSafe(row.Name), csvSafe(row.Version), row.Ecosystem, csvSafe(row.PURL), csvSafe(row.Path), strconv.FormatBool(row.Dev), row.Expression, row.Category, row.Source, confidence, row.Effect, row.Basis, row.Status, until})
			}
		}
		out.Flush()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="licenses.csv"`)
		_, _ = w.Write(buf.Bytes())
	case "md":
		var b strings.Builder
		fmt.Fprintf(&b, "# Licence inventory\n\nGenerated %s by SCRS %s. Licence data is a policy aid, not legal advice.\n\n", generated, buildinfo.Version())
		for _, inv := range inventories {
			fmt.Fprintf(&b, "## %s (%s)\n\nPolicy %s, %s. ", mdEscape(inv.Asset), inv.Distribution, inv.Policy, map[bool]string{true: "enforcing", false: "report-only"}[inv.Enforcing])
			fmt.Fprintf(&b, "Deny %d, review %d, allow %d.\n\n", inv.Counts[license.Deny], inv.Counts[license.Review], inv.Counts[license.Allow])
			if inv.Hint != "" {
				fmt.Fprintf(&b, "> %s\n\n", inv.Hint)
			}
			rows := append([]assessments.LicenseRow(nil), inv.Items...)
			sort.SliceStable(rows, func(i, j int) bool { return effectRank(rows[i].Effect) > effectRank(rows[j].Effect) })
			b.WriteString("| Component | Version | Licence | Category | Source | Result | Status |\n| --- | --- | --- | --- | --- | --- | --- |\n")
			for i, row := range rows {
				if i == 500 {
					fmt.Fprintf(&b, "\n%d more components; use format=csv for the full list.\n", len(rows)-500)
					break
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", mdEscape(row.Name), mdEscape(row.Version), mdEscape(row.Expression), row.Category, row.Source, row.Effect, row.Status)
			}
			b.WriteString("\n")
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	}
}

func effectRank(effect string) int {
	switch effect {
	case license.Deny:
		return 2
	case license.Review:
		return 1
	}
	return 0
}

// csvSafe stops spreadsheet formula injection from component names.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "<", "&lt;").Replace(s)
}

// notices builds a third-party notices file (LIC-009) from the licence
// data and copyright lines SCRS recorded. Development-only dependencies
// are left out unless requested; they are not shipped.
func notices(inv assessments.LicenseInventory, includeDev bool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "THIRD-PARTY SOFTWARE NOTICES\n\n%s", inv.Asset)
	if inv.Revision != "" {
		fmt.Fprintf(&b, " at %s", inv.Revision)
	}
	fmt.Fprintf(&b, "\nGenerated %s by SCRS %s.\n\n", time.Now().UTC().Format(time.RFC3339), buildinfo.Version())
	b.WriteString("This file lists the third-party components SCRS found and the licence and copyright information it recorded.\nIt is a starting point for your notices, not legal advice. Licence texts are linked from the SPDX License List.\n")
	seen := map[string]bool{}
	rows := append([]assessments.LicenseRow(nil), inv.Items...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Version < rows[j].Version
	})
	for _, row := range rows {
		key := row.Ecosystem + "\x00" + row.Name + "\x00" + row.Version
		if seen[key] || (row.Dev && !includeDev) {
			continue
		}
		seen[key] = true
		fmt.Fprintf(&b, "\n------------------------------------------------------------\n%s %s (%s)\n", row.Name, row.Version, row.Ecosystem)
		fmt.Fprintf(&b, "Licence: %s (%s)\n", row.Expression, row.Source)
		if row.License != nil {
			for _, line := range row.License.Copyright {
				fmt.Fprintf(&b, "%s\n", line)
			}
		}
		for _, id := range license.IDs(row.Expression) {
			if strings.HasPrefix(id, "LicenseRef-") {
				if row.License != nil && row.License.Refs[id] != "" {
					fmt.Fprintf(&b, "Licence text as declared: %s\n", row.License.Refs[id])
				}
				continue
			}
			fmt.Fprintf(&b, "Licence text: https://spdx.org/licenses/%s.html\n", strings.TrimSuffix(id, "+"))
		}
	}
	return []byte(b.String())
}
