package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
)

// sourceHandler manages indicator sources (TIF) with the ruleset permission
// model: write may create, import into and change hunt sources; promoting to
// alert or block, and changing a source that gates verdicts, needs admin.
type sourceHandler struct {
	store    *assessments.Store
	validate RuleValidator
	// compiles is shared with the ruleset handler to bound compiler processes.
	compiles chan struct{}
	// secrets seals TAXII credentials; taxiiHosts may resolve privately.
	secrets    Sealer
	taxiiHosts map[string]bool
}

type sourceInput struct {
	Name          string                 `json:"name"`
	Kind          string                 `json:"kind"`
	Description   string                 `json:"description"`
	Mode          string                 `json:"mode"`
	Severity      string                 `json:"severity"`
	MinConfidence int                    `json:"min_confidence"`
	Enabled       *bool                  `json:"enabled"`
	Origin        assessments.RuleOrigin `json:"origin"`
	TAXII         *taxiiInput            `json:"taxii"`
}

var (
	errEnforcingSource = errors.New("indicator sources in alert or block mode gate verdicts; admin scope required")
	errCompilerBusy    = errors.New("rule compiler busy")
)

func readSourceBody(w http.ResponseWriter, r *http.Request, value any) bool {
	// TAXII settings may carry a client certificate, key and CA bundle.
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid request body")
		return false
	}
	return true
}

func sourceError(w http.ResponseWriter, err error) {
	var compile *intelligence.RuleError
	switch {
	case errors.As(err, &compile):
		writeJSON(w, 422, map[string]any{"error": "the source's combined YARA patterns do not compile", "diagnostics": compile.Diagnostics})
	case errors.Is(err, errCompilerBusy):
		w.Header().Set("Retry-After", "5")
		writeError(w, 429, err.Error())
	case errors.Is(err, errEnforcingSource), errors.Is(err, errTAXIIAdmin):
		writeError(w, 403, err.Error())
	case errors.Is(err, errTAXIIConfig):
		writeError(w, 400, "invalid TAXII feed: "+err.Error())
	case errors.Is(err, errNoSealer):
		writeError(w, 503, err.Error())
	case errors.Is(err, assessments.ErrSourceKind):
		writeError(w, 409, "import a bundle into a manual source with PUT .../indicators, or STIX into a stix source with POST ...:import-stix")
	case errors.Is(err, assessments.ErrLinkedName):
		writeError(w, 409, err.Error())
	case errors.Is(err, assessments.ErrRulePackLimit):
		writeError(w, 422, err.Error())
	case errors.Is(err, assessments.ErrNotFound):
		writeError(w, 404, "indicator source not found")
	case errors.Is(err, assessments.ErrConflict):
		writeError(w, 409, "indicator source name exists or revision is stale; reload and retry")
	case errors.Is(err, assessments.ErrIndicatorLimit):
		writeError(w, 422, err.Error())
	case errors.Is(err, assessments.ErrInput):
		writeError(w, 400, "invalid indicator source: name is lower-case letters, digits and underscores; kind manual, stix or taxii; mode hunt, alert or block; severity critical, high, medium, low or info; min_confidence 0 to 100; origin url https")
	default:
		writeError(w, 500, "indicator source operation failed")
	}
}

func (h sourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	w.Header().Set("Cache-Control", "no-store")
	// STIX uploads may compile up to 200 YARA patterns.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	path := strings.TrimPrefix(r.URL.Path, BasePath+"/intel/indicator-sources")
	if r.Method != http.MethodGet && !principal.Allows("write") {
		writeError(w, 403, "write scope required")
		return
	}
	switch {
	case path == "" && r.Method == http.MethodGet:
		items, err := h.store.IndicatorSources(ctx)
		if err != nil {
			sourceError(w, err)
			return
		}
		feeds, err := h.store.TAXIIFeeds(ctx)
		if err != nil {
			sourceError(w, err)
			return
		}
		views := make([]sourceView, len(items))
		for n, item := range items {
			views[n].IndicatorSource = item
			if feed, ok := feeds[item.ID]; ok {
				views[n].TAXII = &feed
			}
		}
		writeJSON(w, 200, map[string]any{"items": views})
	case path == "" && r.Method == http.MethodPost:
		var input sourceInput
		if !readSourceBody(w, r, &input) {
			return
		}
		record := assessments.IndicatorSource{Name: input.Name, Kind: input.Kind, Description: input.Description, Mode: input.Mode, Severity: input.Severity, MinConfidence: input.MinConfidence, Enabled: input.Enabled == nil || *input.Enabled, Origin: input.Origin}
		if record.Kind == "" {
			record.Kind = "manual"
		}
		if record.Mode == "" {
			record.Mode = "hunt"
		}
		if record.Severity == "" {
			record.Severity = "high"
		}
		if enforcing(record.Mode) && !principal.Allows("admin") {
			sourceError(w, errEnforcingSource)
			return
		}
		if record.Kind == "taxii" || input.TAXII != nil {
			if record.Kind != "taxii" {
				sourceError(w, taxiiConfigError{"a taxii object needs kind taxii"})
				return
			}
			h.createTAXII(ctx, w, principal, record, input.TAXII)
			return
		}
		created, err := h.store.CreateIndicatorSource(ctx, record, principal.ID)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, created.Revision))
		w.Header().Set("Location", BasePath+"/intel/indicator-sources/"+created.ID.String())
		writeJSON(w, 201, created)
	case strings.HasPrefix(path, "/"):
		rest := strings.TrimPrefix(path, "/")
		idPart, sub, _ := strings.Cut(rest, "/")
		idPart, action, _ := strings.Cut(idPart, ":")
		id, err := uuid.Parse(idPart)
		if err != nil || (sub != "" && ((sub != "indicators" && sub != "taxii") || action != "")) {
			writeError(w, 404, "indicator source not found")
			return
		}
		if sub != "" {
			action = sub
		}
		if action == "taxii" || action == "poll" || action == "test" {
			h.taxiiItem(ctx, w, r, principal, id, action)
			return
		}
		h.item(ctx, w, r, principal, id, action)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h sourceHandler) item(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, action string) {
	allowed := func(before, after assessments.IndicatorSource) error {
		if before.Kind == "taxii" && !principal.Allows("admin") {
			return errTAXIIAdmin
		}
		if (enforcing(before.Mode) || enforcing(after.Mode)) && !principal.Allows("admin") {
			return errEnforcingSource
		}
		return nil
	}
	same := func(record assessments.IndicatorSource) error { return allowed(record, record) }
	switch {
	case action == "" && r.Method == http.MethodGet:
		record, err := h.store.IndicatorSourceByID(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		view := sourceView{IndicatorSource: record}
		if record.Kind == "taxii" {
			feed, err := h.store.TAXIIFeedFor(ctx, id)
			if err != nil {
				sourceError(w, err)
				return
			}
			view.TAXII = &feed
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, record.Revision))
		writeJSON(w, 200, view)
	case action == "" && r.Method == http.MethodPatch:
		revision, ok := ifMatch(w, r)
		if !ok {
			return
		}
		var change assessments.IndicatorSourceChange
		if !readSourceBody(w, r, &change) {
			return
		}
		updated, err := h.store.UpdateIndicatorSource(ctx, id, revision, change, principal.ID, allowed)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
		writeJSON(w, 200, updated)
	case action == "" && r.Method == http.MethodDelete:
		if err := h.store.DeleteIndicatorSource(ctx, id, principal.ID, same); err != nil {
			sourceError(w, err)
			return
		}
		w.WriteHeader(204)
	case action == "indicators" && r.Method == http.MethodGet:
		bundle, err := h.store.SourceIndicators(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		writeJSON(w, 200, bundle)
	case action == "indicators" && r.Method == http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, intelligence.MaxImportBytes))
		if err != nil {
			writeError(w, 413, "indicator bundle too large")
			return
		}
		bundle, err := intelligence.Parse(body)
		if err != nil {
			writeError(w, 400, "invalid indicator bundle: "+err.Error())
			return
		}
		updated, err := h.store.ImportSourceIndicators(ctx, id, bundle, principal.ID, same)
		if err != nil {
			sourceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
		writeJSON(w, 200, updated)
	case action == "import-stix" && r.Method == http.MethodPost:
		h.importSTIX(ctx, w, r, principal, id, same)
	case action == "import-csv" && r.Method == http.MethodPost:
		h.importCSV(ctx, w, r, principal, id, same)
	case action == "hunt" && r.Method == http.MethodPost:
		// Retro-hunt: rescan the default branch of every in-scope repository
		// so the source's indicators are checked against current code.
		record, err := h.store.IndicatorSourceByID(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		if !record.Enabled {
			writeError(w, 409, "enable the indicator source before hunting")
			return
		}
		queued, err := h.store.EnqueueRescans(ctx, 0, 500)
		if err != nil {
			assessmentError(w, err)
			return
		}
		writeJSON(w, 202, map[string]int{"rescans_queued": queued})
	default:
		writeError(w, 405, "method not allowed")
	}
}

// importSTIX stores a STIX 2.1 bundle in a stix source. Query merge=true keeps
// indicators from objects the bundle does not mention; valid_days (default
// 180) sets the expiry of indicators without valid_until.
func (h sourceHandler) importSTIX(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, allowed func(assessments.IndicatorSource) error) {
	query := r.URL.Query()
	merge := query.Get("merge") == "true"
	if m := query.Get("merge"); m != "" && m != "true" && m != "false" {
		writeError(w, 400, "merge is true or false")
		return
	}
	days := 180
	if v := query.Get("valid_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			writeError(w, 400, "valid_days is 1 to 3650")
			return
		}
		days = n
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, intelligence.MaxSTIXBytes))
	if err != nil {
		writeError(w, 413, "STIX bundle too large")
		return
	}
	imp, err := intelligence.ParseSTIX(body, time.Now(), time.Duration(days)*24*time.Hour)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	// Check each YARA pattern alone so one bad rule is reported, not fatal.
	if len(imp.Yara) > 0 {
		if !h.acquire() {
			sourceError(w, errCompilerBusy)
			return
		}
		err := imp.CheckYara(ctx, func(ctx context.Context, rules string) error {
			_, err := h.validate(ctx, rules)
			return err
		})
		h.release()
		if err != nil {
			writeError(w, 500, "YARA compiler failed")
			return
		}
	}
	compile := func(ctx context.Context, rules string) error {
		if !h.acquire() {
			return errCompilerBusy
		}
		defer h.release()
		_, err := h.validate(ctx, rules)
		return err
	}
	source, outcome, err := h.store.ImportSTIX(ctx, id, imp, merge, principal.ID, allowed, compile)
	if err != nil {
		sourceError(w, err)
		return
	}
	// Patterns left out of the combined ruleset; with merge they may come
	// from earlier uploads, so yara_patterns still counts this upload's.
	for _, skip := range outcome.Skipped {
		imp.Report.Skip(skip.ID, skip.Reason, "left out of the combined ruleset")
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, source.Revision))
	writeJSON(w, 200, map[string]any{"source": source, "report": imp.Report, "yara_ruleset": outcome.RuleSet})
}

func (h sourceHandler) acquire() bool {
	select {
	case h.compiles <- struct{}{}:
		return true
	default:
		return false
	}
}

func (h sourceHandler) release() { <-h.compiles }

// importCSV loads indicators from CSV into a manual source (TIF-005). Query
// parameters map columns (value_column, type_column, first_seen_column,
// confidence_column, label_column, valid_until_column), set a default type,
// valid_days (default 180) and delimiter (comma, tab or semicolon).
// merge=true keeps the source's other indicators; otherwise the CSV
// replaces them.
func (h sourceHandler) importCSV(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, allowed func(assessments.IndicatorSource) error) {
	query := r.URL.Query()
	o := intelligence.CSVOptions{Mapping: intelligence.CSVMapping{Value: query.Get("value_column"), Type: query.Get("type_column"), FirstSeen: query.Get("first_seen_column"), Confidence: query.Get("confidence_column"), Label: query.Get("label_column"), ValidUntil: query.Get("valid_until_column")}, DefaultType: query.Get("type"), ValidDays: 180}
	if v := query.Get("valid_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			writeError(w, 400, "valid_days is 1 to 3650")
			return
		}
		o.ValidDays = n
	}
	switch query.Get("delimiter") {
	case "", "comma":
	case "tab":
		o.Comma = '\t'
	case "semicolon":
		o.Comma = ';'
	default:
		writeError(w, 400, "delimiter is comma, tab or semicolon")
		return
	}
	merge := query.Get("merge") == "true"
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, intelligence.MaxImportBytes))
	if err != nil {
		writeError(w, 413, "CSV is over 16 MiB")
		return
	}
	bundle, report, err := intelligence.ParseCSV(body, o)
	if err != nil {
		writeError(w, 400, "invalid CSV: "+err.Error())
		return
	}
	if merge {
		existing, err := h.store.SourceIndicators(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		replaced := map[string]bool{}
		for _, i := range bundle.Indicators {
			replaced[i.ID] = true
		}
		for _, i := range existing.Indicators {
			if !replaced[i.ID] {
				i.Source, i.Mode, i.Severity = "", "", ""
				bundle.Indicators = append(bundle.Indicators, i)
			}
		}
		if len(bundle.Indicators) > intelligence.MaxImportIndicators {
			writeError(w, 422, "the merged source would hold more than 50000 indicators")
			return
		}
	}
	updated, err := h.store.ImportSourceIndicators(ctx, id, bundle, principal.ID, allowed)
	if err != nil {
		sourceError(w, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, updated.Revision))
	writeJSON(w, 200, map[string]any{"source": updated, "report": report, "merged": merge})
}
