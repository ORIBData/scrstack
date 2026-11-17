package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/actionscheck"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/sast"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type TokenStore interface {
	Authenticate(context.Context, string, netip.Addr) (connections.Token, error)
	CreateToken(context.Context, connections.Token, uuid.UUID) (connections.Token, string, error)
	Tokens(context.Context, uuid.UUID, int) ([]connections.Token, error)
	RevokeToken(context.Context, uuid.UUID, uuid.UUID) error
}
type principalKey struct{}
type Security struct {
	// ActionsAPI reads GitHub Actions inventories; nil uses GitHub itself (tests only).
	ActionsAPI          actionscheck.API
	GitHubWebhookSecret string
	RemediationEnabled  bool
	RelayEnabled        bool
	Assessments         *assessments.Store
	Artifacts           interface {
		GetSBOM(context.Context, string) ([]byte, error)
	}
	// Mirrors opens stored git bundles; nil disables bundle download.
	Mirrors    MirrorReader
	Notify     *notify.Store
	Logger     *slog.Logger
	Store      TokenStore
	Redis      *redis.Client
	DocsPublic bool
	// DocsDisabled removes the Swagger UI and the OpenAPI document
	// (SCRS_SWAGGER_DOCS_ENABLE=false): every /docs path is then answered
	// like an unknown route, with or without a token.
	DocsDisabled   bool
	TrustedProxies []netip.Prefix
	Origins        []string
	// GitHubHooks overrides the GitHub API for the delivery check; tests only.
	GitHubHooks connections.HookAPI
	// ValidateRules overrides the YARA-X compiler; tests only.
	ValidateRules RuleValidator
	// Secrets seals TAXII credentials; when nil, the connection store is used.
	Secrets Sealer
	// TAXIIPrivateHosts may resolve to private addresses (SCRS_TAXII_PRIVATE_HOSTS).
	TAXIIPrivateHosts map[string]bool
	// QAReports opens stored Karate reports; QARunner, when set, answers
	// GET /qa/runner. LLMPrivateHosts may resolve to private addresses
	// (SCRS_LLM_PRIVATE_HOSTS, self-hosted models).
	QAReports       QAReportReader
	QARunner        *qa.Runner
	LLMPrivateHosts map[string]bool
	// LLMAllowSource is the platform switch that lets an acknowledged hosted
	// provider receive source code (SCRS_LLM_ALLOW_SOURCE_TO_HOSTED).
	LLMAllowSource bool
	// SAST is the scrs-sast service client (M9); SASTDefaults are the
	// deployment defaults for SAST and reachability.
	SAST         *sast.Client
	SASTDefaults assessments.SASTDefaults
	// Live fans committed events out to GET /events streams (OUT-004);
	// nil answers 503.
	Live *notify.Hub
	// Status serves GET /system/status; nil leaves the route unregistered.
	Status *PlatformStatus
	// DTrackPrivateHosts may be internal Dependency-Track servers
	// (SCRS_DTRACK_PRIVATE_HOSTS); DTrackHTTP overrides the guarded client
	// (tests only).
	DTrackPrivateHosts map[string]bool
	DTrackHTTP         *http.Client
}

var tokenWindow = redis.NewScript(`
local t=redis.call('TIME')
local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-60000)
if redis.call('ZCARD',KEYS[1])>=120 then return 0 end
redis.call('ZADD',KEYS[1],now,ARGV[1])
redis.call('PEXPIRE',KEYS[1],60000)
return 1`)

func HandlerWithSecurity(check func(context.Context) error, store ConnectionStore, security Security) http.Handler {
	mux := routeMux{http.NewServeMux()}
	mux.HandleFunc("GET "+BasePath+"/system/healthz", health)
	mux.Handle("GET "+BasePath+"/system/readyz", readiness(check))
	// Reuse the embedded docs-only mux; protect all its assets consistently.
	// Disabled docs are not routed at all, so they 404 like any unknown path.
	if !security.DocsDisabled {
		docsHandler := Handler()
		if !security.DocsPublic {
			docsHandler = security.protect("", docsHandler)
		}
		mux.Handle(BasePath+"/docs", docsHandler)
		mux.Handle(BasePath+"/docs/", docsHandler)
	}
	handler := connectionHandler{store: store, providerSlots: make(chan struct{}, 4)}
	mux.Handle(BasePath+"/connections", security.protect("admin", handler))
	mux.Handle(BasePath+"/connections/", security.protect("admin", handler))
	mux.Handle("GET "+BasePath+"/assets", security.protect("read", handler))
	if security.Status != nil {
		mux.Handle("GET "+BasePath+"/system/status", security.protect("read|write", security.Status.Handler()))
	}
	m := newMetrics(security.Assessments, security.Notify)
	mux.Handle("GET "+BasePath+"/system/metrics", security.protect("read", m.handler()))
	if checker, ok := store.(hookChecker); ok {
		api := security.GitHubHooks
		if api == nil {
			api = connections.NewNativeAdapters()
		}
		hooks := hookHandler{store: checker, api: api}
		mux.Handle("GET "+BasePath+"/system/github-webhooks", security.protect("read", hooks))
		mux.Handle("POST "+BasePath+"/system/github-webhooks:check", security.protect("admin", hooks))
	}
	if cs, ok := store.(*connections.Store); ok && security.Assessments != nil {
		var api actionscheck.API = security.ActionsAPI
		if api == nil {
			api = connections.NewNativeAdapters()
		}
		actions := actionsHandler{checker: actionscheck.Checker{Connections: cs, Store: security.Assessments, API: api}, slots: make(chan struct{}, 4)}
		mux.Handle("GET "+BasePath+"/assets/{id}/actions", security.protect("read|write", actions))
		mux.Handle("POST "+BasePath+"/assets/{id}/actions:check", security.protect("write", actions))
	}
	if uploads, ok := store.(uploadAssets); ok && security.Assessments != nil {
		handler := uploadHandler{assets: uploads, store: security.Assessments, artifacts: security.Artifacts}
		mux.Handle("POST "+BasePath+"/uploads", security.protect("write", handler))
		mux.Handle("GET "+BasePath+"/assets/{id}/uploads", security.protect("read|write", handler))
		mux.Handle("DELETE "+BasePath+"/assets/{id}/uploads/{upload}", security.protect("admin", handler))
	}
	if admin, ok := store.(assetAdmin); ok {
		assetsHandler := assetHandler{store: admin}
		if security.Assessments != nil {
			assetsHandler.uploads = security.Assessments
		}
		mux.Handle("GET "+BasePath+"/owners", security.protect("read|write", assetsHandler))
		mux.Handle("POST "+BasePath+"/owners", security.protect("write", assetsHandler))
		mux.Handle("PATCH "+BasePath+"/owners/{id}", security.protect("write", assetsHandler))
		mux.Handle("GET "+BasePath+"/assets/{id}", security.protect("read|write", assetsHandler))
		mux.Handle("PATCH "+BasePath+"/assets/{id}", security.protect("write", assetsHandler))
		mux.Handle("DELETE "+BasePath+"/assets/{id}", security.protect("admin", assetsHandler))
		mux.Handle("POST "+BasePath+"/assets", security.protect("write", assetsHandler))
		mux.Handle("POST "+BasePath+"/assets:import", security.protect("write", assetsHandler))
	}
	mux.Handle(BasePath+"/tokens", security.protect("admin", http.HandlerFunc(security.tokens)))
	mux.Handle(BasePath+"/tokens/", security.protect("admin", http.HandlerFunc(security.tokens)))
	if security.Notify != nil {
		subscriptions := security.protect("admin", subscriptionHandler{security.Notify})
		mux.Handle(BasePath+"/webhooks", subscriptions)
		mux.Handle(BasePath+"/webhooks/", subscriptions)
	}
	if security.Assessments != nil {
		for _, path := range []string{"/settings/retention", "/settings/retention:preview", "/settings/retention:purge"} {
			mux.Handle(BasePath+path, security.protect("admin", retentionHandler(security.Assessments)))
		}
		ingest := newGitHubIngest(security.Assessments, security.GitHubWebhookSecret, security.RemediationEnabled, security.RelayEnabled)
		hooks, _ := store.(webhookStore)
		ingest.hooks = hooks
		mux.Handle("POST "+BasePath+"/webhooks/github", ingest.direct("github"))
		// ING-001/TRG-002: one provider endpoint, two entry modes. A bearer
		// token selects relay mode (which also verifies a forwarded provider
		// signature); otherwise the provider's own authentication applies.
		// /ingest/<provider>/<connection> uses that connection's secret.
		for _, provider := range []string{"github", "gitlab"} {
			direct, relay := ingest.direct(provider), security.protect("ingest:relay", ingest.relay(provider))
			both := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					relay.ServeHTTP(w, r)
					return
				}
				direct.ServeHTTP(w, r)
			})
			mux.Handle("POST "+BasePath+"/ingest/"+provider, both)
			mux.Handle("POST "+BasePath+"/ingest/"+provider+"/{connection}", both)
		}
		validate := security.ValidateRules
		if validate == nil {
			validate = yaraValidator()
		}
		compiles := make(chan struct{}, 2)
		rules := security.protect("read|write", ruleHandler{store: security.Assessments, validate: validate, compiles: compiles})
		for _, path := range []string{"/intel/yara-rulesets", "/intel/yara-rulesets:validate", "/intel/yara-rulesets/"} {
			mux.Handle(BasePath+path, rules)
		}
		secrets := security.Secrets
		if sealer, ok := store.(Sealer); ok && secrets == nil {
			secrets = sealer
		}
		dtrackAPI := security.protect("read|write", dtrackHandler{store: security.Assessments, secrets: secrets, hosts: security.DTrackPrivateHosts, client: security.DTrackHTTP})
		mux.Handle("GET "+BasePath+"/integrations/dependency-track", dtrackAPI)
		mux.Handle("PUT "+BasePath+"/integrations/dependency-track", dtrackAPI)
		mux.Handle("POST "+BasePath+"/integrations/dependency-track:test", dtrackAPI)
		mux.Handle("GET "+BasePath+"/integrations/dependency-track/uploads", dtrackAPI)
		mux.Handle("POST "+BasePath+"/integrations/dependency-track/uploads/{id}/retry", dtrackAPI)
		mux.Handle("GET "+BasePath+"/integrations/dependency-track/findings", dtrackAPI)
		mux.Handle("POST "+BasePath+"/integrations/dependency-track:sync", dtrackAPI)
		sources := security.protect("read|write", sourceHandler{store: security.Assessments, validate: validate, compiles: compiles, secrets: secrets, taxiiHosts: security.TAXIIPrivateHosts})
		mux.Handle(BasePath+"/intel/indicator-sources", sources)
		mux.Handle(BasePath+"/intel/indicator-sources/", sources)
		vulns := security.protect("read|write", vulnHandler{security.Assessments})
		for _, path := range []string{"/intel/vulnerability-sources", "/intel/vulnerability-sources/", "/intel/vulnerabilities/", "/intel/vex-documents", "/intel/vex-documents/", "/intel/vex-statements"} {
			mux.Handle(BasePath+path, vulns)
		}
		advisories := security.protect("read|write", advisoryHandler{security.Assessments})
		mux.Handle(BasePath+"/advisories", advisories)
		mux.Handle(BasePath+"/advisories/", advisories)
		mux.Handle("POST "+BasePath+"/ingest/registry/{provider}", security.protect("ingest:relay", registryIngest{store: security.Assessments, relayEnabled: security.RelayEnabled}))
		// A registry connection's own receiver, authenticated by its webhook secret.
		mux.Handle("POST "+BasePath+"/ingest/registry/{provider}/{connection}", registryIngest{store: security.Assessments, hooks: hooks})
		mux.Handle(BasePath+"/feeds/indicators", security.protect("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			if r.Method == "GET" {
				body, err := security.Assessments.ActiveIndicators(ctx)
				if err != nil {
					assessmentError(w, err)
					return
				}
				if len(body) == 0 {
					writeError(w, 404, "no active indicators")
					return
				}
				writeJSON(w, 200, body)
				return
			}
			if r.Method != "PUT" {
				writeError(w, 405, "method not allowed")
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeError(w, 413, "indicator bundle too large")
				return
			}
			actor := r.Context().Value(principalKey{}).(connections.Token)
			version, err := security.Assessments.ImportIndicators(ctx, actor.ID, body)
			if err != nil {
				assessmentError(w, err)
				return
			}
			writeJSON(w, 201, map[string]string{"version": version})
		})))
		// M8: licences, SBOM exports and compliance evidence reports.
		licenses := security.protect("read|write", licenseHandler{security.Assessments})
		mux.Handle("GET "+BasePath+"/policies/gate", licenses)
		mux.Handle("GET "+BasePath+"/policies/license", licenses)
		mux.Handle("PUT "+BasePath+"/policies/license", licenses)
		mux.Handle("POST "+BasePath+"/policies/license:evaluate", licenses)
		mux.Handle("GET "+BasePath+"/licenses/categories", licenses)
		mux.Handle("PUT "+BasePath+"/licenses/categories", licenses)
		mux.Handle("GET "+BasePath+"/licenses/categories/history", licenses)
		mux.Handle("GET "+BasePath+"/reports/licenses", licenses)
		mux.Handle("GET "+BasePath+"/assets/{id}/licenses", licenses)
		mux.Handle("GET "+BasePath+"/assets/{id}/licenses/notices", licenses)
		mux.Handle("GET "+BasePath+"/events", security.protect("read|write", eventStream{hub: security.Live, lifetime: streamLifetime}))
		reports := security.protect("read|write", reportHandler{store: security.Assessments, artifacts: security.Artifacts})
		mux.Handle("GET "+BasePath+"/reports/frameworks", reports)
		mux.Handle("POST "+BasePath+"/reports/frameworks", reports)
		mux.Handle("POST "+BasePath+"/reports/frameworks/stig", reports)
		mux.Handle("GET "+BasePath+"/frameworks/{id}", reports)
		mux.Handle("DELETE "+BasePath+"/frameworks/{id}", reports)
		mux.Handle("GET "+BasePath+"/reports", reports)
		mux.Handle("POST "+BasePath+"/reports", reports)
		mux.Handle("GET "+BasePath+"/reports/{id}", reports)
		mux.Handle("GET "+BasePath+"/reports/{id}/download", reports)
		mux.Handle("GET "+BasePath+"/schemas/{name}", security.protect("read|write|trigger", http.HandlerFunc(schemaDocuments)))
		sboms := assessmentHandler{store: security.Assessments, artifacts: security.Artifacts}
		mux.Handle("GET "+BasePath+"/sboms/{id}/download", security.protect("read|write", http.HandlerFunc(sboms.sbomDownload)))
		// M9: SAST analyzers, settings, rulesets and reachability.
		sastAPI := security.protect("read|write", sastHandler{store: security.Assessments, client: security.SAST, defaults: security.SASTDefaults})
		mux.Handle("GET "+BasePath+"/sast/analyzers", sastAPI)
		mux.Handle("GET "+BasePath+"/reachability/capabilities", sastAPI)
		mux.Handle("GET "+BasePath+"/sast/settings", sastAPI)
		mux.Handle("PUT "+BasePath+"/sast/settings", sastAPI)
		mux.Handle("GET "+BasePath+"/assets/{id}/sast", sastAPI)
		mux.Handle("PUT "+BasePath+"/assets/{id}/sast", sastAPI)
		mux.Handle("GET "+BasePath+"/sast/rulesets", sastAPI)
		mux.Handle("POST "+BasePath+"/sast/rulesets", sastAPI)
		mux.Handle("GET "+BasePath+"/sast/rulesets/{id}", sastAPI)
		mux.Handle("DELETE "+BasePath+"/sast/rulesets/{id}", sastAPI)
		mux.Handle("GET "+BasePath+"/audit", security.protect("admin", auditHandler{security.Assessments}))
		mux.Handle("GET "+BasePath+"/schemas/events", security.protect("read|write|trigger", http.HandlerFunc(eventSchemas)))
		mux.Handle("GET "+BasePath+"/schemas/events/{type}/{version}", security.protect("read|write|trigger", http.HandlerFunc(eventSchemas)))
		maintenance := security.protect("admin", maintenanceHandler{security.Assessments, security.Notify, security.QARunner})
		mux.Handle(BasePath+"/maintenance/", maintenance)
		mux.Handle(BasePath+"/events/inbound", maintenance)
		mux.Handle(BasePath+"/events/inbound/", maintenance)
		h := assessmentHandler{store: security.Assessments, artifacts: security.Artifacts, remediationEnabled: security.RemediationEnabled}
		mux.Handle("POST "+BasePath+"/assessments", security.protect("write|trigger", h))
		mux.Handle("POST "+BasePath+"/assessments:batch", security.protect("write|trigger", h))
		mux.Handle("POST "+BasePath+"/assessments:import", security.protect("write|trigger", h))
		mux.Handle("GET "+BasePath+"/assets/{id}/last-known-good", security.protect("read|write", h))
		mux.Handle("GET "+BasePath+"/assets/{id}/revisions", security.protect("read|write", h))
		mux.Handle("GET "+BasePath+"/assets/{id}/sbom-diff", security.protect("read|write", h))
		mux.Handle("GET "+BasePath+"/assessments", security.protect("read|write|trigger", h))
		mux.Handle(BasePath+"/assessments/", security.protect("read|write|trigger", h))
		mux.Handle("GET "+BasePath+"/remediation/capabilities", security.protect("read|write", h))
		mux.Handle("POST "+BasePath+"/assets/{id}/remediations", security.protect("write", h))
		dependencies := dependencyPolicyHandler{store: security.Assessments}
		mux.Handle("GET "+BasePath+"/policies/dependencies", security.protect("read|write", dependencies))
		mux.Handle("PUT "+BasePath+"/policies/dependencies", security.protect("admin", dependencies))
		integrity := integrityPolicyHandler{store: security.Assessments}
		mux.Handle("GET "+BasePath+"/policies/integrity", security.protect("read|write", integrity))
		mux.Handle("PUT "+BasePath+"/policies/integrity", security.protect("admin", integrity))
		incidents := incidentHandler{store: security.Assessments}
		mux.Handle("POST "+BasePath+"/incidents", security.protect("admin", incidents))
		mux.Handle("GET "+BasePath+"/incidents", security.protect("read|write", incidents))
		mux.Handle("GET "+BasePath+"/incidents/{id}", security.protect("read|write", incidents))
		links := assetLinkHandler{store: security.Assessments}
		mux.Handle("GET "+BasePath+"/assets/{id}/links", security.protect("read|write", links))
		mux.Handle("POST "+BasePath+"/assets/{id}/links", security.protect("write", links))
		mux.Handle("DELETE "+BasePath+"/assets/{id}/links/{to}", security.protect("write", links))
		jobs := jobHandler{store: security.Assessments}
		mux.Handle("GET "+BasePath+"/jobs", security.protect("read|write", jobs))
		mux.Handle(BasePath+"/jobs/", security.protect("read|write", jobs)) // cancel is checked as admin in the handler
		mirrors := mirrorHandler{store: security.Assessments, bundles: security.Mirrors}
		mux.Handle("POST "+BasePath+"/assets/{id}/mirrors", security.protect("write", mirrors))
		mux.Handle("GET "+BasePath+"/assets/{id}/mirrors", security.protect("read|write", mirrors))
		mux.Handle("GET "+BasePath+"/assets/{id}/mirrors/{mirror}/bundle", security.protect("admin", mirrors))
		mux.Handle(BasePath+"/register", security.protect("read|write", h))
		mux.Handle(BasePath+"/register/", security.protect("read|write", h))
		// E2E QA (Karate) and the LLM providers that draft tests.
		qaH := qaHandler{store: security.Assessments, secrets: secrets, reports: security.QAReports, runner: security.QARunner, llmHosts: security.LLMPrivateHosts, allowSource: security.LLMAllowSource}
		mux.Handle("GET "+BasePath+"/assets/{id}/qa/profile", security.protect("read|write", qaH))
		mux.Handle("PUT "+BasePath+"/assets/{id}/qa/profile", security.protect("admin", qaH))
		mux.Handle("DELETE "+BasePath+"/assets/{id}/qa/profile", security.protect("admin", qaH))
		mux.Handle("GET "+BasePath+"/assets/{id}/qa/runs", security.protect("read|write", qaH))
		mux.Handle("POST "+BasePath+"/assets/{id}/qa/runs", security.protect("write|trigger", qaH))
		mux.Handle("GET "+BasePath+"/assets/{id}/qa/coverage", security.protect("read|write", qaH))
		mux.Handle("GET "+BasePath+"/assets/{id}/qa/generations", security.protect("read|write", qaH))
		mux.Handle("POST "+BasePath+"/assets/{id}/qa/generations", security.protect("write", qaH))
		aiReviews := aiReviewHandler{store: security.Assessments, hosts: security.LLMPrivateHosts, allowSource: security.LLMAllowSource}
		mux.Handle("POST "+BasePath+"/assets/{id}/ai-reviews", security.protect("write|trigger", aiReviews))
		mux.Handle("GET "+BasePath+"/assets/{id}/ai-reviews", security.protect("read|write", aiReviews))
		mux.Handle("GET "+BasePath+"/ai-reviews/{id}", security.protect("read|write", aiReviews))
		aiSummaries := aiSummaryHandler{store: security.Assessments}
		mux.Handle("POST "+BasePath+"/assessments/{id}/summaries", security.protect("write|trigger", aiSummaries))
		mux.Handle("GET "+BasePath+"/assessments/{id}/summaries", security.protect("read|write", aiSummaries))
		mux.Handle("GET "+BasePath+"/summary-jobs/{id}", security.protect("read|write", aiSummaries))
		mux.Handle("GET "+BasePath+"/assets/{id}/chronicle", security.protect("read|write", aiSummaries))
		mux.Handle("GET "+BasePath+"/assets/{id}/qa/suites", security.protect("read|write", qaH))
		mux.Handle("GET "+BasePath+"/assessments/{id}/qa", security.protect("read|write|trigger", qaH))
		mux.Handle(BasePath+"/qa/", security.protect("read|write|trigger", qaH))
		models := security.protect("read|write", llmHandler{store: security.Assessments, secrets: secrets, hosts: security.LLMPrivateHosts, allowSource: security.LLMAllowSource})
		mux.Handle(BasePath+"/llm/", models)
	}
	return security.observe(m, security.cors(mux))
}
func (s Security) protect(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) > 1024 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, 401, "unauthorized")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		remote, _ := netip.ParseAddr(host)
		remote = s.clientIP(remote, r.Header.Get("X-Forwarded-For"))
		principal, err := s.Store.Authenticate(ctx, strings.TrimPrefix(authorization, "Bearer "), remote)
		if err != nil {
			if errors.Is(err, connections.ErrUnauthorized) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, 401, "unauthorized")
			} else {
				writeError(w, 503, "authentication unavailable")
			}
			return
		}
		allowedScope := scope == ""
		for _, value := range strings.Split(scope, "|") {
			if principal.Allows(value) {
				allowedScope = true
			}
		}
		if !allowedScope {
			writeError(w, 403, "insufficient scope")
			return
		}
		if s.Redis == nil {
			writeError(w, 503, "rate limiter unavailable")
			return
		}
		allowed, err := tokenWindow.Run(ctx, s.Redis, []string{"scrs:token-window:" + principal.ID.String()}, uuid.NewString()).Int()
		if err != nil {
			writeError(w, 503, "rate limiter unavailable")
			return
		}
		if allowed != 1 {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "token rate limit exceeded")
			return
		}
		if info, ok := r.Context().Value(infoKey{}).(*requestInfo); ok {
			info.principal = principal.Name
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
	})
}
func (s Security) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			allowed := false
			for _, value := range s.Origins {
				if value == origin && value != "*" {
					allowed = true
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, If-Match")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Expose-Headers", "Location, ETag, Retry-After, X-Next-Cursor, X-Request-Id, Idempotent-Replayed")
			}
			if r.Method == http.MethodOptions {
				if !allowed {
					writeError(w, 403, "origin not allowed")
				} else {
					w.WriteHeader(204)
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (s Security) tokens(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path == BasePath+"/tokens" {
		switch r.Method {
		case http.MethodGet:
			after := uuid.Nil
			if raw := r.URL.Query().Get("cursor"); raw != "" {
				var err error
				after, err = uuid.Parse(raw)
				if err != nil {
					writeError(w, 400, "invalid cursor")
					return
				}
			}
			items, err := s.Store.Tokens(ctx, after, 101)
			if err != nil {
				writeError(w, 500, "token list failed")
				return
			}
			next := ""
			if len(items) > 100 {
				items = items[:100]
				next = items[99].ID.String()
			}
			writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		case http.MethodPost:
			var input struct {
				Name      string     `json:"name"`
				Scopes    []string   `json:"scopes"`
				Networks  []string   `json:"ip_allow_list"`
				ExpiresAt *time.Time `json:"expires_at"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
				writeError(w, 400, "invalid token request")
				return
			}
			item, secret, err := s.Store.CreateToken(ctx, connections.Token{Name: input.Name, Scopes: input.Scopes, Networks: input.Networks, ExpiresAt: input.ExpiresAt}, actor.ID)
			if err != nil {
				switch {
				case errors.Is(err, connections.ErrTokenInput):
					writeError(w, 400, "invalid token request")
				case errors.Is(err, connections.ErrConflict):
					writeError(w, 409, "token name already exists")
				default:
					writeError(w, 500, "token creation failed")
				}
				return
			}
			writeJSON(w, 201, map[string]any{"token": secret, "metadata": item})
		default:
			w.Header().Set("Allow", "GET, POST")
			writeError(w, 405, "method not allowed")
		}
		return
	}
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, BasePath+"/tokens/"))
	if err != nil {
		writeError(w, 404, "token not found")
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		writeError(w, 405, "method not allowed")
		return
	}
	if err := s.Store.RevokeToken(ctx, id, actor.ID); err != nil {
		if errors.Is(err, connections.ErrTokenInput) {
			writeError(w, 409, "token not found or bootstrap token cannot be revoked; rotate bootstrap via environment")
		} else {
			writeError(w, 500, "token revocation failed")
		}
		return
	}
	w.WriteHeader(204)
}

// Walk the forwarded chain from the socket inward; stop at the first untrusted
// hop. Headers supplied by a direct untrusted client never affect its identity.
func (s Security) clientIP(peer netip.Addr, forwarded string) netip.Addr {
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range s.TrustedProxies {
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) || len(forwarded) > 4096 || strings.TrimSpace(forwarded) == "" {
		return peer.Unmap()
	}
	hops := strings.Split(forwarded, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		if !trusted(peer) {
			break
		}
		parsed, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{}
		}
		peer = parsed.Unmap()
	}
	return peer.Unmap()
}
