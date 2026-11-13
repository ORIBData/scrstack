package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var safeRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// modules bounds the route label so arbitrary paths cannot grow metric cardinality.
var modules = map[string]bool{"system": true, "docs": true, "tokens": true, "connections": true, "assets": true, "owners": true, "assessments": true, "assessments:batch": true, "register": true, "remediation": true, "feeds": true, "webhooks": true, "ingest": true, "settings": true, "maintenance": true}

func module(path string) string {
	segment, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(path, BasePath), "/"), "/")
	if modules[segment] {
		return segment
	}
	return "other"
}

// requestInfo lets inner handlers report the authenticated principal to the access log.
type requestInfo struct{ principal string }
type infoKey struct{}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}
func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = 200
	}
	return s.ResponseWriter.Write(b)
}

type metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	triggers *prometheus.CounterVec
}

func newMetrics(store *assessments.Store, events *notify.Store) *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "scrs_http_requests_total", Help: "API requests by module, method and status code."}, []string{"module", "method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "scrs_http_request_duration_seconds", Help: "API request latency by module.", Buckets: prometheus.DefBuckets}, []string{"module"}),
		triggers: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "scrs_trigger_requests_total", Help: "Assessment triggers by entry mode and result class (TRG-015)."}, []string{"mode", "result"}),
	}
	m.registry.MustRegister(m.requests, m.duration, m.triggers, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if store != nil {
		m.registry.MustRegister(storeCollector{store, events})
	}
	return m
}

func triggerMode(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, BasePath)
	switch {
	case r.Method != http.MethodPost:
		return ""
	case path == "/assessments":
		return "trigger"
	case path == "/assessments:batch":
		return "batch"
	case path == "/webhooks/github", path == "/ingest/github" && r.Header.Get("X-Hub-Signature-256") != "":
		return "direct"
	case path == "/ingest/github":
		return "relay"
	}
	return ""
}

// observe assigns request ids, writes one access-log line and records metrics.
func (s Security) observe(m *metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !safeRequestID.MatchString(id) {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		info := &requestInfo{}
		ctx := context.WithValue(assessments.WithRequestID(r.Context(), id), infoKey{}, info)
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		mode := triggerMode(r)
		next.ServeHTTP(sw, r.WithContext(ctx))
		if sw.status == 0 {
			sw.status = 200
		}
		elapsed := time.Since(start)
		mod := module(r.URL.Path)
		m.requests.WithLabelValues(mod, r.Method, strconv.Itoa(sw.status)).Inc()
		m.duration.WithLabelValues(mod).Observe(elapsed.Seconds())
		if mode != "" {
			m.triggers.WithLabelValues(mode, strconv.Itoa(sw.status/100)+"xx").Inc()
		}
		if s.Logger != nil && mod != "system" {
			s.Logger.Info("request", "request_id", id, "method", r.Method, "module", mod, "path", r.URL.Path, "status", sw.status, "duration_ms", elapsed.Milliseconds(), "principal", info.principal)
		}
	})
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Timeout: 5 * time.Second})
}

// storeCollector reads queue, verdict and delivery state from PostgreSQL at
// scrape time, so values are correct across API and worker processes.
type storeCollector struct {
	store  *assessments.Store
	events *notify.Store
}

var (
	queueDesc    = prometheus.NewDesc("scrs_assessment_queue_depth", "Assessments waiting or running.", []string{"status"}, nil)
	oldestDesc   = prometheus.NewDesc("scrs_assessment_oldest_queued_seconds", "Age of the oldest queued assessment.", nil, nil)
	verdictDesc  = prometheus.NewDesc("scrs_assessment_verdict_total", "Completed assessments by verdict (TRG-015).", []string{"verdict"}, nil)
	durationDesc = prometheus.NewDesc("scrs_assessment_duration_seconds", "Assessment duration quantiles over the last 24 hours (TRG-015).", []string{"kind", "quantile"}, nil)
	webhookDesc  = prometheus.NewDesc("scrs_webhook_deliveries", "Outbound webhook deliveries not yet delivered, by status.", []string{"status"}, nil)
	upDesc       = prometheus.NewDesc("scrs_store_up", "1 when the metrics store query succeeded.", nil, nil)
)

func (c storeCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{queueDesc, oldestDesc, verdictDesc, durationDesc, webhookDesc, upDesc} {
		ch <- d
	}
}

func (c storeCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stats, err := c.store.Stats(ctx)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 1)
	for _, status := range []string{"queued", "running"} {
		ch <- prometheus.MustNewConstMetric(queueDesc, prometheus.GaugeValue, float64(stats.Queue[status]), status)
	}
	ch <- prometheus.MustNewConstMetric(oldestDesc, prometheus.GaugeValue, stats.OldestQueuedSeconds)
	for verdict, n := range stats.Verdicts {
		ch <- prometheus.MustNewConstMetric(verdictDesc, prometheus.CounterValue, float64(n), verdict)
	}
	for kind, q := range stats.Durations {
		ch <- prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, q[0], kind, "0.5")
		ch <- prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, q[1], kind, "0.95")
	}
	if c.events != nil {
		if deliveries, err := c.events.Stats(ctx); err == nil {
			for _, status := range []string{"pending", "sending", "dead"} {
				ch <- prometheus.MustNewConstMetric(webhookDesc, prometheus.GaugeValue, float64(deliveries[status]), status)
			}
		}
	}
}
