package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ORIBData/scrstack/internal/actionscheck"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/depsdev"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/ORIBData/scrstack/internal/netguard"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/sast"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/ORIBData/scrstack/internal/worker"
)

func setting(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func pipelineCommand() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	switch os.Args[1] {
	case "egress-proxy":
		// The go-modules profile serves the SAST analyzers' module downloads
		// only; the default serves remediation planning.
		proxy := scanner.EgressProxy()
		if os.Getenv("SCRS_EGRESS_PROFILE") == "go-modules" {
			proxy = scanner.EgressProxyFor(scanner.GoModuleHosts)
		}
		server := &http.Server{Addr: ":8082", Handler: proxy, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() { <-ctx.Done(); _ = server.Close() }()
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case "yara-install":
		// One-shot: install the embedded YARA ruleset into ClamAV's database volume.
		// ClamAV populates and owns its volume on first start, so retry until
		// the directory is writable, then reload clamd to apply the rules.
		directory := setting("SCRS_CLAMAV_DATABASE", "/clamav-db")
		deadline := time.Now().Add(10 * time.Minute)
		for {
			err := scanner.InstallRules(directory)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return err
			}
			logger.Warn("waiting for ClamAV database directory", "error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
			}
		}
		logger.Info("YARA ruleset installed", "version", scanner.RulesVersion)
		if address := os.Getenv("SCRS_CLAMD_ADDRESS"); address != "" {
			for attempt := 0; attempt < 30; attempt++ {
				reloadCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
				err := scanner.ReloadClamd(reloadCtx, address)
				cancel()
				if err == nil {
					logger.Info("clamd reloaded with SCRS YARA ruleset")
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Second):
				}
			}
			logger.Warn("clamd reload not confirmed; rules apply at its next SelfCheck")
		}
		return nil
	case "sast":
		// M9: static analyzers and Go reachability, in the scrs-sast image.
		token := os.Getenv("SCRS_SAST_API_TOKEN")
		if len(token) < 32 || strings.HasPrefix(token, "REPLACE") {
			return errors.New("set a random SCRS_SAST_API_TOKEN of at least 32 characters")
		}
		paths := sast.DefaultPaths
		engine := sast.New(paths, setting("SCRS_OSV_DB", "/feeds/current"), os.Getenv("SCRS_SAST_GO_PROXY"), strings.Split(setting("SCRS_SAST_ANALYZERS", "gosec,bandit,opengrep,bearer"), ","))
		slots := 1
		if n, err := strconv.Atoi(os.Getenv("SCRS_SAST_SLOTS")); err == nil && n > 0 && n <= 8 {
			slots = n
		}
		service := &sast.Server{Engine: engine, WorkRoot: setting("SCRS_WORK_ROOT", "/work"), Slots: slots}
		server := &http.Server{Addr: setting("SCRS_SAST_ADDR", ":8083"), Handler: service.Handler(token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 50 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
		logger.Info("SAST analyzers listening", "addr", server.Addr, "analyzers", setting("SCRS_SAST_ANALYZERS", "gosec,bandit,opengrep,bearer"))
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case "sast-healthcheck":
		client := &http.Client{Timeout: 20 * time.Second}
		response, err := client.Get("http://127.0.0.1" + setting("SCRS_SAST_ADDR", ":8083") + "/healthz")
		if err != nil {
			return errors.New("SAST service unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return errors.New("an enabled analyzer is unavailable")
		}
		return nil
	case "scanner-healthcheck":
		client := &http.Client{Timeout: 2 * time.Second}
		response, err := client.Get("http://127.0.0.1:8081/healthz")
		if err != nil {
			return errors.New("scanner unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return errors.New("scanner feeds unavailable")
		}
		return nil

	case "feed-sync":
		// Failures back off exponentially: a persistent rejection must not
		// re-download hundreds of MiB every minute.
		retry := time.Minute
		for {
			syncCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			err := scanner.SyncFeeds(syncCtx, setting("SCRS_FEED_ROOT", "/feeds"), strings.Split(setting("SCRS_OSV_ECOSYSTEMS", "npm,Go,Maven,PyPI,Pub,SwiftURL,RubyGems,Alpine,Debian"), ","))
			cancel()
			if err != nil {
				logger.Error("OSV feed synchronization failed", "error", err, "retry_in", retry.String())
			} else {
				logger.Info("OSV feed synchronized")
			}
			if len(os.Args) < 3 || os.Args[2] != "--loop" {
				return err
			}
			delay := 6 * time.Hour
			if err != nil {
				delay = retry
				retry = min(retry*2, time.Hour)
			} else {
				retry = time.Minute
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
		}
	case "scanner":
		token := os.Getenv("SCRS_SCANNER_API_TOKEN")
		if len(token) < 32 || strings.HasPrefix(token, "REPLACE") {
			return errors.New("set a random SCRS_SCANNER_API_TOKEN of at least 32 characters")
		}
		engine := scanner.Engine{ClamdAddress: os.Getenv("SCRS_CLAMD_ADDRESS"), IndicatorFile: os.Getenv("SCRS_INDICATOR_FILE"), RemediationEnabled: os.Getenv("SCRS_REMEDIATION_ENABLED") == "true", RemediationProxy: os.Getenv("SCRS_REMEDIATION_PROXY"), Binary: setting("SCRS_OSV_BINARY", "/usr/local/bin/osv-scanner"), WorkRoot: setting("SCRS_WORK_ROOT", "/work"), Database: setting("SCRS_OSV_DB", "/feeds/current"), YARABinary: setting("SCRS_YARA_BINARY", "/usr/local/bin/yr")}
		if limit, err := strconv.ParseInt(os.Getenv("SCRS_MAX_IMAGE_BYTES"), 10, 64); err == nil && limit > 0 {
			engine.MaxImageBytes = limit
		} else {
			engine.MaxImageBytes = 400 << 20
		}
		if _, err := os.Stat(engine.Binary); err != nil {
			return errors.New("pinned OSV-Scanner binary unavailable")
		}
		server := &http.Server{Addr: setting("SCRS_SCANNER_ADDR", ":8081"), Handler: engine.Handler(token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 9 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case "worker":
		cfg, err := storage.ConfigFromEnv()
		if err != nil {
			return err
		}
		store, err := assessments.Open(ctx, cfg.DatabaseURL, cfg.DatabaseSchema)
		if err != nil {
			return err
		}
		defer store.Close()
		providers, err := connections.Open(ctx, cfg.DatabaseURL, cfg.DatabaseSchema, os.Getenv("SCRS_MASTER_KEY"))
		if err != nil {
			return err
		}
		defer providers.Close()
		artifacts, err := storage.NewArtifacts(cfg)
		if err != nil {
			return err
		}
		events, err := notify.Open(ctx, cfg.DatabaseURL, cfg.DatabaseSchema, os.Getenv("SCRS_MASTER_KEY"))
		if err != nil {
			return err
		}
		defer events.Close()
		store.UseObjects(artifacts)
		w := worker.Worker{AutoRemediation: os.Getenv("SCRS_REMEDIATION_ENABLED") == "true", Store: store, Connections: providers, Artifacts: artifacts, ScannerURL: setting("SCRS_SCANNER_URL", "http://scrs-scanner:8081/scan"), ScannerToken: os.Getenv("SCRS_SCANNER_API_TOKEN"), Logger: logger, Notify: events}
		if limit, err := strconv.ParseInt(os.Getenv("SCRS_MAX_IMAGE_BYTES"), 10, 64); err == nil && limit > 0 {
			w.MaxImageBytes = limit
		}
		w.Uploads = artifacts
		if os.Getenv("SCRS_SNAPSHOT_ARCHIVES") == "true" {
			w.Snapshots = artifacts
		}
		dispatcher := &notify.Dispatcher{Store: events, Logger: logger, Document: store.ProfileDocument}
		go dispatcher.Run(ctx)
		go w.MonitorFeeds(ctx, 5*time.Minute)
		rescan := time.Duration(0)
		if hours, err := strconv.Atoi(os.Getenv("SCRS_RESCAN_INTERVAL_HOURS")); err == nil && hours > 0 && hours <= 24*90 {
			rescan = time.Duration(hours) * time.Hour
		}
		if os.Getenv("SCRS_MIRRORS_ENABLED") != "false" {
			w.Mirrors = artifacts
			if limit, err := strconv.ParseInt(os.Getenv("SCRS_MIRROR_MAX_BYTES"), 10, 64); err == nil && limit > 0 {
				w.MaxMirrorBytes = limit
			}
			w.KeepMirrors = 7
			if keep, err := strconv.Atoi(os.Getenv("SCRS_MIRROR_KEEP")); err == nil && keep > 0 && keep <= 365 {
				w.KeepMirrors = keep
			}
			w.MirrorMinAgeDays = 30
			if days, err := strconv.Atoi(os.Getenv("SCRS_MIRROR_MIN_AGE_DAYS")); err == nil && days >= 0 && days <= 3650 {
				w.MirrorMinAgeDays = days
			}
			go w.RunMirrors(ctx)
		}
		mirror := time.Duration(0)
		if hours, err := strconv.Atoi(os.Getenv("SCRS_MIRROR_INTERVAL_HOURS")); err == nil && hours > 0 && hours <= 24*90 {
			mirror = time.Duration(hours) * time.Hour
		}
		hookCheck := 5 * time.Minute
		if minutes, err := strconv.Atoi(os.Getenv("SCRS_GITHUB_HOOK_CHECK_MINUTES")); err == nil && minutes >= 0 && minutes <= 1440 {
			hookCheck = time.Duration(minutes) * time.Minute
		}
		if hookCheck > 0 {
			go w.CheckGitHubHooks(ctx, hookCheck, os.Getenv("SCRS_GITHUB_HOOK_URL"))
		}
		taxiiPoll := time.Minute
		if seconds, err := strconv.Atoi(os.Getenv("SCRS_TAXII_POLL_SECONDS")); err == nil && seconds >= 0 && seconds <= 3600 {
			taxiiPoll = time.Duration(seconds) * time.Second
		}
		if taxiiPoll > 0 {
			w.TAXIIPrivateHosts = netguard.Hosts(os.Getenv("SCRS_TAXII_PRIVATE_HOSTS"))
			yara := setting("SCRS_YARA_BINARY", "/usr/local/bin/yr")
			w.ValidateRules = func(ctx context.Context, rules string) error {
				_, err := scanner.ValidateRules(ctx, yara, os.TempDir(), rules)
				return err
			}
			go w.PollTAXII(ctx, taxiiPoll)
		}
		// E2E QA: runs need the Karate runner; generation needs only an LLM
		// provider configured through the API.
		runner, err := qaRunnerFromEnv()
		if err != nil {
			return err
		}
		w.LLMPrivateHosts = netguard.Hosts(os.Getenv("SCRS_LLM_PRIVATE_HOSTS"))
		w.LLMAllowSource = llm.AllowSourceToHosted()
		if runner != nil {
			w.QARunner, w.QAReports = runner, artifacts
			w.QAMaxActive = 4
			if active, err := strconv.Atoi(os.Getenv("SCRS_QA_MAX_ACTIVE")); err == nil && active > 0 && active <= 64 {
				w.QAMaxActive = active
			}
			go w.RunQA(ctx)
		}
		if os.Getenv("SCRS_QA_GENERATION_ENABLED") != "false" {
			go w.RunGenerations(ctx)
			go w.RunAIReviews(ctx)
			go w.RunAISummaries(ctx)
		}
		// Dependency-Track export (P2): configured through the API; this loop
		// only pushes uploads while it is enabled there.
		dtrackPush := 30 * time.Second
		if seconds, err := strconv.Atoi(os.Getenv("SCRS_DTRACK_PUSH_SECONDS")); err == nil && seconds >= 0 && seconds <= 3600 {
			dtrackPush = time.Duration(seconds) * time.Second
		}
		if dtrackPush > 0 {
			w.SBOMs, w.DTrackPrivateHosts = artifacts, netguard.Hosts(os.Getenv("SCRS_DTRACK_PRIVATE_HOSTS"))
			go w.RunDependencyTrack(ctx, dtrackPush)
		}
		// NVD and CVE Program records for the CVEs the register references.
		advisorySync := time.Minute
		if seconds, err := strconv.Atoi(os.Getenv("SCRS_ADVISORY_SYNC_SECONDS")); err == nil && seconds >= 0 && seconds <= 3600 {
			advisorySync = time.Duration(seconds) * time.Second
		}
		if advisorySync > 0 {
			w.NVDAPIKey, w.NVDURL, w.CVEURL = os.Getenv("SCRS_NVD_API_KEY"), os.Getenv("SCRS_NVD_API_URL"), os.Getenv("SCRS_CVE_API_URL")
			go w.RunAdvisorySources(ctx, advisorySync)
		}
		// Licence metadata and version lists from deps.dev (LIC-001, VUL-008).
		if os.Getenv("SCRS_DEPSDEV_ENABLED") != "false" {
			client := depsdev.New(os.Getenv("SCRS_DEPSDEV_URL"), netguard.Hosts(os.Getenv("SCRS_DEPSDEV_PRIVATE_HOSTS")))
			w.DepsDev = &client
			if limit, err := strconv.Atoi(os.Getenv("SCRS_DEPSDEV_MAX_LOOKUPS")); err == nil && limit > 0 && limit <= 20000 {
				w.DepsDevMaxLookups = limit
			}
		}
		// GitHub Actions inventory and run-number gaps (INT-014, INT-015). Off
		// unless an interval is set: it calls GitHub's API for every in-scope
		// repository and needs the read-only Actions permission.
		if hours, err := strconv.Atoi(os.Getenv("SCRS_ACTIONS_SWEEP_INTERVAL_HOURS")); err == nil && hours > 0 && hours <= 24*30 {
			checker := actionscheck.Checker{Connections: providers, Store: store, API: connections.NewNativeAdapters()}
			go func() {
				for {
					checker.Sweep(ctx, time.Duration(hours)*time.Hour, 25, 2*time.Second, logger)
					select {
					case <-ctx.Done():
						return
					case <-time.After(15 * time.Minute):
					}
				}
			}()
		}
		// Compliance evidence reports (CMP-006).
		reportPoll := 30 * time.Second
		if seconds, err := strconv.Atoi(os.Getenv("SCRS_REPORT_POLL_SECONDS")); err == nil && seconds >= 0 && seconds <= 3600 {
			reportPoll = time.Duration(seconds) * time.Second
		}
		if reportPoll > 0 {
			w.Reports = artifacts
			go w.RunReports(ctx, reportPoll)
		}
		// SAST analyzers and Go reachability in the scrs-sast service (M9).
		w.SAST, w.SASTDefaults, w.SASTTimeout, err = sastFromEnv()
		if err != nil {
			return err
		}
		if raw := os.Getenv("SCRS_REACHABILITY_WEIGHTS"); raw != "" {
			reach, not, ok := strings.Cut(raw, ",")
			a, errA := strconv.Atoi(strings.TrimSpace(reach))
			b, errB := strconv.Atoi(strings.TrimSpace(not))
			if !ok || errA != nil || errB != nil || a < 0 || a > 50 || b > 0 || b < -50 {
				return errors.New("SCRS_REACHABILITY_WEIGHTS must be <reachable 0..50>,<not reachable -50..0>, for example 10,-15")
			}
			w.ReachabilityWeights = &[2]int{a, b}
		}
		go w.Maintain(ctx, time.Hour, rescan, mirror)
		return w.Run(ctx)
	}
	return errors.New("unknown pipeline command")
}

// sastFromEnv returns the scrs-sast client (nil when SCRS_SAST_URL is
// unset), the deployment defaults and the per-analyzer budget.
func sastFromEnv() (*sast.Client, assessments.SASTDefaults, time.Duration, error) {
	defaults := assessments.SASTDefaults{Enabled: os.Getenv("SCRS_SAST_ENABLED") == "true", Reachability: os.Getenv("SCRS_REACHABILITY_ENABLED") == "true"}
	timeout := sast.DefaultTimeout
	if raw := os.Getenv("SCRS_SAST_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Minute || d > time.Hour {
			return nil, defaults, 0, errors.New("SCRS_SAST_TIMEOUT must be a duration from 1m to 1h")
		}
		timeout = d
	}
	url := os.Getenv("SCRS_SAST_URL")
	if url == "" {
		return nil, defaults, timeout, nil
	}
	token := os.Getenv("SCRS_SAST_API_TOKEN")
	if len(token) < 32 || strings.HasPrefix(token, "REPLACE") {
		return nil, defaults, 0, errors.New("SCRS_SAST_URL is set: set a random SCRS_SAST_API_TOKEN of at least 32 characters")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, defaults, 0, errors.New("SCRS_SAST_URL must be an http(s) URL")
	}
	return sast.NewClient(url, token), defaults, timeout, nil
}

// qaRunnerFromEnv returns the Karate runner client, or nil when
// SCRS_QA_RUNNER_URL is unset (QA runs stay queued).
func qaRunnerFromEnv() (*qa.Runner, error) {
	raw := os.Getenv("SCRS_QA_RUNNER_URL")
	if raw == "" {
		return nil, nil
	}
	var ca string
	if file := os.Getenv("SCRS_QA_RUNNER_CA_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, errors.New("SCRS_QA_RUNNER_CA_FILE unreadable")
		}
		ca = string(data)
	}
	return qa.NewRunner(raw, os.Getenv("SCRS_QA_RUNNER_TOKEN"), ca, os.Getenv("SCRS_QA_RUNNER_ALLOW_HTTP") == "true")
}
