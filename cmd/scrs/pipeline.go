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

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
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
		server := &http.Server{Addr: ":8082", Handler: scanner.EgressProxy(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
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
		w := worker.Worker{AutoRemediation: os.Getenv("SCRS_REMEDIATION_ENABLED") == "true", Store: store, Connections: providers, Artifacts: artifacts, ScannerURL: setting("SCRS_SCANNER_URL", "http://scrs-scanner:8081/scan"), ScannerToken: os.Getenv("SCRS_SCANNER_API_TOKEN"), Logger: logger, Notify: events}
		if limit, err := strconv.ParseInt(os.Getenv("SCRS_MAX_IMAGE_BYTES"), 10, 64); err == nil && limit > 0 {
			w.MaxImageBytes = limit
		}
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
		go w.Maintain(ctx, time.Hour, rescan, mirror)
		return w.Run(ctx)
	}
	return errors.New("unknown pipeline command")
}
