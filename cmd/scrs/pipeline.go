package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
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
			err := scanner.SyncFeeds(syncCtx, setting("SCRS_FEED_ROOT", "/feeds"), strings.Split(setting("SCRS_OSV_ECOSYSTEMS", "npm,Go"), ","))
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
		engine := scanner.Engine{ClamdAddress: os.Getenv("SCRS_CLAMD_ADDRESS"), IndicatorFile: os.Getenv("SCRS_INDICATOR_FILE"), RemediationEnabled: os.Getenv("SCRS_REMEDIATION_ENABLED") == "true", RemediationProxy: os.Getenv("SCRS_REMEDIATION_PROXY"), Binary: setting("SCRS_OSV_BINARY", "/usr/local/bin/osv-scanner"), WorkRoot: setting("SCRS_WORK_ROOT", "/work"), Database: setting("SCRS_OSV_DB", "/feeds/current")}
		if _, err := os.Stat(engine.Binary); err != nil {
			return errors.New("pinned OSV-Scanner binary unavailable")
		}
		server := &http.Server{Addr: setting("SCRS_SCANNER_ADDR", ":8081"), Handler: engine.Handler(token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 250 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
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
		w := worker.Worker{AutoRemediation: os.Getenv("SCRS_REMEDIATION_ENABLED") == "true", Store: store, Connections: providers, Artifacts: artifacts, ScannerURL: setting("SCRS_SCANNER_URL", "http://scrs-scanner:8081/scan"), ScannerToken: os.Getenv("SCRS_SCANNER_API_TOKEN"), Logger: logger}
		return w.Run(ctx)
	}
	return errors.New("unknown pipeline command")
}
