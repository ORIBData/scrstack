package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/httpapi"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/redis/go-redis/v9"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "init" || os.Args[1] == "connections") {
		if err := manageConnections(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "storage" {
		if len(os.Args) != 3 || (os.Args[2] != "check" && os.Args[2] != "bootstrap") {
			fmt.Fprintln(os.Stderr, "usage: scrs storage [check|bootstrap]")
			os.Exit(2)
		}
		cfg, err := storage.ConfigFromEnv()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if os.Args[2] == "bootstrap" {
			err = storage.Bootstrap(ctx, cfg)
		} else {
			err = storage.Check(ctx, cfg)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("storage " + os.Args[2] + " succeeded")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] != "api" {
		fmt.Fprintln(os.Stderr, "usage: scrs [api|healthcheck|storage check|storage bootstrap]")
		os.Exit(2)
	}

	addr := os.Getenv("SCRS_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if !strings.HasPrefix(addr, ":") || len(addr) < 2 {
		fmt.Fprintln(os.Stderr, "SCRS_HTTP_ADDR must be a port such as :8080")
		os.Exit(2)
	}
	cfg, err := storage.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = storage.Check(checkCtx, cfg)
	checkCancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bootstrapToken := os.Getenv("SCRS_BOOTSTRAP_API_TOKEN")
	if bootstrapToken != "" && len(bootstrapToken) < 32 {
		fmt.Fprintln(os.Stderr, "SCRS_BOOTSTRAP_API_TOKEN must be at least 32 characters")
		os.Exit(2)
	}
	store, err := connections.Open(context.Background(), cfg.DatabaseURL, cfg.DatabaseSchema, os.Getenv("SCRS_MASTER_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	authCtx, authCancel := context.WithTimeout(context.Background(), 10*time.Second)
	generated, err := store.SyncBootstrap(authCtx, bootstrapToken)
	authCancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "token bootstrap failed; run scrs init to apply migrations")
		os.Exit(1)
	}
	if generated != "" {
		fmt.Fprintln(os.Stderr, "SCRS initial bootstrap token (shown once): "+generated)
	}
	redisOptions, err := redis.ParseURL(cfg.RedisCacheURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid Redis cache URL")
		os.Exit(2)
	}
	rateClient := redis.NewClient(redisOptions)
	defer rateClient.Close()
	docsPublic := os.Getenv("SCRS_DOCS_PUBLIC") == "true"
	if value := os.Getenv("SCRS_DOCS_PUBLIC"); value != "" && value != "true" && value != "false" {
		fmt.Fprintln(os.Stderr, "SCRS_DOCS_PUBLIC must be true or false")
		os.Exit(2)
	}
	var origins []string
	for _, value := range strings.Split(os.Getenv("SCRS_CORS_ORIGINS"), ",") {
		if value = strings.TrimSpace(value); value != "" {
			origins = append(origins, value)
		}
	}

	var trustedProxies []netip.Prefix
	for _, value := range strings.Split(os.Getenv("SCRS_TRUSTED_PROXY_CIDRS"), ",") {
		if value = strings.TrimSpace(value); value != "" {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Bits() == 0 {
				fmt.Fprintln(os.Stderr, "SCRS_TRUSTED_PROXY_CIDRS must contain specific trusted proxy CIDRs, not a default route")
				os.Exit(2)
			}
			trustedProxies = append(trustedProxies, prefix)
		}
	}
	readinessCheck, closeReadiness, err := storage.NewReadiness(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "readiness initialization failed")
		os.Exit(1)
	}
	defer closeReadiness()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.HandlerWithSecurity(readinessCheck, store, httpapi.Security{Store: store, Redis: rateClient, DocsPublic: docsPublic, Origins: origins, TrustedProxies: trustedProxies}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      190 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown", "error", err)
		}
	}()
	logger.Info("starting SCRS API", "address", addr, "base_path", httpapi.BasePath)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func manageConnections() error {
	cfg, err := storage.ConfigFromEnv()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if os.Args[1] == "init" {
		if err := storage.Bootstrap(ctx, cfg); err != nil {
			return err
		}
	}
	store, err := connections.Open(ctx, cfg.DatabaseURL, cfg.DatabaseSchema, os.Getenv("SCRS_MASTER_KEY"))
	if err != nil {
		return err
	}
	defer store.Close()
	if os.Args[1] == "init" {
		count, err := store.SeedFromEnv(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("storage ready; %d provider connections seeded\n", count)
		return nil
	}
	if len(os.Args) < 3 {
		return errors.New("usage: scrs connections [list|assets|test <name>|discover <name|all>]")
	}
	switch os.Args[2] {
	case "list":
		list, err := store.List(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(list)
	case "assets":
		assets, err := store.ListAssets(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(assets)
	case "test":
		if len(os.Args) != 4 {
			return errors.New("usage: scrs connections test <name>")
		}
		count, err := store.Test(ctx, os.Args[3], connections.NewNativeAdapters())
		if err != nil {
			return err
		}
		fmt.Printf("connection %s can list %d resources\n", os.Args[3], count)
		return nil
	case "discover":
		if len(os.Args) != 4 {
			return errors.New("usage: scrs connections discover <name|all>")
		}
		names := []string{os.Args[3]}
		if os.Args[3] == "all" {
			list, err := store.List(ctx)
			if err != nil {
				return err
			}
			names = nil
			for _, item := range list {
				names = append(names, item.Name)
			}
		}
		adapter := connections.NewNativeAdapters()
		for _, name := range names {
			result, err := store.Discover(ctx, name, adapter)
			if err != nil {
				return fmt.Errorf("discovery for %s failed: %w", name, err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("usage: scrs connections [list|assets|test <name>|discover <name|all>]")
	}
}

func healthcheck() error {
	addr := os.Getenv("SCRS_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if !strings.HasPrefix(addr, ":") {
		return errors.New("healthcheck requires a port-only SCRS_HTTP_ADDR")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + addr + httpapi.BasePath + "/system/readyz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned %d", resp.StatusCode)
	}
	return nil
}
