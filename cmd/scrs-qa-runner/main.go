// Command scrs-qa-runner is the Karate runner SCRS submits QA jobs to. Run
// it on a host you manage, with no SCRS credentials and outbound network
// limited to the systems under test; see docs/QA_TESTING.md.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/ORIBData/scrstack/internal/qarunner"
)

func number(key string, fallback, lo, hi int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v >= lo && v <= hi {
		return v
	}
	return fallback
}

func setting(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("runner stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	token := os.Getenv("SCRS_QA_RUNNER_TOKEN")
	// A token file (a Docker or Kubernetes secret) keeps the token out of
	// the container's configuration.
	if file := os.Getenv("SCRS_QA_RUNNER_TOKEN_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return errors.New("SCRS_QA_RUNNER_TOKEN_FILE unreadable")
		}
		token = strings.TrimSpace(string(data))
	}
	_ = os.Unsetenv("SCRS_QA_RUNNER_TOKEN")
	var pass []string
	for _, name := range strings.Split(os.Getenv("SCRS_QA_RUNNER_PASS_ENV"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			pass = append(pass, name)
		}
	}
	// A linter is available when its executable is found. The default
	// command is the tool's name; SCRS_QA_RUNNER_LINT_<TOOL> overrides it
	// (RUFF, GOLANGCI_LINT, ESLINT).
	lint := map[string]string{}
	for tool := range qa.LintTools {
		key := "SCRS_QA_RUNNER_LINT_" + strings.ToUpper(strings.ReplaceAll(tool, "-", "_"))
		if path, err := exec.LookPath(setting(key, qa.LintExecutable(tool))); err == nil {
			lint[tool] = path
		}
	}
	eslintFallback := setting("SCRS_QA_RUNNER_ESLINT_FALLBACK", "/opt/eslint/eslint.config.mjs")
	if _, err := os.Stat(eslintFallback); err != nil {
		eslintFallback = ""
	}
	server, err := qarunner.New(qarunner.Config{
		Lint:           lint,
		LintDeps:       os.Getenv("SCRS_QA_RUNNER_LINT_DEPS") == "true",
		ESLintFallback: eslintFallback,
		Token:          token,
		WorkDir:        setting("SCRS_QA_RUNNER_WORKDIR", "/work"),
		Slots:          number("SCRS_QA_RUNNER_SLOTS", 1, 1, 16),
		MaxQueued:      number("SCRS_QA_RUNNER_MAX_QUEUED", 20, 1, 500),
		Karate:         strings.Fields(setting("SCRS_QA_RUNNER_KARATE", "karate")),
		Java:           setting("SCRS_QA_RUNNER_JAVA", "java"),
		PerfClasspath:  os.Getenv("SCRS_QA_RUNNER_PERF_CLASSPATH"),
		KarateVersion:  os.Getenv("SCRS_QA_RUNNER_KARATE_VERSION"),
		JobUID:         number("SCRS_QA_RUNNER_JOB_UID", 0, 0, 1<<30),
		JobGID:         number("SCRS_QA_RUNNER_JOB_GID", 0, 0, 1<<30),
		Retention:      time.Duration(number("SCRS_QA_RUNNER_RETENTION_HOURS", 24, 1, 720)) * time.Hour,
		PassEnv:        pass,
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	go server.Run(ctx)
	httpServer := &http.Server{Addr: setting("SCRS_QA_RUNNER_ADDR", ":8090"), Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	go func() { <-ctx.Done(); _ = httpServer.Close() }()
	cert, key := os.Getenv("SCRS_QA_RUNNER_TLS_CERT"), os.Getenv("SCRS_QA_RUNNER_TLS_KEY")
	logger.Info("karate runner listening", "addr", httpServer.Addr, "tls", cert != "")
	if cert != "" {
		err = httpServer.ListenAndServeTLS(cert, key)
	} else {
		err = httpServer.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
