package storage

import (
	"strings"
	"testing"
)

func TestConfigFromEnvValidatesStorageAndDefaults(t *testing.T) {
	t.Setenv("SCRS_DATABASE_URL", "postgres://app:secret@localhost:5432/scrs?sslmode=disable")
	t.Setenv("SCRS_REDIS_QUEUE_URL", "redis://localhost:6379/0")
	t.Setenv("SCRS_REDIS_CACHE_URL", "")
	t.Setenv("SCRS_S3_ENDPOINT", "https://s3.example.net")
	t.Setenv("SCRS_S3_REGION", "us-east-1")
	t.Setenv("SCRS_S3_BUCKET", "scrs-test")
	t.Setenv("SCRS_S3_ACCESS_KEY", "access")
	t.Setenv("SCRS_S3_SECRET_KEY", "secret")
	t.Setenv("SCRS_DATABASE_SCHEMA", "")
	t.Setenv("SCRS_S3_FORCE_PATH_STYLE", "true")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseSchema != "scrs" || cfg.RedisCacheURL != cfg.RedisQueueURL || !cfg.S3PathStyle {
		t.Fatalf("defaults not applied: %#v", cfg)
	}

	cfg.DatabaseSchema = "scrs; DROP SCHEMA public"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SCRS_DATABASE_SCHEMA") {
		t.Fatalf("unsafe schema accepted: %v", err)
	}
	cfg.DatabaseSchema = "scrs"
	cfg.S3Endpoint = "https://access:secret@s3.example.net/bucket"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SCRS_S3_ENDPOINT") {
		t.Fatalf("unsafe S3 endpoint accepted: %v", err)
	}
}

func TestConfigFromEnvReportsMissingRequiredValues(t *testing.T) {
	t.Setenv("SCRS_DATABASE_URL", "")
	_, err := ConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "SCRS_DATABASE_URL") {
		t.Fatalf("missing database URL: %v", err)
	}
}
