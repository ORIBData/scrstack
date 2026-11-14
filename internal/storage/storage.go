package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
)

// Bootstrap creates only SCRS-owned storage. It never drops or resets data.
func Bootstrap(ctx context.Context, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := BootstrapDatabase(ctx, c); err != nil {
		return err
	}
	return bootstrapObjects(ctx, c)
}

// BootstrapDatabase initializes only the configured SCRS database/schema.
func BootstrapDatabase(ctx context.Context, c Config) error {
	if err := ensureDatabase(ctx, c); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return errors.New("PostgreSQL connection configuration failed")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("PostgreSQL connection failed; check SCRS_DATABASE_URL, network and TLS")
	}
	name := pgx.Identifier{c.DatabaseSchema}.Sanitize()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return errors.New("PostgreSQL schema transaction failed")
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, name+".scrs_schema"); err != nil {
		return errors.New("PostgreSQL schema lock failed")
	}
	_, err = tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+name)
	if err != nil {
		return errors.New("PostgreSQL schema creation failed; the application role needs CREATE on its database")
	}
	_, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS "+name+".schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
	if err != nil {
		return errors.New("PostgreSQL migration-table creation failed; check schema ownership and CREATE permission")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("PostgreSQL schema commit failed")
	}
	return bootstrapConnectionTables(ctx, pool, name)
}

func bootstrapObjects(ctx context.Context, c Config) error {
	client, err := s3Client(c)
	if err != nil {
		return err
	}
	exists, err := client.BucketExists(ctx, c.S3Bucket)
	if err != nil {
		return errors.New("S3 bucket lookup failed; check endpoint, credentials, region and bucket permission")
	}
	if !exists {
		if err := client.MakeBucket(ctx, c.S3Bucket, minio.MakeBucketOptions{Region: c.S3Region}); err != nil {
			// Another bootstrap may have created it after our lookup.
			if concurrentExists, lookupErr := client.BucketExists(ctx, c.S3Bucket); lookupErr != nil || !concurrentExists {
				return errors.New("S3 bucket creation failed; credentials need CreateBucket permission or pre-create the bucket")
			}
		}
	}
	return Check(ctx, c)
}

func bootstrapConnectionTables(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return errors.New("PostgreSQL connection migration failed")
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, schema+".scrs_migrations"); err != nil {
		return errors.New("PostgreSQL migration lock failed")
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS ` + schema + `.connections (
			id uuid PRIMARY KEY, provider text NOT NULL, name text NOT NULL UNIQUE,
			config jsonb NOT NULL, scope jsonb NOT NULL, credential_ciphertext bytea NOT NULL,
			secret_key_id text NOT NULL, status jsonb NOT NULL DEFAULT '{}',
			created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
			CHECK (provider IN ('github','gitlab','dockerhub','gar','harbor','oci'))
		)`,
		`CREATE TABLE IF NOT EXISTS ` + schema + `.assets (
			id uuid PRIMARY KEY, type text NOT NULL, locator text NOT NULL,
			connection_id uuid NOT NULL REFERENCES ` + schema + `.connections(id),
			flags jsonb NOT NULL DEFAULT '{}', metadata jsonb NOT NULL DEFAULT '{}',
			last_discovered_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (connection_id, type, locator)
		)`,
		`ALTER TABLE ` + schema + `.connections ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true`,
		`ALTER TABLE ` + schema + `.connections ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 1`,
		`ALTER TABLE ` + schema + `.connections ADD COLUMN IF NOT EXISTS configuration_revision bigint NOT NULL DEFAULT 1`,
		`ALTER TABLE ` + schema + `.assets DROP CONSTRAINT IF EXISTS assets_type_locator_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS assets_connection_locator_uq ON ` + schema + `.assets(connection_id,type,locator)`,
		`CREATE INDEX IF NOT EXISTS assets_connection_idx ON ` + schema + `.assets(connection_id)`,
		`CREATE INDEX IF NOT EXISTS assets_locator_id_idx ON ` + schema + `.assets(locator,id)`,
		// 2026111401: GitLab, Harbor and generic OCI providers.
		`ALTER TABLE ` + schema + `.connections DROP CONSTRAINT IF EXISTS connections_provider_check`,
		`ALTER TABLE ` + schema + `.connections ADD CONSTRAINT connections_provider_check CHECK (provider IN ('github','gitlab','dockerhub','gar','harbor','oci'))`,
		`CREATE TABLE IF NOT EXISTS ` + schema + `.api_tokens (
   id uuid PRIMARY KEY, name text NOT NULL UNIQUE, prefix text NOT NULL,
   secret_hash bytea NOT NULL UNIQUE CHECK(octet_length(secret_hash)=32),
   scopes jsonb NOT NULL, ip_allow_list jsonb NOT NULL DEFAULT '[]',
   expires_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
   last_used_at timestamptz, revoked_at timestamptz
  )`,
		// 2026111402: GitHub webhook delivery check (state and redelivery retries).
		`ALTER TABLE ` + schema + `.connections ADD COLUMN IF NOT EXISTS webhook_check jsonb NOT NULL DEFAULT '{}'`,
		`CREATE TABLE IF NOT EXISTS ` + schema + `.github_redeliveries(connection_id uuid NOT NULL REFERENCES ` + schema + `.connections(id),guid text NOT NULL,hook_source text NOT NULL,hook_id bigint NOT NULL,delivery_id bigint NOT NULL,event text NOT NULL,status text NOT NULL CHECK(status IN ('retrying','delivered','abandoned','rejected')),status_code integer NOT NULL,attempts integer NOT NULL DEFAULT 0,first_failed_at timestamptz NOT NULL,last_attempt_at timestamptz,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(connection_id,guid))`,
		`CREATE INDEX IF NOT EXISTS github_redeliveries_retrying_idx ON ` + schema + `.github_redeliveries(connection_id) WHERE status='retrying'`,
		`CREATE TABLE IF NOT EXISTS ` + schema + `.audit_log (
			id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(),
			action text NOT NULL, target_id uuid, details jsonb NOT NULL DEFAULT '{}'
		)`,
	} {
		if _, err := tx.Exec(ctx, ddl); err != nil {
			return errors.New("PostgreSQL connection migration failed; check schema ownership and CREATE permission")
		}
	}
	for _, ddl := range assessments.Schema(schema) {
		if _, err := tx.Exec(ctx, ddl); err != nil {
			return errors.New("assessment schema migration failed")
		}
	}
	for _, ddl := range notify.Schema(schema) {
		if _, err := tx.Exec(ctx, ddl); err != nil {
			return errors.New("notification schema migration failed")
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+schema+`.schema_migrations(version) VALUES (2026111301),(2026111401),(2026111402) ON CONFLICT DO NOTHING`); err != nil {
		return errors.New("PostgreSQL migration version record failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("PostgreSQL connection migration commit failed")
	}
	return nil
}

// Check tests the app role, Redis operations and S3 object operations without
// changing application data. Each probe has a unique, short-lived name.
func Check(ctx context.Context, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return errors.New("PostgreSQL connection configuration failed")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("PostgreSQL connection failed; check SCRS_DATABASE_URL, network and TLS")
	}
	var migrationTable string
	if err := pool.QueryRow(ctx, "SELECT COALESCE(to_regclass($1)::text, '')", c.DatabaseSchema+".schema_migrations").Scan(&migrationTable); err != nil || migrationTable == "" {
		return errors.New("PostgreSQL SCRS schema is missing; run storage bootstrap")
	}
	if err := probeRedisQueue(ctx, c.RedisQueueURL); err != nil {
		return err
	}
	if err := probeRedisCache(ctx, c.RedisCacheURL); err != nil {
		return err
	}
	client, err := s3Client(c)
	if err != nil {
		return err
	}
	exists, err := client.BucketExists(ctx, c.S3Bucket)
	if err != nil || !exists {
		return errors.New("S3 bucket is unavailable; run storage bootstrap or check credentials")
	}
	return probeS3(ctx, client, c.S3Bucket)
}

// Ready performs a bounded, read-only check of each backing service.
func Ready(ctx context.Context, c Config) error {
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return errors.New("PostgreSQL unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("PostgreSQL unavailable")
	}
	redisURLs := []string{c.RedisQueueURL}
	if c.RedisCacheURL != c.RedisQueueURL {
		redisURLs = append(redisURLs, c.RedisCacheURL)
	}
	for _, rawURL := range redisURLs {
		opts, _ := redis.ParseURL(rawURL)
		client := redis.NewClient(opts)
		err := client.Ping(ctx).Err()
		_ = client.Close()
		if err != nil {
			return errors.New("Redis unavailable")
		}
	}
	client, err := s3Client(c)
	if err != nil {
		return errors.New("S3 unavailable")
	}
	exists, err := client.BucketExists(ctx, c.S3Bucket)
	if err != nil || !exists {
		return errors.New("S3 bucket unavailable")
	}
	return nil
}

func ensureDatabase(ctx context.Context, c Config) error {
	if c.DatabaseAdminURL == "" {
		return nil
	}
	appCfg, _ := pgxpool.ParseConfig(c.DatabaseURL)
	admin, err := pgx.Connect(ctx, c.DatabaseAdminURL)
	if err != nil {
		return errors.New("PostgreSQL admin connection failed; check SCRS_DATABASE_ADMIN_URL")
	}
	defer admin.Close(ctx)
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)", appCfg.ConnConfig.Database).Scan(&exists); err != nil {
		return errors.New("PostgreSQL database lookup failed")
	}
	if exists {
		return nil
	}
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{appCfg.ConnConfig.Database}.Sanitize()+" OWNER "+pgx.Identifier{appCfg.ConnConfig.User}.Sanitize())
	if err != nil {
		// A concurrent bootstrap may have created the database after the lookup.
		if checkErr := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)", appCfg.ConnConfig.Database).Scan(&exists); checkErr == nil && exists {
			return nil
		}
		return errors.New("PostgreSQL database creation failed; admin role needs CREATEDB and app role must exist")
	}
	return nil
}

func s3Client(c Config) (*minio.Client, error) {
	u, _ := url.Parse(c.S3Endpoint)
	lookup := minio.BucketLookupAuto
	if c.S3PathStyle {
		lookup = minio.BucketLookupPath
	}
	client, err := minio.New(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(c.S3AccessKey, c.S3SecretKey, ""),
		Secure:       u.Scheme == "https",
		Region:       c.S3Region,
		BucketLookup: lookup,
	})
	if err != nil {
		return nil, errors.New("S3 client configuration failed")
	}
	return client, nil
}

func probeRedisQueue(ctx context.Context, rawURL string) error {
	opts, _ := redis.ParseURL(rawURL)
	client := redis.NewClient(opts)
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		return errors.New("Redis queue connection failed; check SCRS_REDIS_QUEUE_URL, network and TLS")
	}
	key, err := probeKey("scrs:probe:queue:")
	if err != nil {
		return err
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: key, Values: map[string]any{"check": "ok"}}).Err(); err != nil {
		return errors.New("Redis queue stream write failed; check ACL for XADD")
	}
	removed := false
	defer func() {
		if !removed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = client.Del(cleanupCtx, key).Err()
		}
	}()
	if err := client.Expire(ctx, key, time.Minute).Err(); err != nil {
		return errors.New("Redis queue expiry failed; check EXPIRE ACL")
	}
	if values, err := client.XRangeN(ctx, key, "-", "+", 1).Result(); err != nil || len(values) != 1 {
		return errors.New("Redis queue stream read failed; check XRANGE ACL")
	}
	if err := client.Del(ctx, key).Err(); err != nil {
		return errors.New("Redis queue probe cleanup failed; check DEL ACL")
	}
	removed = true
	return nil
}

func probeRedisCache(ctx context.Context, rawURL string) error {
	opts, _ := redis.ParseURL(rawURL)
	client := redis.NewClient(opts)
	defer client.Close()
	key, err := probeKey("scrs:probe:cache:")
	if err != nil {
		return err
	}
	if err := client.Set(ctx, key, "ok", time.Minute).Err(); err != nil {
		return errors.New("Redis cache write failed; check SCRS_REDIS_CACHE_URL and SET ACL")
	}
	if value, err := client.Get(ctx, key).Result(); err != nil || value != "ok" {
		return errors.New("Redis cache read failed; check GET ACL")
	}
	if err := client.Del(ctx, key).Err(); err != nil {
		return errors.New("Redis cache probe cleanup failed; check DEL ACL")
	}
	return nil
}

func probeS3(ctx context.Context, client *minio.Client, bucket string) error {
	key, err := probeKey("scrs/probe/")
	if err != nil {
		return err
	}
	data := []byte("scrs-storage-probe")
	upload, err := client.PutObject(ctx, bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "text/plain"})
	if err != nil {
		return errors.New("S3 object write failed; check PutObject permission")
	}
	removeOptions := minio.RemoveObjectOptions{VersionID: upload.VersionID}
	removed := false
	defer func() {
		if !removed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = client.RemoveObject(cleanupCtx, bucket, key, removeOptions)
		}
	}()
	object, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return errors.New("S3 object read failed; check GetObject permission")
	}
	defer object.Close()
	read, err := io.ReadAll(io.LimitReader(object, int64(len(data)+1)))
	if err != nil || !bytes.Equal(read, data) {
		return errors.New("S3 object read failed or returned unexpected content")
	}
	if err := client.RemoveObject(ctx, bucket, key, removeOptions); err != nil {
		return errors.New("S3 probe cleanup failed; check DeleteObject or DeleteObjectVersion permission")
	}
	removed = true
	return nil
}

func probeKey(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("random probe id failed: %w", err)
	}
	return prefix + hex.EncodeToString(random[:]), nil
}
