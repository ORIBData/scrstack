package storage

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

type Config struct {
	DatabaseURL      string
	DatabaseAdminURL string
	DatabaseSchema   string
	RedisQueueURL    string
	RedisCacheURL    string
	S3Endpoint       string
	S3Region         string
	S3Bucket         string
	S3AccessKey      string
	S3SecretKey      string
	S3PathStyle      bool
}

func ConfigFromEnv() (Config, error) {
	c := Config{
		DatabaseURL:      os.Getenv("SCRS_DATABASE_URL"),
		DatabaseAdminURL: os.Getenv("SCRS_DATABASE_ADMIN_URL"),
		DatabaseSchema:   os.Getenv("SCRS_DATABASE_SCHEMA"),
		RedisQueueURL:    os.Getenv("SCRS_REDIS_QUEUE_URL"),
		RedisCacheURL:    os.Getenv("SCRS_REDIS_CACHE_URL"),
		S3Endpoint:       os.Getenv("SCRS_S3_ENDPOINT"),
		S3Region:         os.Getenv("SCRS_S3_REGION"),
		S3Bucket:         os.Getenv("SCRS_S3_BUCKET"),
		S3AccessKey:      os.Getenv("SCRS_S3_ACCESS_KEY"),
		S3SecretKey:      os.Getenv("SCRS_S3_SECRET_KEY"),
	}
	if c.DatabaseSchema == "" {
		c.DatabaseSchema = "scrs"
	}
	if c.RedisCacheURL == "" {
		c.RedisCacheURL = c.RedisQueueURL
	}
	if raw := os.Getenv("SCRS_S3_FORCE_PATH_STYLE"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, errors.New("SCRS_S3_FORCE_PATH_STYLE must be true or false")
		}
		c.S3PathStyle = value
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	for _, item := range []struct{ name, value string }{
		{"SCRS_DATABASE_URL", c.DatabaseURL},
		{"SCRS_REDIS_QUEUE_URL", c.RedisQueueURL},
		{"SCRS_S3_ENDPOINT", c.S3Endpoint},
		{"SCRS_S3_REGION", c.S3Region},
		{"SCRS_S3_BUCKET", c.S3Bucket},
		{"SCRS_S3_ACCESS_KEY", c.S3AccessKey},
		{"SCRS_S3_SECRET_KEY", c.S3SecretKey},
	} {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("%s is required", item.name)
		}
	}
	if !schemaName.MatchString(c.DatabaseSchema) {
		return errors.New("SCRS_DATABASE_SCHEMA must be a lowercase PostgreSQL identifier")
	}
	for _, item := range []struct{ name, value string }{
		{"SCRS_DATABASE_URL", c.DatabaseURL},
		{"SCRS_DATABASE_ADMIN_URL", c.DatabaseAdminURL},
	} {
		if item.value == "" {
			continue
		}
		u, parseErr := url.Parse(item.value)
		if parseErr != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" || strings.Trim(u.Path, "/") == "" {
			return fmt.Errorf("%s must be a PostgreSQL URL with a database name", item.name)
		}
		cfg, err := pgxpool.ParseConfig(item.value)
		if err != nil || cfg.ConnConfig.Database == "" {
			return fmt.Errorf("%s must be a PostgreSQL URL with a database name", item.name)
		}
	}
	for _, item := range []struct{ name, value string }{
		{"SCRS_REDIS_QUEUE_URL", c.RedisQueueURL},
		{"SCRS_REDIS_CACHE_URL", c.RedisCacheURL},
	} {
		if _, err := redis.ParseURL(item.value); err != nil {
			return fmt.Errorf("%s must be a redis:// or rediss:// URL", item.name)
		}
	}
	u, err := url.Parse(c.S3Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("SCRS_S3_ENDPOINT must be an http(s) origin without credentials, path or query")
	}
	return nil
}
