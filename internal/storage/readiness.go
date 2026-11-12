package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// NewReadiness reuses bounded client pools across probes. Its close function
// must be called after HTTP shutdown, not after each health request.
func NewReadiness(ctx context.Context, c Config) (func(context.Context) error, func(), error) {
	options, err := pgxpool.ParseConfig(c.DatabaseURL)
	if err != nil {
		return nil, nil, errors.New("invalid readiness database configuration")
	}
	options.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, options)
	if err != nil {
		return nil, nil, errors.New("readiness pool unavailable")
	}
	var clients []*redis.Client
	closeAll := func() {
		pool.Close()
		for _, client := range clients {
			_ = client.Close()
		}
	}
	urls := []string{c.RedisQueueURL}
	if c.RedisCacheURL != c.RedisQueueURL {
		urls = append(urls, c.RedisCacheURL)
	}
	for _, url := range urls {
		opts, err := redis.ParseURL(url)
		if err != nil {
			closeAll()
			return nil, nil, errors.New("invalid readiness Redis configuration")
		}
		opts.PoolSize = 2
		clients = append(clients, redis.NewClient(opts))
	}
	object, err := s3Client(c)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	check := func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return errors.New("PostgreSQL unavailable")
		}
		for _, client := range clients {
			if err := client.Ping(ctx).Err(); err != nil {
				return errors.New("Redis unavailable")
			}
		}
		exists, err := object.BucketExists(ctx, c.S3Bucket)
		if err != nil || !exists {
			return errors.New("S3 bucket unavailable")
		}
		return nil
	}
	return check, closeAll, nil
}
