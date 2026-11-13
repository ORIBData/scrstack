package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"regexp"

	"github.com/minio/minio-go/v7"
)

type Artifacts struct {
	client *minio.Client
	bucket string
}

func NewArtifacts(c Config) (*Artifacts, error) {
	client, err := s3Client(c)
	if err != nil {
		return nil, err
	}
	return &Artifacts{client, c.S3Bucket}, nil
}
func (a *Artifacts) PutSBOM(ctx context.Context, data []byte) (string, string, error) {
	if len(data) > 32<<20 {
		return "", "", errors.New("SBOM size exceeded")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	key := "sbom/" + digest + ".cdx.json"
	_, err := a.client.PutObject(ctx, a.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/vnd.cyclonedx+json"})
	return key, digest, err
}

var sbomKey = regexp.MustCompile(`^sbom/[a-f0-9]{64}\.cdx\.json$`)

func (a *Artifacts) GetSBOM(ctx context.Context, key string) ([]byte, error) {
	if !sbomKey.MatchString(key) {
		return nil, errors.New("invalid SBOM key")
	}
	object, err := a.client.GetObject(ctx, a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, (32<<20)+1))
	if err != nil || len(data) > 32<<20 {
		return nil, errors.New("SBOM unavailable")
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != key[5:69] {
		return nil, errors.New("SBOM integrity check failed")
	}
	return data, nil
}

func (a *Artifacts) PutPlan(ctx context.Context, data []byte) (string, string, error) {
	if len(data) > 8<<20 {
		return "", "", errors.New("plan size exceeded")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	key := "remediation/" + digest + ".json"
	_, err := a.client.PutObject(ctx, a.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/json"})
	return key, digest, err
}

var planKey = regexp.MustCompile(`^remediation/[a-f0-9]{64}\.json$`)

func (a *Artifacts) GetPlan(ctx context.Context, key string) ([]byte, error) {
	if !planKey.MatchString(key) {
		return nil, errors.New("invalid plan key")
	}
	object, err := a.client.GetObject(ctx, a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return nil, errors.New("plan unavailable")
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != key[12:76] {
		return nil, errors.New("plan integrity check failed")
	}
	return data, nil
}

var snapshotKey = regexp.MustCompile(`^snapshots/[a-f0-9]{64}\.tar\.gz$`)

// PutSnapshot stores a fetched source archive content-addressed (INT-006).
func (a *Artifacts) PutSnapshot(ctx context.Context, data []byte) (string, error) {
	if len(data) > 64<<20 {
		return "", errors.New("snapshot size exceeded")
	}
	hash := sha256.Sum256(data)
	key := "snapshots/" + hex.EncodeToString(hash[:]) + ".tar.gz"
	_, err := a.client.PutObject(ctx, a.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/gzip"})
	return key, err
}

func (a *Artifacts) GetSnapshot(ctx context.Context, key string) ([]byte, error) {
	if !snapshotKey.MatchString(key) {
		return nil, errors.New("invalid snapshot key")
	}
	object, err := a.client.GetObject(ctx, a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		return nil, errors.New("snapshot unavailable")
	}
	hash := sha256.Sum256(data)
	if "snapshots/"+hex.EncodeToString(hash[:])+".tar.gz" != key {
		return nil, errors.New("snapshot integrity check failed")
	}
	return data, nil
}

var mirrorKey = regexp.MustCompile(`^mirrors/[0-9a-f-]{36}\.bundle$`)

// PutMirror streams a git bundle into S3 without buffering it whole; minio
// uploads it in 16 MiB parts. The caller hashes the stream for integrity.
func (a *Artifacts) PutMirror(ctx context.Context, id string, r io.Reader) (string, int64, error) {
	key := "mirrors/" + id + ".bundle"
	if !mirrorKey.MatchString(key) {
		return "", 0, errors.New("invalid mirror id")
	}
	info, err := a.client.PutObject(ctx, a.bucket, key, r, -1, minio.PutObjectOptions{ContentType: "application/x-git-bundle", PartSize: 16 << 20})
	if err != nil {
		return "", 0, err
	}
	return key, info.Size, nil
}

// OpenMirror streams a stored bundle; the caller checks the recorded digest.
func (a *Artifacts) OpenMirror(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if !mirrorKey.MatchString(key) {
		return nil, 0, errors.New("invalid mirror key")
	}
	object, err := a.client.GetObject(ctx, a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, err
	}
	info, err := object.Stat()
	if err != nil {
		object.Close()
		return nil, 0, err
	}
	return object, info.Size, nil
}

// DeleteMirror removes a pruned bundle.
func (a *Artifacts) DeleteMirror(ctx context.Context, key string) error {
	if !mirrorKey.MatchString(key) {
		return errors.New("invalid mirror key")
	}
	return a.client.RemoveObject(ctx, a.bucket, key, minio.RemoveObjectOptions{})
}
