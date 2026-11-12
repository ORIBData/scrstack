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
