package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

func TestS3ArtifactsRoundTripAndTamper(t *testing.T) {
	endpoint := os.Getenv("SCRS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires disposable MinIO")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := NewArtifacts(Config{S3Endpoint: endpoint, S3Region: "us-east-1", S3Bucket: "qa-" + uuid.NewString(), S3AccessKey: "synthetic-access", S3SecretKey: "synthetic-secret", S3PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.client.MakeBucket(ctx, a.bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		t.Fatal(err)
	}
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	key, digest, err := a.PutSBOM(ctx, sbom)
	if err != nil || len(digest) != 64 {
		t.Fatal(err)
	}
	data, err := a.GetSBOM(ctx, key)
	if err != nil || !bytes.Equal(sbom, data) {
		t.Fatal("SBOM roundtrip failed", err)
	}
	plan := []byte(`{"strategy":"in-place","changes":[]}`)
	planKey, _, err := a.PutPlan(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	data, err = a.GetPlan(ctx, planKey)
	if err != nil || !bytes.Equal(plan, data) {
		t.Fatal("plan roundtrip failed", err)
	}
	if _, err := a.GetSBOM(ctx, "../other-object"); err == nil {
		t.Fatal("arbitrary object key accepted")
	}
	if _, err := a.client.PutObject(ctx, a.bucket, key, strings.NewReader("tampered"), 8, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSBOM(ctx, key); err == nil {
		t.Fatal("artifact corruption not detected")
	}
	// Mirrors stream in multipart chunks larger than one part.
	bundle := bytes.Repeat([]byte("git-bundle-"), 2<<20)
	id := "00000000-0000-4000-8000-000000000001"
	mirrorKey, size, err := a.PutMirror(ctx, id, bytes.NewReader(bundle))
	if err != nil || size != int64(len(bundle)) {
		t.Fatal("mirror upload failed", err, size)
	}
	body, n, err := a.OpenMirror(ctx, mirrorKey)
	if err != nil || n != size {
		t.Fatal("mirror open failed", err)
	}
	got, _ := io.ReadAll(body)
	body.Close()
	if !bytes.Equal(got, bundle) {
		t.Fatal("mirror roundtrip failed")
	}
	if _, _, err := a.PutMirror(ctx, "../escape", bytes.NewReader(nil)); err == nil {
		t.Fatal("arbitrary mirror key accepted")
	}
	if err := a.DeleteMirror(ctx, mirrorKey); err != nil {
		t.Fatal(err)
	}
	if body, _, err := a.OpenMirror(ctx, mirrorKey); err == nil {
		body.Close()
		t.Fatal("deleted mirror still readable")
	}
	archive := []byte("\x1f\x8bsynthetic-archive")
	snapKey, err := a.PutSnapshot(ctx, archive)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := a.GetSnapshot(ctx, snapKey); err != nil || !bytes.Equal(archive, data) {
		t.Fatal("snapshot roundtrip failed", err)
	}
	if _, err := a.GetSnapshot(ctx, "sbom/"+digest+".cdx.json"); err == nil {
		t.Fatal("snapshot reader accepted another artifact class")
	}
	if _, err := a.client.PutObject(ctx, a.bucket, snapKey, strings.NewReader("tampered"), 8, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSnapshot(ctx, snapKey); err == nil {
		t.Fatal("snapshot corruption not detected")
	}
	for _, object := range []string{key, planKey, snapKey} {
		if err := a.client.RemoveObject(ctx, a.bucket, object, minio.RemoveObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.client.RemoveBucket(ctx, a.bucket); err != nil {
		t.Fatal(err)
	}
}
