package connections

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/oauth2/google"
)

var imageDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// limitedWriter fails once more than limit bytes have been written.
type limitedWriter struct {
	w     io.Writer
	limit int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.limit {
		return 0, errors.New("image exceeded size limit")
	}
	l.limit -= int64(len(p))
	return l.w.Write(p)
}

func (a NativeAdapters) registryAuth(ctx context.Context, c Connection, secret json.RawMessage) (authn.Authenticator, error) {
	switch c.Provider {
	case "dockerhub":
		var cfg struct {
			Identifier string `json:"identifier"`
		}
		var cred struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(c.Config, &cfg) != nil || json.Unmarshal(secret, &cred) != nil || cfg.Identifier == "" || cred.Token == "" {
			return nil, errors.New("Docker Hub credential invalid")
		}
		return &authn.Basic{Username: cfg.Identifier, Password: cred.Token}, nil
	case "gar":
		var cred struct {
			ServiceAccountJSON json.RawMessage `json:"service_account_json"`
		}
		if json.Unmarshal(secret, &cred) != nil {
			return nil, errors.New("GAR credential invalid")
		}
		creds, err := google.CredentialsFromJSONWithType(ctx, cred.ServiceAccountJSON, google.ServiceAccount, "https://www.googleapis.com/auth/cloud-platform.read-only")
		if err != nil {
			return nil, errors.New("GAR service account JSON invalid")
		}
		token, err := creds.TokenSource.Token()
		if err != nil {
			return nil, errors.New("GAR OAuth token request failed")
		}
		return &authn.Basic{Username: "oauth2accesstoken", Password: token.AccessToken}, nil
	}
	return nil, errors.New("provider has no image registry")
}

// ImageArchive resolves an in-scope image to one platform's manifest digest
// and streams it as a docker-save archive to w (M6, ING-002/003). The tag is
// a hint: the assessment belongs to the digest (TRG-003). Images whose
// compressed layers exceed limit are rejected before any layer is fetched.
func (a NativeAdapters) ImageArchive(ctx context.Context, c Connection, secret json.RawMessage, locator, tag, digest, platform string, limit int64, w io.Writer) (string, error) {
	if !c.Enabled || !c.Scope.matchesResource(Resource{Type: "container_image", Locator: locator}) {
		return "", errors.New("image is outside connection scope")
	}
	host, _, _ := strings.Cut(locator, "/")
	switch {
	case a.RegistryHost != "":
		if host != a.RegistryHost {
			return "", errors.New("image registry does not match connection")
		}
	case c.Provider == "dockerhub" && host != "docker.io",
		c.Provider == "gar" && !strings.HasSuffix(host, "-docker.pkg.dev"):
		return "", errors.New("image registry does not match connection")
	}
	reference := locator + ":" + tag
	if digest != "" {
		if !imageDigest.MatchString(digest) {
			return "", errors.New("invalid image digest")
		}
		reference = locator + "@" + digest
	}
	options := []name.Option{name.StrictValidation}
	if a.RegistryHost != "" {
		options = append(options, name.Insecure) // tests against a local registry only
	}
	ref, err := name.ParseReference(reference, options...)
	if err != nil {
		return "", errors.New("invalid image reference")
	}
	auth, err := a.registryAuth(ctx, c, secret)
	if err != nil && a.RegistryHost == "" {
		return "", err
	}
	if auth == nil {
		auth = authn.Anonymous
	}
	plat, err := v1.ParsePlatform(platform)
	if err != nil {
		return "", errors.New("invalid platform")
	}
	remoteOptions := []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithPlatform(*plat)}
	if a.Client != nil && a.Client.Transport != nil {
		remoteOptions = append(remoteOptions, remote.WithTransport(a.Client.Transport))
	}
	image, err := remote.Image(ref, remoteOptions...)
	if err != nil {
		return "", errors.New("image resolution failed; check reference, platform and registry credential")
	}
	resolved, err := image.Digest()
	if err != nil {
		return "", errors.New("image digest unavailable")
	}
	// A digest naming a multi-platform index resolves to the selected
	// platform's image; the assessment records the digest actually scanned.
	layers, err := image.Layers()
	if err != nil {
		return "", errors.New("image layers unavailable")
	}
	var total int64
	for _, layer := range layers {
		size, err := layer.Size()
		if err != nil {
			return "", errors.New("image layer size unavailable")
		}
		total += size
	}
	if total > limit {
		return "", errors.New("image exceeds SCRS_MAX_IMAGE_BYTES")
	}
	tagged, err := name.NewTag(locator+":scrs", options...)
	if err != nil {
		return "", err
	}
	// The archive carries the layer blobs as stored plus small manifests; the
	// scanner applies the same SCRS_MAX_IMAGE_BYTES cap to what it receives.
	if err := tarball.Write(tagged, image, &limitedWriter{w: w, limit: limit + 1<<20}); err != nil {
		return "", errors.New("image archive stream failed")
	}
	return resolved.String(), nil
}
