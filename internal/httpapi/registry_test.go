package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/connections"
)

func TestParseRegistryEvents(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	gar := base64.StdEncoding.EncodeToString([]byte(`{"action":"INSERT","digest":"us-docker.pkg.dev/p/r/img@` + digest + `","tag":"us-docker.pkg.dev/p/r/img:1.2"}`))
	for _, tc := range []struct {
		provider, body string
		want           []imagePush
	}{
		{"harbor", `{"type":"PUSH_ARTIFACT","event_data":{"resources":[{"digest":"` + digest + `","tag":"1.0","resource_url":"Harbor.Example.com/apps/web:1.0"}],"repository":{"repo_full_name":"apps/web"}}}`, []imagePush{{"harbor.example.com/apps/web", "1.0", digest}}},
		{"harbor", `{"type":"PULL_ARTIFACT","event_data":{}}`, nil},
		{"dockerhub", `{"push_data":{"tag":"latest"},"repository":{"repo_name":"Acme/API"}}`, []imagePush{{"docker.io/acme/api", "latest", ""}}},
		{"gar", `{"message":{"data":"` + gar + `"}}`, []imagePush{{"us-docker.pkg.dev/p/r/img", "1.2", digest}}},
		{"gar", `{"action":"DELETE","digest":"x"}`, nil},
		{"oci", `{"events":[{"action":"push","target":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + digest + `","repository":"apps/web","url":"https://reg.example.com:5000/v2/apps/web/manifests/` + digest + `","tag":"2.0"}},{"action":"push","target":{"mediaType":"application/octet-stream","repository":"apps/web"}},{"action":"pull","target":{"mediaType":"application/vnd.oci.image.manifest.v1+json","repository":"apps/web"}}]}`, []imagePush{{"reg.example.com:5000/apps/web", "2.0", digest}}},
	} {
		got, err := parseRegistryEvent(tc.provider, []byte(tc.body))
		if err != nil || len(got) != len(tc.want) {
			t.Fatalf("%s: got %v err %v", tc.provider, got, err)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: got %+v want %+v", tc.provider, got[i], tc.want[i])
			}
		}
	}
	if _, err := parseRegistryEvent("quay", []byte(`{}`)); err != errRegistryProvider {
		t.Fatal("unknown provider accepted")
	}
}

func TestGitLabPayloadMapping(t *testing.T) {
	zero := strings.Repeat("0", 40)
	sha := strings.Repeat("b", 40)
	event, p, ok := gitlabPayload("Push Hook", []byte(`{"object_kind":"push","ref":"refs/heads/main","before":"`+zero+`","after":"`+sha+`","user_username":"dev","project":{"path_with_namespace":"team/app","default_branch":"main"},"commits":[{"id":"`+sha+`","message":"m","removed":["a"]}]}`))
	if !ok || event != "push" || p.Repository.FullName != "team/app" || !p.Created || p.Deleted || p.Pusher.Name != "dev" || len(p.Commits) != 1 || p.Commits[0].Removed[0] != "a" {
		t.Fatalf("push mapping: %s %+v", event, p)
	}
	event, p, _ = gitlabPayload("Merge Request Hook", []byte(`{"object_kind":"merge_request","user":{"username":"dev"},"project":{"path_with_namespace":"team/app"},"object_attributes":{"iid":7,"title":"t","source_branch":"f","target_branch":"main","action":"update","oldrev":"`+zero+`","last_commit":{"id":"`+sha+`"}}}`))
	if event != "pull_request" || p.Action != "synchronize" || p.PullRequest.Number != 7 || p.PullRequest.Head.SHA != sha || p.PullRequest.Base.Ref != "main" {
		t.Fatalf("merge request mapping: %+v", p)
	}
	_, p, _ = gitlabPayload("Merge Request Hook", []byte(`{"object_kind":"merge_request","project":{"path_with_namespace":"team/app"},"object_attributes":{"action":"update"}}`))
	if p.Action != "update" {
		t.Fatal("metadata-only update must not trigger a scan", p.Action)
	}
	if event, _, ok := gitlabPayload("Pipeline Hook", []byte(`{}`)); event != "" || !ok {
		t.Fatal("unsupported GitLab hooks should be acknowledged")
	}
	if _, _, ok := gitlabPayload("Push Hook", []byte(`{"project":{}}`)); ok {
		t.Fatal("push without project accepted")
	}
}

// A relay that forwards a provider signature must forward a valid one.
func TestRelayVerifiesForwardedSignatures(t *testing.T) {
	g := newGitHubIngest(nil, strings.Repeat("s", 40), false, true)
	g.gitlabSecret = strings.Repeat("g", 40)
	principal := context.WithValue(context.Background(), principalKey{}, connections.Token{Name: "n8n"})
	for _, tc := range []struct {
		provider, header, value string
	}{{"github", "X-Hub-Signature-256", "sha256=" + strings.Repeat("0", 64)}, {"gitlab", "X-Gitlab-Token", "wrong"}} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`)).WithContext(principal)
		r.Header.Set(tc.header, tc.value)
		w := httptest.NewRecorder()
		g.relay(tc.provider).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s forged forwarded signature: %d", tc.provider, w.Code)
		}
	}
	g.gitlabSecret = ""
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`)).WithContext(principal)
	r.Header.Set("X-Gitlab-Token", "anything")
	w := httptest.NewRecorder()
	g.relay("gitlab").ServeHTTP(w, r)
	// With no provider secret configured the forwarded value cannot be
	// checked: the relay token alone decides, and processing continues to
	// header validation instead of breaking relays that forward it.
	if w.Code != http.StatusBadRequest {
		t.Fatal("relay without a configured provider secret should rely on the token", w.Code)
	}
	w = httptest.NewRecorder()
	g.direct("gitlab").ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("GitLab direct ingest without a secret must be unavailable", w.Code)
	}
}
