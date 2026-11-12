package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

type fakeConnectionStore struct {
	items []connections.Connection
}

func (s *fakeConnectionStore) List(context.Context) ([]connections.Connection, error) {
	return s.items, nil
}
func (s *fakeConnectionStore) Put(_ context.Context, c connections.Connection, _ json.RawMessage, _ bool) (bool, error) {
	for _, item := range s.items {
		if item.Name == c.Name {
			return false, nil
		}
	}
	c.ID = uuid.New()
	c.Status = json.RawMessage(`{}`)
	s.items = append(s.items, c)
	return true, nil
}
func (s *fakeConnectionStore) PublicByID(_ context.Context, id uuid.UUID) (connections.Connection, error) {
	for _, item := range s.items {
		if item.ID == id {
			return item, nil
		}
	}
	return connections.Connection{}, context.Canceled
}
func (s *fakeConnectionStore) PublicByName(_ context.Context, name string) (connections.Connection, error) {
	for _, item := range s.items {
		if item.Name == name {
			return item, nil
		}
	}
	return connections.Connection{}, context.Canceled
}
func (s *fakeConnectionStore) NameByID(_ context.Context, id uuid.UUID) (string, error) {
	for _, item := range s.items {
		if item.ID == id {
			return item.Name, nil
		}
	}
	return "", context.Canceled
}
func (s *fakeConnectionStore) Test(context.Context, string, connections.Adapter) (int, error) {
	return 1, nil
}
func (s *fakeConnectionStore) Discover(context.Context, string, connections.Adapter) (connections.DiscoveryResult, error) {
	return connections.DiscoveryResult{Discovered: 1, InScope: 1}, nil
}
func (s *fakeConnectionStore) ListAssetsPage(context.Context, int, string, uuid.UUID) ([]connections.Asset, error) {
	return []connections.Asset{}, nil
}

func TestConnectionAPIRequiresTokenAndRedactsSecrets(t *testing.T) {
	store := &fakeConnectionStore{}
	token := strings.Repeat("t", 40)
	handler := HandlerWithConnections(nil, store, token)
	body := `{"provider":"github","name":"org-one","config":{"organization":"org","auth_type":"fine_grained_pat"},"scope":{"include":["org/*"]},"credential":{"token":"super-private-token"}}`
	request := func(method, path, auth, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("POST", BasePath+"/connections", "", body); w.Code != 401 || len(store.items) != 0 {
		t.Fatalf("unauthorized create: %d", w.Code)
	}
	if w := request("GET", BasePath+"/connections", "wrong", ""); w.Code != 401 {
		t.Fatalf("unauthorized list: %d", w.Code)
	}
	w := request("POST", BasePath+"/connections", token, body)
	if w.Code != 201 || strings.Contains(w.Body.String(), "super-private-token") {
		t.Fatalf("create response: %d %s", w.Code, w.Body.String())
	}
	w = request("POST", BasePath+"/connections", token, body)
	if w.Code != 409 {
		t.Fatalf("duplicate create: %d", w.Code)
	}
	w = request("GET", BasePath+"/connections", token, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "super-private-token") {
		t.Fatalf("list response: %d %s", w.Code, w.Body.String())
	}
	id := store.items[0].ID.String()
	if w := request("GET", BasePath+"/assets", token, ""); w.Code != 200 {
		t.Fatalf("asset list: %d", w.Code)
	}
	if w := request("GET", BasePath+"/assets?limit=501", token, ""); w.Code != 400 {
		t.Fatalf("oversized page accepted: %d", w.Code)
	}
	if w := request("GET", BasePath+"/assets?cursor=invalid", token, ""); w.Code != 400 {
		t.Fatalf("invalid cursor accepted: %d", w.Code)
	}
	if w := request("POST", BasePath+"/connections/"+id+":test", token, ""); w.Code != 200 {
		t.Fatalf("test route: %d", w.Code)
	}
	if w := request("POST", BasePath+"/connections/"+id+":discover", token, ""); w.Code != 200 {
		t.Fatalf("discover route: %d", w.Code)
	}
}

func TestConnectionAPIRejectsSecretInConfigAndOversizedBody(t *testing.T) {
	store := &fakeConnectionStore{}
	token := strings.Repeat("t", 40)
	handler := HandlerWithConnections(nil, store, token)
	for _, body := range []string{
		`{"provider":"github","name":"bad","config":{"organization":"org","auth_type":"fine_grained_pat","token":"leak"},"scope":{"include":["org/*"]},"credential":{"token":"secret"}}`,
		strings.Repeat("x", 100000),
	} {
		r := httptest.NewRequest(http.MethodPost, BasePath+"/connections", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 400 || len(store.items) != 0 {
			t.Fatalf("invalid request accepted: %d", w.Code)
		}
	}
}
