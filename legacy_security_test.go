package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacySecurity(t *testing.T) {
	token := strings.Repeat("s", 40)
	for _, c := range []struct {
		configured, provided, path string
		want                       int
	}{
		{"", "", "/v2/scan", 503},
		{token, "", "/v2/scan", 401},
		{token, token, "/scanPath", 410},
		{token, token, "/scanFile", 410},
		{token, token, "/v2/scan", 204},
	} {
		handler := legacySecurity(c.configured, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		r := httptest.NewRequest("POST", c.path, nil)
		r.Header.Set("Authorization", "Bearer "+c.provided)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s got %d want %d", c.path, w.Code, c.want)
		}
	}
}
func TestMalformedMultipartDoesNotPanic(t *testing.T) {
	r := httptest.NewRequest("POST", "/v2/scan", strings.NewReader("--boundary\r\nbad multipart"))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	w := httptest.NewRecorder()
	scanner(w, r, 2)
	if w.Code != 400 {
		t.Fatalf("got %d want 400", w.Code)
	}
}
