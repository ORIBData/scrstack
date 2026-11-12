package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFoundationRoutesStayUnderBasePath(t *testing.T) {
	h := Handler()
	for _, tc := range []struct {
		path        string
		wantStatus  int
		contentType string
		contains    string
	}{
		{BasePath + "/system/healthz", 200, "application/json", `"status":"ok"`},
		{BasePath + "/system/readyz", 200, "application/json", `"status":"ok"`},
		{BasePath + "/docs/openapi.yaml", 200, "application/yaml", "openapi: 3.1.0"},
		{BasePath + "/docs", 200, "text/html", "/scrs/v1/docs/init.js"},
		{BasePath + "/docs/swagger-ui.css", 200, "text/css", "swagger-ui"},
		{BasePath + "/docs/swagger-ui-bundle.js", 200, "text/javascript", "SwaggerUIBundle"},
		{BasePath + "/docs/init.js", 200, "text/javascript", "/scrs/v1/docs/openapi.yaml"},
		{"/healthz", 404, "text/plain", "404"},
		{"/api/v1/assets", 404, "text/plain", "404"},
		{BasePath + "/assets", 404, "text/plain", "404"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if response.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d", response.Code, tc.wantStatus)
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), tc.contentType) {
				t.Errorf("content type %q, want %q", response.Header().Get("Content-Type"), tc.contentType)
			}
			if !strings.Contains(response.Body.String(), tc.contains) {
				t.Errorf("response does not contain %q", tc.contains)
			}
		})
	}
}

func TestReadinessFailsClosedWhenStorageIsUnavailable(t *testing.T) {
	h := HandlerWithReadiness(func(context.Context) error { return errors.New("backend down") })
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, BasePath+"/system/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "unavailable") {
		t.Fatalf("readiness response: %d %s", response.Code, response.Body.String())
	}
}

func TestDocsAssetPathDoesNotExposeOtherFiles(t *testing.T) {
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, BasePath+"/docs/LICENSE", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", response.Code)
	}
}
