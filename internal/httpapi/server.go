package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/api"
)

const BasePath = "/scrs/v1"

// Handler exposes only implemented routes. Future modules register under BasePath.
func Handler() http.Handler {
	return HandlerWithReadiness(nil)
}

// HandlerWithReadiness checks backing services for the readiness endpoint.
// Results are cached briefly to keep public health polling inexpensive.
func HandlerWithReadiness(check func(context.Context) error) http.Handler {
	return HandlerWithConnections(check, nil, "")
}

func HandlerWithConnections(check func(context.Context) error, store ConnectionStore, bootstrapToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+BasePath+"/system/healthz", health)
	mux.Handle("GET "+BasePath+"/system/readyz", readiness(check))
	mux.HandleFunc("GET "+BasePath+"/docs/openapi.yaml", openAPI)
	mux.HandleFunc("GET "+BasePath+"/docs", docs)
	mux.HandleFunc("GET "+BasePath+"/docs/", docs)
	mux.Handle("GET "+BasePath+"/docs/swagger-ui.css", swaggerAsset("swagger/swagger-ui.css", "text/css; charset=utf-8"))
	mux.Handle("GET "+BasePath+"/docs/swagger-ui-bundle.js", swaggerAsset("swagger/swagger-ui-bundle.js", "text/javascript; charset=utf-8"))
	mux.Handle("GET "+BasePath+"/docs/init.js", swaggerAsset("swagger/init.js", "text/javascript; charset=utf-8"))
	if store != nil {
		connections := connectionHandler{store: store, tokenHash: hashToken(bootstrapToken)}
		mux.Handle("GET "+BasePath+"/connections", connections)
		mux.Handle("POST "+BasePath+"/connections", connections)
		mux.Handle(BasePath+"/connections/", connections)
		mux.Handle("GET "+BasePath+"/assets", connections)
	}
	return mux
}

func readiness(check func(context.Context) error) http.Handler {
	var mu sync.Mutex
	var checkedAt time.Time
	var lastErr error
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		if check != nil && time.Since(checkedAt) >= 10*time.Second {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			lastErr = check(ctx)
			checkedAt = time.Now()
			cancel()
		}
		err := lastErr
		mu.Unlock()
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		health(w, nil)
	})
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(api.OpenAPI)
}

const swaggerHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCRS API docs</title><link rel="stylesheet" href="/scrs/v1/docs/swagger-ui.css">
</head><body><div id="swagger-ui"></div>
<script src="/scrs/v1/docs/swagger-ui-bundle.js"></script>
<script src="/scrs/v1/docs/init.js"></script>
</body></html>`

func docs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != BasePath+"/docs" && r.URL.Path != BasePath+"/docs/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src data:; connect-src 'self'; font-src 'self'")
	_, _ = w.Write([]byte(swaggerHTML))
}

func swaggerAsset(path, contentType string) http.Handler {
	data, readErr := api.Swagger.ReadFile(path)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if readErr != nil {
			http.Error(w, "Swagger UI asset unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
}
