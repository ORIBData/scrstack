package httpapi

import "net/http"

// routeObserver, when set by a test, receives every pattern registered on the
// router so the contract can be checked against the routes that really exist.
var routeObserver func(pattern string)

// routeMux is the router: a ServeMux that reports what is registered on it.
type routeMux struct{ *http.ServeMux }

func (m routeMux) Handle(pattern string, handler http.Handler) {
	if routeObserver != nil {
		routeObserver(pattern)
	}
	m.ServeMux.Handle(pattern, handler)
}

func (m routeMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(handler))
}
