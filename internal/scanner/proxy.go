package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func allowedProxyHost(host string) bool {
	switch strings.ToLower(host) {
	case "api.deps.dev", "deps.dev", "registry.npmjs.org":
		return true
	}
	return false
}
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
func EgressProxy() http.Handler {
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil || r.Method != "CONNECT" || port != "443" || !allowedProxyHost(host) {
			http.Error(w, "egress destination forbidden", 403)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "egress capacity exceeded", 503)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			http.Error(w, "destination unavailable", 502)
			return
		}
		for _, ip := range addresses {
			if !publicAddress(ip) {
				http.Error(w, "nonpublic destination rejected", 403)
				return
			}
		}
		upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].String(), port))
		if err != nil {
			http.Error(w, "destination unavailable", 502)
			return
		}
		defer upstream.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "tunnel unavailable", 500)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_ = upstream.SetDeadline(time.Now().Add(5 * time.Minute))
		_ = client.SetDeadline(time.Now().Add(5 * time.Minute))
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if buffer.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.CopyN(upstream, buffer, 64<<20); _ = upstream.Close(); close(done) }()
		_, _ = io.CopyN(client, upstream, 64<<20)
		_ = client.Close()
		<-done
	})
}
