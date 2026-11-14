// Package netguard keeps outbound requests to operator-configured URLs
// (webhooks, threat-intelligence feeds) off internal networks.
package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Special-purpose ranges that are not reachable public destinations
// (RFC 6890): "this network", carrier-grade NAT, IETF protocol assignments,
// benchmarking, reserved, and NAT64 (which can front private IPv4).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
}

// Public reports a globally routable unicast address.
func Public(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// DialContext connects only to addresses it validated itself, so DNS cannot
// rebind a public name to an internal service between check and connect.
// Hosts in private (lower-case names) may resolve to non-public addresses.
func DialContext(private map[string]bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("destination unresolvable")
		}
		allowed := private[strings.ToLower(host)]
		for _, ip := range ips {
			if !allowed && !Public(ip) {
				return nil, errors.New("destination address not permitted")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}

// Hosts parses a comma-separated hostname list (for example
// SCRS_TAXII_PRIVATE_HOSTS) into the set DialContext accepts.
func Hosts(list string) map[string]bool {
	hosts := map[string]bool{}
	for _, h := range strings.Split(list, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts[h] = true
		}
	}
	return hosts
}
