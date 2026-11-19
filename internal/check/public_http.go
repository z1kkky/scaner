package check

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/z1kkky/scaner/internal/targetscope"
)

// NewPublicHTTPClient returns a client that connects only to globally routable
// addresses. It resolves and checks DNS immediately before dialing, then dials
// the checked IP directly so DNS rebinding cannot change the destination.
// Environment-configured proxies are intentionally not used because they
// could bypass the destination check.
func NewPublicHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:            publicDialContext,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  10 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			IdleConnTimeout:        30 * time.Second,
		},
		Timeout: 15 * time.Second,
	}
}

// NewScopedHTTPClient preserves the request hostname (Host and TLS SNI) while
// the policy dialer connects only to the job's immutable address snapshot.
func NewScopedHTTPClient(policy *targetscope.Policy) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: policy.DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10, IdleConnTimeout: 30 * time.Second}, Timeout: 15 * time.Second}
}

var blockedPrefixes = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
		"100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7",
		"fe80::/10", "ff00::/8",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}()

func publicDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return publicDialContextWith(ctx, network, address, net.DefaultResolver.LookupNetIP, dialer.DialContext)
}

func publicDialContextWith(ctx context.Context, network, address string, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		ips, err = lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for target")
	}
	for _, ip := range ips {
		if !isPublicAddress(ip.Unmap()) {
			return nil, fmt.Errorf("target resolves to a non-public address")
		}
	}
	var dialErr error
	for _, ip := range ips {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, dialErr
}

func isPublicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
