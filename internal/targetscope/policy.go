// Package targetscope freezes DNS-verified targets for one scan job.
package targetscope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// TargetResolver resolves the complete CNAME path and terminal addresses as
// one admission operation. Implementations must query A/AAAA on the validated
// terminal name directly, rejecting any CNAME not present in the returned
// chain.
type TargetResolver interface {
	ResolveTarget(context.Context, string) ([]string, []netip.Addr, error)
}

type systemResolver struct{}

func (systemResolver) LookupTXT(ctx context.Context, n string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, n)
}
func (systemResolver) LookupCNAME(ctx context.Context, n string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, n)
}
func (systemResolver) LookupNetIP(ctx context.Context, network, n string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, n)
}

// Challenge creates an unguessable DNS TXT value for a canonical hostname.
type Challenge struct {
	Host   string `json:"host"`
	Record string `json:"record"`
	Value  string `json:"value"`
}

func NewChallenge(host string) (Challenge, error) {
	h, err := canonical(host)
	if err != nil {
		return Challenge{}, err
	}
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return Challenge{}, err
	}
	return Challenge{Host: h, Record: "_scaner-verification." + h, Value: "scaner-verification=" + hex.EncodeToString(b)}, nil
}
func VerifyTXT(ctx context.Context, r Resolver, c Challenge) error {
	if r == nil {
		r = systemResolver{}
	}
	h, err := canonical(c.Host)
	if err != nil || h != c.Host || c.Record != "_scaner-verification."+h || c.Value == "" {
		return errors.New("invalid verification challenge")
	}
	values, err := r.LookupTXT(ctx, c.Record)
	if err != nil {
		return fmt.Errorf("lookup verification TXT: %w", err)
	}
	for _, v := range values {
		if v == c.Value {
			return nil
		}
	}
	return errors.New("verification TXT record does not match")
}

// Policy contains a frozen set of verified names, addresses, and ports. Its
// state is private and all collection accessors return copies.
type Policy struct {
	root        string
	addresses   map[string][]netip.Addr
	cnameChains map[string][]string
	ports       map[uint16]struct{}
	dial        func(context.Context, string, string) (net.Conn, error)
}

// Freeze resolves explicit names once and rejects any unsafe answer. Hosts may
// only be the root or its label-boundary subdomains; no enumeration occurs.
func Freeze(ctx context.Context, r Resolver, root string, hosts []string, ports []uint16) (*Policy, error) {
	return FreezeWithDial(ctx, r, root, hosts, ports, nil)
}

// FreezeWithDial is Freeze with an injectable socket dialer, primarily for
// deterministic tests. The resolver is still used only during admission.
func FreezeWithDial(ctx context.Context, r Resolver, root string, hosts []string, ports []uint16, dial func(context.Context, string, string) (net.Conn, error)) (*Policy, error) {
	if r == nil {
		r = systemResolver{}
	}
	root, err := canonical(root)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		hosts = []string{root}
	}
	p := &Policy{root: root, addresses: make(map[string][]netip.Addr), cnameChains: make(map[string][]string), ports: make(map[uint16]struct{}), dial: dial}
	for _, port := range ports {
		if port == 0 {
			return nil, errors.New("port zero is not allowed")
		}
		p.ports[port] = struct{}{}
	}
	for _, raw := range hosts {
		h, err := canonical(raw)
		if err != nil {
			return nil, err
		}
		if h != root && !strings.HasSuffix(h, "."+root) {
			return nil, fmt.Errorf("target %q is outside verified hostname", h)
		}
		if _, ok := p.addresses[h]; ok {
			continue
		}
		targetResolver, ok := r.(TargetResolver)
		if !ok {
			return nil, errors.New("resolver cannot atomically validate CNAME chain and terminal addresses")
		}
		chain, ips, err := targetResolver.ResolveTarget(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("resolve scoped target %s: %w", h, err)
		}
		chain, err = canonicalCNAMEChain(h, chain)
		if err != nil {
			return nil, fmt.Errorf("validate CNAME chain for %s: %w", h, err)
		}
		for _, hop := range chain {
			if hop != root && !strings.HasSuffix(hop, "."+root) {
				return nil, fmt.Errorf("external CNAME target %q is not allowed", hop)
			}
		}
		p.cnameChains[h] = append([]string(nil), chain...)
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", h)
		}
		seen := map[netip.Addr]bool{}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !public(ip) {
				return nil, fmt.Errorf("%s resolves to a non-public address", h)
			}
			if !seen[ip] {
				seen[ip] = true
				p.addresses[h] = append(p.addresses[h], ip)
			}
		}
	}
	return p, nil
}
func (p *Policy) Root() string {
	if p == nil {
		return ""
	}
	return p.root
}
func (p *Policy) Hosts() []string {
	out := []string{}
	if p != nil {
		for h := range p.addresses {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}
func (p *Policy) Addresses(host string) []netip.Addr {
	if p == nil {
		return nil
	}
	h, _ := canonical(host)
	return append([]netip.Addr(nil), p.addresses[h]...)
}

// CNAMEChain returns the frozen hostname-to-terminal-alias path, including
// the queried host. The returned slice is independent of policy state.
func (p *Policy) CNAMEChain(host string) []string {
	if p == nil {
		return nil
	}
	h, _ := canonical(host)
	return append([]string(nil), p.cnameChains[h]...)
}
func (p *Policy) AllowedPorts() []uint16 {
	out := []uint16{}
	if p != nil {
		for n := range p.ports {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func canonicalCNAMEChain(host string, chain []string) ([]string, error) {
	if len(chain) == 0 || len(chain) > maxCNAMEHops+1 {
		return nil, fmt.Errorf("invalid CNAME chain length: %d", len(chain))
	}
	seen := make(map[string]struct{}, len(chain))
	for i := range chain {
		hop, err := canonical(chain[i])
		if err != nil {
			return nil, fmt.Errorf("invalid CNAME hop %q: %w", chain[i], err)
		}
		if i == 0 && hop != host {
			return nil, errors.New("CNAME chain does not begin with queried host")
		}
		if _, ok := seen[hop]; ok {
			return nil, fmt.Errorf("CNAME cycle detected at %s", hop)
		}
		seen[hop] = struct{}{}
		chain[i] = hop
	}
	return chain, nil
}
func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p == nil {
		return nil, errors.New("target policy required")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("network %q is outside TCP target policy", network)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	h, err := canonical(host)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("invalid port")
	}
	port := uint16(n)
	if _, ok := p.ports[port]; !ok {
		return nil, fmt.Errorf("port %d is outside target policy", port)
	}
	ips := p.addresses[h]
	if len(ips) == 0 {
		return nil, fmt.Errorf("host %q is outside target policy", h)
	}
	dial := p.dial
	if dial == nil {
		d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		dial = d.DialContext
	}
	var last error
	for _, ip := range ips {
		conn, e := dial(ctx, network, net.JoinHostPort(ip.String(), portText))
		if e == nil {
			return conn, nil
		}
		last = e
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
func canonical(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(s)), ".")
	if s == "" || strings.ContainsAny(s, "/:@") {
		return "", errors.New("invalid hostname")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", errors.New("IP literals cannot be DNS-verified targets")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid hostname")
			}
		}
	}
	return s, nil
}
func public(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	blocked := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"}
	for _, s := range blocked {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
