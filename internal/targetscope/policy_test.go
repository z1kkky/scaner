package targetscope

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeResolver struct {
	txt      []string
	cname    string
	ips      []netip.Addr
	cnameErr error
	lookups  int
}

func (r *fakeResolver) LookupTXT(context.Context, string) ([]string, error) { return r.txt, nil }
func (r *fakeResolver) LookupCNAME(context.Context, string) (string, error) {
	return r.cname, r.cnameErr
}
func (r *fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.lookups++
	return append([]netip.Addr(nil), r.ips...), nil
}
func (r *fakeResolver) ResolveTarget(_ context.Context, host string) ([]string, []netip.Addr, error) {
	r.lookups++
	if r.cnameErr != nil {
		var dnsErr *net.DNSError
		if !errors.As(r.cnameErr, &dnsErr) || !dnsErr.IsNotFound {
			return nil, nil, r.cnameErr
		}
		return []string{host}, append([]netip.Addr(nil), r.ips...), nil
	}
	if r.cname == "" {
		return []string{host}, append([]netip.Addr(nil), r.ips...), nil
	}
	target, err := canonical(r.cname)
	if err != nil {
		return nil, nil, err
	}
	if target == host {
		return []string{host}, append([]netip.Addr(nil), r.ips...), nil
	}
	return []string{host, target}, append([]netip.Addr(nil), r.ips...), nil
}

type fakeChainResolver struct {
	*fakeResolver
	chain []string
	err   error
}

func (r *fakeChainResolver) LookupCNAMEChain(context.Context, string) ([]string, error) {
	return append([]string(nil), r.chain...), r.err
}
func (r *fakeChainResolver) ResolveTarget(_ context.Context, _ string) ([]string, []netip.Addr, error) {
	r.lookups++
	if r.err != nil {
		return nil, nil, r.err
	}
	return append([]string(nil), r.chain...), append([]netip.Addr(nil), r.ips...), nil
}

func noCNAME() error {
	return &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
}

func TestTXTVerification(t *testing.T) {
	c := Challenge{Host: "example.com", Record: "_scaner-verification.example.com", Value: "token"}
	if err := VerifyTXT(context.Background(), &fakeResolver{txt: []string{"token"}}, c); err != nil {
		t.Fatalf("valid TXT rejected: %v", err)
	}
	if err := VerifyTXT(context.Background(), &fakeResolver{txt: []string{"wrong"}}, c); err == nil {
		t.Fatal("mismatched TXT accepted")
	}
}
func TestFreezeSuffixBoundary(t *testing.T) {
	r := &fakeResolver{cname: "api.example.com.", ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	if _, err := Freeze(context.Background(), r, "example.com", []string{"api.example.com"}, []uint16{443}); err != nil {
		t.Fatal(err)
	}
	r = &fakeResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	if _, err := Freeze(context.Background(), r, "example.com", []string{"example.com.attacker.test"}, []uint16{443}); err == nil {
		t.Fatal("suffix lookalike accepted")
	}
}
func TestFreezeRejectsExternalCNAMEAndMixedPrivateAnswer(t *testing.T) {
	if _, err := Freeze(context.Background(), &fakeResolver{cname: "outside.test.", ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, "example.com", nil, []uint16{443}); err == nil {
		t.Fatal("external CNAME accepted")
	}
	if _, err := Freeze(context.Background(), &fakeResolver{cnameErr: noCNAME(), ips: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}}, "example.com", nil, []uint16{443}); err == nil {
		t.Fatal("mixed public/private answers accepted")
	}
}

func TestFreezeRejectsExternalIntermediateCNAME(t *testing.T) {
	r := &fakeChainResolver{
		fakeResolver: &fakeResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		chain:        []string{"api.example.com", "alias.external.test", "edge.example.com"},
	}
	if _, err := Freeze(context.Background(), r, "example.com", []string{"api.example.com"}, []uint16{443}); err == nil {
		t.Fatal("external intermediate CNAME accepted because the terminal target was in-zone")
	}
}

func TestFreezeStoresImmutableInZoneCNAMEChain(t *testing.T) {
	chain := []string{"api.example.com", "edge.example.com", "example.com"}
	r := &fakeChainResolver{
		fakeResolver: &fakeResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		chain:        chain,
	}
	p, err := Freeze(context.Background(), r, "example.com", []string{"api.example.com"}, []uint16{443})
	if err != nil {
		t.Fatalf("in-zone CNAME chain rejected: %v", err)
	}
	chain[1] = "mutated.example.com"
	got := p.CNAMEChain("api.example.com")
	if strings.Join(got, ",") != "api.example.com,edge.example.com,example.com" {
		t.Fatalf("stored CNAME chain changed with resolver input: %v", got)
	}
	got[1] = "mutated.example.com"
	if want := p.CNAMEChain("api.example.com"); strings.Join(want, ",") != "api.example.com,edge.example.com,example.com" {
		t.Fatalf("CNAMEChain accessor exposed policy state: %v", want)
	}
}

func TestFreezeRejectsInvalidCNAMEChains(t *testing.T) {
	tests := []struct {
		name  string
		chain []string
		err   error
	}{
		{name: "cycle", chain: []string{"api.example.com", "edge.example.com", "api.example.com"}},
		{name: "over depth", chain: []string{"api.example.com", "a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com", "g.example.com", "h.example.com", "i.example.com"}},
		{name: "resolver error", err: errors.New("DNS timeout")},
		{name: "wrong start", chain: []string{"other.example.com", "api.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeChainResolver{fakeResolver: &fakeResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, chain: tt.chain, err: tt.err}
			if _, err := Freeze(context.Background(), r, "example.com", []string{"api.example.com"}, []uint16{443}); err == nil {
				t.Fatal("invalid CNAME chain was accepted")
			}
		})
	}
}

func TestLookupCNAMEChainUsesOnlyLocalResolverFixture(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targets := map[string]string{
		"api.example.com":  "edge.example.com",
		"edge.example.com": "example.com",
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 4096)
		for {
			n, addr, readErr := listener.ReadFrom(buf)
			if readErr != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buf[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			name := strings.TrimSuffix(q.Name.String(), ".")
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess},
				Questions: []dnsmessage.Question{q},
			}
			if target := targets[name]; target != "" {
				cname, nameErr := dnsmessage.NewName(target + ".")
				if nameErr != nil {
					continue
				}
				response.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30},
					Body:   &dnsmessage.CNAMEResource{CNAME: cname},
				}}
			} else if name == "example.com" && q.Type == dnsmessage.TypeA {
				response.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
					Body:   &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}},
				}}
			}
			packet, packErr := response.Pack()
			if packErr == nil {
				_, _ = listener.WriteTo(packet, addr)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	chain, addresses, err := resolveTarget(ctx, "api.example.com", []string{listener.LocalAddr().String()})
	if err != nil {
		t.Fatalf("lookup through local DNS fixture: %v", err)
	}
	if got := strings.Join(chain, ","); got != "api.example.com,edge.example.com,example.com" {
		t.Fatalf("chain = %q", got)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("terminal address = %v", addresses)
	}
	_ = listener.Close()
	<-serverDone
}

func TestResolveTargetRejectsCNAMEIntroducedByTerminalAddressResponse(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 4096)
		for {
			n, addr, readErr := listener.ReadFrom(buf)
			if readErr != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buf[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			name := strings.TrimSuffix(q.Name.String(), ".")
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess},
				Questions: []dnsmessage.Question{q},
			}
			// The CNAME answer is safe and direct, but a subsequent A lookup
			// returns a new external alias plus its address. The policy must
			// reject the unseen hop rather than pinning that address.
			if name == "api.example.com" && q.Type == dnsmessage.TypeA {
				external, nameErr := dnsmessage.NewName("outside.test.")
				if nameErr != nil {
					continue
				}
				response.Answers = []dnsmessage.Resource{
					{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: external}},
					{Header: dnsmessage.ResourceHeader{Name: external, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}},
				}
			}
			packet, packErr := response.Pack()
			if packErr == nil {
				_, _ = listener.WriteTo(packet, addr)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err = resolveTarget(ctx, "api.example.com", []string{listener.LocalAddr().String()})
	if err == nil || !strings.Contains(err.Error(), "unexpected CNAME") {
		t.Fatalf("unseen CNAME in terminal address lookup was accepted: %v", err)
	}
	_ = listener.Close()
	<-serverDone
}

func TestFreezeRequiresCombinedCNAMEAndAddressResolver(t *testing.T) {
	legacy := &legacyResolver{ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	if _, err := Freeze(context.Background(), legacy, "example.com", nil, []uint16{443}); err == nil {
		t.Fatal("resolver with separate opaque lookups was accepted")
	}
}

type legacyResolver struct{ ips []netip.Addr }

func (*legacyResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (*legacyResolver) LookupCNAME(context.Context, string) (string, error) {
	return "example.com", nil
}
func (r *legacyResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.ips...), nil
}
func TestFrozenAddressesAndPortScope(t *testing.T) {
	r := &fakeResolver{cnameErr: noCNAME(), ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	p, err := Freeze(context.Background(), r, "example.com", nil, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	r.ips = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	if got := p.Addresses("example.com"); len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatalf("frozen addresses changed: %v", got)
	}
	if r.lookups != 1 {
		t.Fatalf("DNS lookups after freeze: %d", r.lookups)
	}
	if _, err := p.DialContext(context.Background(), "tcp", net.JoinHostPort("example.com", "80")); err == nil {
		t.Fatal("unallowed port accepted")
	}
	if _, err := p.DialContext(context.Background(), "tcp", net.JoinHostPort("other.example.com", "443")); err == nil {
		t.Fatal("unlisted host accepted")
	}
	if _, err := Freeze(context.Background(), r, "example.com", nil, []uint16{0}); err == nil {
		t.Fatal("port zero accepted")
	}
}

func TestFreezeRejectsCNAMELookupFailureAndIPLiteral(t *testing.T) {
	r := &fakeResolver{cnameErr: errors.New("temporary DNS failure"), ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	if _, err := Freeze(context.Background(), r, "example.com", nil, []uint16{443}); err == nil {
		t.Fatal("temporary CNAME lookup failure was ignored")
	}
	if _, err := Freeze(context.Background(), r, "8.8.8.8", nil, []uint16{443}); err == nil {
		t.Fatal("IP literal accepted as a verified target")
	}
}

func TestDialUsesOnlyFrozenIPAfterResolverMutation(t *testing.T) {
	r := &fakeResolver{cnameErr: noCNAME(), ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	var dialed string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("unexpected network %q", network)
		}
		dialed = address
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	}
	p, err := FreezeWithDial(context.Background(), r, "example.com", []string{"www.example.com", "example.com"}, []uint16{8443, 443}, dial)
	if err != nil {
		t.Fatal(err)
	}
	r.ips = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	conn, err := p.DialContext(context.Background(), "tcp", net.JoinHostPort("example.com", "443"))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "8.8.8.8:443" {
		t.Fatalf("dialed %q, want frozen IP", dialed)
	}
	if r.lookups != 2 {
		t.Fatalf("dial caused DNS lookup; total resolver calls=%d", r.lookups)
	}
	if got := strings.Join(p.Hosts(), ","); got != "example.com,www.example.com" {
		t.Fatalf("hosts not sorted: %q", got)
	}
	if got := p.AllowedPorts(); len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("ports not sorted: %v", got)
	}
	if _, err := p.DialContext(context.Background(), "udp", net.JoinHostPort("example.com", "443")); err == nil {
		t.Fatal("UDP network accepted")
	}
}
