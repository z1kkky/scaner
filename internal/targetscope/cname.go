package targetscope

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxCNAMEHops = 8

// CNAMEChainResolver exposes each alias hop. LookupCNAME alone is not enough
// for target admission because it returns only the final canonical name.
type CNAMEChainResolver interface {
	LookupCNAMEChain(context.Context, string) ([]string, error)
}

// SystemResolver returns the system DNS resolver with explicit CNAME-chain
// and terminal-address inspection. TXT lookups use Go's resolver; target
// admission queries CNAME, A, and AAAA records directly against configured
// nameservers so intermediate hops are visible and terminal aliases rejected.
func SystemResolver() Resolver { return systemResolver{} }

func (systemResolver) LookupCNAMEChain(ctx context.Context, host string) ([]string, error) {
	servers, err := systemNameservers()
	if err != nil {
		return nil, err
	}
	return lookupCNAMEChain(ctx, host, servers)
}

// ResolveTarget reads the resolver configuration once, follows each CNAME
// hop, then asks for A and AAAA records of the validated terminal name. The
// address queries are direct: a CNAME in either answer is rejected instead
// of being followed by net.Resolver behind the policy's back.
func (systemResolver) ResolveTarget(ctx context.Context, host string) ([]string, []netip.Addr, error) {
	servers, err := systemNameservers()
	if err != nil {
		return nil, nil, err
	}
	return resolveTarget(ctx, host, servers)
}

func resolveTarget(ctx context.Context, host string, servers []string) ([]string, []netip.Addr, error) {
	chain, err := lookupCNAMEChain(ctx, host, servers)
	if err != nil {
		return nil, nil, err
	}
	terminal := chain[len(chain)-1]
	addresses, err := lookupDirectIPs(ctx, servers, terminal)
	if err != nil {
		return nil, nil, err
	}
	return chain, addresses, nil
}

func lookupDirectIPs(ctx context.Context, servers []string, host string) ([]netip.Addr, error) {
	v4, err := queryAddresses(ctx, servers, host, dnsmessage.TypeA)
	if err != nil {
		return nil, fmt.Errorf("lookup terminal A records: %w", err)
	}
	v6, err := queryAddresses(ctx, servers, host, dnsmessage.TypeAAAA)
	if err != nil {
		return nil, fmt.Errorf("lookup terminal AAAA records: %w", err)
	}
	addresses := append(v4, v6...)
	if len(addresses) == 0 {
		return nil, errors.New("terminal CNAME target has no A or AAAA records")
	}
	return addresses, nil
}

func queryAddresses(ctx context.Context, servers []string, host string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return nil, errors.New("unsupported DNS address query type")
	}
	var lastErr error
	for _, server := range servers {
		idBytes := make([]byte, 2)
		if _, err := rand.Read(idBytes); err != nil {
			return nil, fmt.Errorf("generate DNS query id: %w", err)
		}
		id := binary.BigEndian.Uint16(idBytes)
		name, err := dnsmessage.NewName(host + ".")
		if err != nil {
			return nil, fmt.Errorf("encode DNS address query name: %w", err)
		}
		msg := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
		}
		packet, err := msg.Pack()
		if err != nil {
			return nil, fmt.Errorf("encode DNS address query: %w", err)
		}
		resp, err := exchangeDNS(ctx, server, packet, false)
		if err != nil {
			lastErr = err
			continue
		}
		var answer dnsmessage.Message
		if err = answer.Unpack(resp); err != nil {
			lastErr = fmt.Errorf("parse DNS address response: %w", err)
			continue
		}
		if !validDNSResponse(answer, id, name, qtype) {
			lastErr = errors.New("DNS address response does not match query")
			continue
		}
		if answer.Header.Truncated {
			resp, err = exchangeDNS(ctx, server, packet, true)
			if err != nil {
				lastErr = err
				continue
			}
			answer = dnsmessage.Message{}
			if err = answer.Unpack(resp); err != nil || answer.Header.Truncated || !validDNSResponse(answer, id, name, qtype) {
				lastErr = errors.New("invalid or truncated DNS TCP address response")
				continue
			}
		}
		if answer.Header.RCode != dnsmessage.RCodeSuccess {
			if answer.Header.RCode == dnsmessage.RCodeNameError {
				return nil, fmt.Errorf("DNS address target %s does not exist", host)
			}
			lastErr = fmt.Errorf("DNS address query returned response code %s", answer.Header.RCode)
			continue
		}
		addresses := make([]netip.Addr, 0, len(answer.Answers))
		for _, resource := range answer.Answers {
			if resource.Header.Class != dnsmessage.ClassINET {
				continue
			}
			owner := strings.TrimSuffix(resource.Header.Name.String(), ".")
			if !strings.EqualFold(owner, host) {
				continue
			}
			if resource.Header.Type == dnsmessage.TypeCNAME {
				return nil, fmt.Errorf("unexpected CNAME in direct terminal address response for %s", host)
			}
			if resource.Header.Type != qtype {
				continue
			}
			switch body := resource.Body.(type) {
			case *dnsmessage.AResource:
				addresses = append(addresses, netip.AddrFrom4(body.A))
			case *dnsmessage.AAAAResource:
				addresses = append(addresses, netip.AddrFrom16(body.AAAA))
			default:
				return nil, errors.New("malformed DNS address resource")
			}
		}
		return addresses, nil
	}
	if lastErr == nil {
		lastErr = errors.New("DNS address lookup failed")
	}
	return nil, lastErr
}

func validDNSResponse(answer dnsmessage.Message, id uint16, name dnsmessage.Name, qtype dnsmessage.Type) bool {
	return answer.Header.ID == id && answer.Header.Response &&
		len(answer.Questions) == 1 && answer.Questions[0].Name.String() == name.String() &&
		answer.Questions[0].Type == qtype && answer.Questions[0].Class == dnsmessage.ClassINET
}

func systemNameservers() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read DNS resolver configuration: %w", err)
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr := strings.Trim(fields[1], "[]")
		if ip := net.ParseIP(addr); ip == nil {
			continue
		}
		servers = append(servers, net.JoinHostPort(addr, "53"))
	}
	if len(servers) == 0 {
		return nil, errors.New("no DNS nameservers configured")
	}
	return servers, nil
}

func lookupCNAMEChain(ctx context.Context, host string, servers []string) ([]string, error) {
	start, err := canonical(host)
	if err != nil {
		return nil, err
	}
	chain := []string{start}
	seen := map[string]struct{}{start: {}}
	current := start
	for hop := 0; hop < maxCNAMEHops; hop++ {
		next, found, err := queryCNAME(ctx, servers, current)
		if err != nil {
			return nil, err
		}
		if !found {
			return chain, nil
		}
		next, err = canonical(next)
		if err != nil {
			return nil, fmt.Errorf("invalid CNAME target for %s: %w", current, err)
		}
		if _, ok := seen[next]; ok {
			return nil, fmt.Errorf("CNAME cycle detected at %s", next)
		}
		seen[next] = struct{}{}
		chain = append(chain, next)
		current = next
	}
	// One final lookup distinguishes a chain of exactly maxCNAMEHops from an
	// overlong chain; another CNAME means the configured depth limit was hit.
	if _, found, err := queryCNAME(ctx, servers, current); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("CNAME chain exceeds %d hops", maxCNAMEHops)
	}
	return chain, nil
}

func queryCNAME(ctx context.Context, servers []string, host string) (string, bool, error) {
	var lastErr error
	for _, server := range servers {
		idBytes := make([]byte, 2)
		if _, err := rand.Read(idBytes); err != nil {
			return "", false, fmt.Errorf("generate DNS query id: %w", err)
		}
		id := binary.BigEndian.Uint16(idBytes)
		name, err := dnsmessage.NewName(host + ".")
		if err != nil {
			return "", false, fmt.Errorf("encode CNAME query name: %w", err)
		}
		msg := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}},
		}
		packet, err := msg.Pack()
		if err != nil {
			return "", false, fmt.Errorf("encode CNAME query: %w", err)
		}
		resp, err := exchangeDNS(ctx, server, packet, false)
		if err != nil {
			lastErr = err
			continue
		}
		var answer dnsmessage.Message
		if err = answer.Unpack(resp); err != nil {
			lastErr = fmt.Errorf("parse DNS CNAME response: %w", err)
			continue
		}
		if answer.Header.ID != id || !answer.Header.Response || len(answer.Questions) != 1 || answer.Questions[0].Name.String() != name.String() || answer.Questions[0].Type != dnsmessage.TypeCNAME || answer.Questions[0].Class != dnsmessage.ClassINET {
			lastErr = errors.New("DNS CNAME response does not match query")
			continue
		}
		if answer.Header.Truncated {
			resp, err = exchangeDNS(ctx, server, packet, true)
			if err != nil {
				lastErr = err
				continue
			}
			answer = dnsmessage.Message{}
			if err = answer.Unpack(resp); err != nil || answer.Header.ID != id || !answer.Header.Response || answer.Header.Truncated || len(answer.Questions) != 1 || answer.Questions[0].Name.String() != name.String() || answer.Questions[0].Type != dnsmessage.TypeCNAME || answer.Questions[0].Class != dnsmessage.ClassINET {
				lastErr = errors.New("invalid or truncated DNS TCP CNAME response")
				continue
			}
		}
		if answer.Header.RCode == dnsmessage.RCodeNameError {
			return "", false, nil
		}
		if answer.Header.RCode != dnsmessage.RCodeSuccess {
			lastErr = fmt.Errorf("DNS CNAME query returned response code %s", answer.Header.RCode)
			continue
		}
		var target string
		for _, resource := range answer.Answers {
			if resource.Header.Type != dnsmessage.TypeCNAME || !strings.EqualFold(strings.TrimSuffix(resource.Header.Name.String(), "."), host) {
				continue
			}
			cname, ok := resource.Body.(*dnsmessage.CNAMEResource)
			if !ok {
				lastErr = errors.New("malformed DNS CNAME resource")
				return "", false, lastErr
			}
			value := strings.TrimSuffix(cname.CNAME.String(), ".")
			if target != "" && !strings.EqualFold(target, value) {
				return "", false, fmt.Errorf("conflicting CNAME records for %s", host)
			}
			target = value
		}
		return target, target != "", nil
	}
	if lastErr == nil {
		lastErr = errors.New("DNS CNAME lookup failed")
	}
	return "", false, lastErr
}

func exchangeDNS(ctx context.Context, server string, packet []byte, tcp bool) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, fmt.Errorf("connect DNS resolver: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if tcp {
		if len(packet) > 65535 {
			return nil, errors.New("DNS query exceeds TCP size limit")
		}
		framed := make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(packet)))
		copy(framed[2:], packet)
		for len(framed) > 0 {
			n, err := conn.Write(framed)
			if err != nil {
				return nil, fmt.Errorf("write DNS TCP query: %w", err)
			}
			if n == 0 {
				return nil, io.ErrShortWrite
			}
			framed = framed[n:]
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, fmt.Errorf("read DNS TCP response length: %w", err)
		}
		response := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, response); err != nil {
			return nil, fmt.Errorf("read DNS TCP response: %w", err)
		}
		return response, nil
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("write DNS UDP query: %w", err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("read DNS UDP response: %w", err)
	}
	return response[:n], nil
}
