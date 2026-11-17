package check

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestIsPublicAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.20.1.2", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"169.254.1.1", false},
		{"192.0.2.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"::ffff:127.0.0.1", false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			ip := netip.MustParseAddr(test.address)
			if got := isPublicAddress(ip); got != test.want {
				t.Errorf("isPublicAddress(%s) = %v, want %v", ip, got, test.want)
			}
		})
	}
}

func TestPublicDialContextRejectsLoopbackBeforeDial(t *testing.T) {
	_, err := publicDialContext(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected non-public target rejection, got %v", err)
	}
}

func TestPublicDialContextPinsCheckedDNSAddress(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var dialAddress string
	conn, err := publicDialContextWith(context.Background(), "tcp", "example.test:443",
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		func(_ context.Context, _, address string) (net.Conn, error) {
			dialAddress = address
			return client, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if conn != client || dialAddress != "8.8.8.8:443" {
		t.Fatalf("dialed %q (conn=%v), want checked IP 8.8.8.8:443", dialAddress, conn == client)
	}
}

func TestPublicDialContextRejectsMixedDNSResults(t *testing.T) {
	dialed := false
	_, err := publicDialContextWith(context.Background(), "tcp", "example.test:443",
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, nil
		})
	if err == nil || dialed {
		t.Fatalf("expected mixed public/private answer to be rejected before dialing; err=%v dialed=%v", err, dialed)
	}
}
