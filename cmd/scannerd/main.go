// scannerd exposes the internal scanner service to the API.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/z1kkky/scaner/api/scanner/v1"
	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/scanner"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:50051", "internal gRPC listen address")
	timeout := flag.Duration("timeout", 10*time.Second, "timeout per check")
	allowRemote := flag.Bool("allow-remote", false, "allow listening on a non-loopback address (requires network isolation; gRPC has no authentication)")
	flag.Parse()
	if *timeout <= 0 {
		log.Fatal("timeout must be positive")
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); !ok || !tcpAddr.IP.IsLoopback() {
		if !*allowRemote {
			_ = listener.Close()
			log.Fatal("refusing non-loopback listen address without -allow-remote; gRPC has no authentication")
		}
		log.Print("WARNING: remote gRPC listener has no authentication; isolate it to trusted API traffic")
	}
	server := grpc.NewServer()
	checks := check.NewDefaultChecks(check.DefaultChecksOptions{PublicTargetsOnly: true})
	pb.RegisterScannerServiceServer(server, scanner.NewServer(checks, *timeout))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() { <-signals; server.Stop() }()
	log.Printf("scanner gRPC listening on %s", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
