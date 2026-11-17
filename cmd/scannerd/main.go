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
	flag.Parse()
	if *timeout <= 0 {
		log.Fatal("timeout must be positive")
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	pb.RegisterScannerServiceServer(server, scanner.NewServer([]check.Check{&check.HeadersCheck{}, &check.EmailCheck{}}, *timeout))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() { <-signals; server.Stop() }()
	log.Printf("scanner gRPC listening on %s", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
