// scannerd exposes the internal scanner service to the API.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:50051", "internal gRPC listen address")
	timeout := flag.Duration("timeout", 10*time.Second, "timeout per check")
	allowRemote := flag.Bool("allow-remote", false, "allow listening on a non-loopback address (requires mTLS certificate flags)")
	serverCert := flag.String("tls-cert", "", "server certificate PEM for mTLS")
	serverKey := flag.String("tls-key", "", "server private key PEM for mTLS")
	clientCA := flag.String("client-ca", "", "CA bundle PEM used to verify mTLS client certificates")
	flag.Parse()
	if *timeout <= 0 {
		log.Fatal("timeout must be positive")
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	remote := false
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); !ok || !tcpAddr.IP.IsLoopback() {
		remote = true
		if !*allowRemote {
			_ = listener.Close()
			log.Fatal("refusing non-loopback listen address without -allow-remote")
		}
	}
	var tlsConfig *tls.Config
	if *serverCert != "" || *serverKey != "" || *clientCA != "" {
		tlsConfig, err = loadMTLSConfig(*serverCert, *serverKey, *clientCA)
		if err != nil {
			_ = listener.Close()
			log.Fatal(err)
		}
	}
	if remote && tlsConfig == nil {
		_ = listener.Close()
		log.Fatal("remote gRPC listener requires -tls-cert, -tls-key and -client-ca for mutual TLS")
	}
	serverOptions := []grpc.ServerOption{grpc.MaxRecvMsgSize(64 << 10), grpc.MaxSendMsgSize(1 << 20)}
	if tlsConfig != nil {
		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	server := grpc.NewServer(serverOptions...)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)
	checks := check.NewDefaultChecks(check.DefaultChecksOptions{PublicTargetsOnly: true})
	pb.RegisterScannerServiceServer(server, scanner.NewServer(checks, *timeout))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	shutdownDone := make(chan struct{})
	go func() {
		<-signals
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		stopGracefully(server, 15*time.Second)
		close(shutdownDone)
	}()
	log.Printf("scanner gRPC listening on %s", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
	<-shutdownDone
}

func loadMTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" || clientCAFile == "" {
		return nil, fmt.Errorf("mTLS requires -tls-cert, -tls-key and -client-ca")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load mTLS server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read mTLS client CA bundle: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mTLS client CA bundle contains no valid certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func stopGracefully(server *grpc.Server, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		server.Stop()
		<-done
	}
}
