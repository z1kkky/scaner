// scannerweb starts the local Scaner control API. The bind address is
// constrained to loopback by web.ListenAddress so it cannot be exposed on LAN.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/z1kkky/scaner/internal/nucleirunner"
	"github.com/z1kkky/scaner/internal/web"
	"github.com/z1kkky/scaner/internal/webscan"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--scaner-internal-relay" {
		if err := nucleirunner.RunContainerRelay(os.Args[2:]); err != nil {
			log.Printf("internal Nuclei relay failed: %v", err)
			os.Exit(1)
		}
		return
	}
	addr := flag.String("listen", "127.0.0.1:8787", "loopback address for the local web service")
	dataDir := flag.String("data", "", "directory for local targets and scan history")
	nucleiPath := flag.String("nuclei", filepath.Join("nuclei", "nuclei"), "path to the pinned Nuclei v3.11.1 binary")
	flag.Parse()
	listen, err := web.ListenAddress(*addr)
	if err != nil {
		log.Fatalf("invalid listen address: %v", err)
	}
	if *dataDir == "" {
		base, e := os.UserConfigDir()
		if e != nil {
			log.Fatal(e)
		}
		*dataDir = filepath.Join(base, "scaner", "local")
	}
	appBinary, err := os.Executable()
	if err != nil {
		log.Fatalf("locate scannerweb executable: %v", err)
	}
	nucleiRunner := nucleirunner.New(nucleirunner.Config{NucleiBinary: *nucleiPath, RelayExecutable: appBinary})
	jobRunner := webscan.New(webscan.Config{Nuclei: nucleiRunner})
	svc, err := web.New(web.Config{DataDir: *dataDir, Runner: jobRunner})
	if err != nil {
		log.Fatalf("initialize local service: %v", err)
	}
	defer svc.Close()
	srv := &http.Server{Addr: listen, Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	fmt.Printf("Scaner local API: http://%s (данные: %s)\n", listen, *dataDir)
	if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
