// Command iroh-relay runs a small, self-hostable iroh relay server.
//
// Run your own relay on a host near your endpoints so they do not depend on the
// number0 canary infrastructure:
//
//	iroh-relay -addr :3340
//
// Clients point at it with a custom relay map:
//
//	url, _ := netaddr.ParseRelayURL("https://my-relay.example.:3340")
//	mode := relay.ModeCustom(relay.MapFromURLs(url))
//
// The server exposes the relay protocol at /relay and a liveness probe at
// /healthz. It shuts down gracefully on SIGINT or SIGTERM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tmc/go-iroh/internal/pprofserver"
	"github.com/tmc/go-iroh/relayserver"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 10 * time.Second
	httpIdleTimeout       = time.Minute
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "iroh-relay:", err)
		os.Exit(1)
	}
}

// run parses args, starts the relay server, and blocks until a shutdown signal
// or a serve error. logOut receives startup and shutdown lines so tests can
// capture them.
func run(args []string, logOut io.Writer) error {
	fs := flag.NewFlagSet("iroh-relay", flag.ContinueOnError)
	fs.SetOutput(logOut)
	addr := fs.String("addr", ":3340", "listen address")
	pprofAddr := fs.String("pprof-addr", "", "pprof HTTP listen address (disabled if empty)")
	shutdownTimeout := fs.Duration("shutdown-timeout", 5*time.Second, "grace period for in-flight connections on shutdown")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	logger := log.New(logOut, "", log.LstdFlags)
	if *pprofAddr != "" {
		profiler, err := pprofserver.Start(*pprofAddr, logger)
		if err != nil {
			return err
		}
		defer profiler.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, ln, logger, *shutdownTimeout)
}

// serve runs a relay server on ln until ctx is canceled, then drains in-flight
// connections within shutdownTimeout. It is separate from run so tests can drive
// it with their own listener and cancellation.
func serve(ctx context.Context, ln net.Listener, logger *log.Logger, shutdownTimeout time.Duration) error {
	mux := http.NewServeMux()
	relay := relayserver.New()
	mux.Handle("/relay", relay)
	// Rust iroh clients probe /ping before selecting a home relay.
	mux.Handle("/ping", relay)
	mux.Handle("/generate_204", relay)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})

	srv := newHTTPServer(mux)
	logger.Printf("iroh-relay listening on %s (relay: /relay, probe: /ping, health: /healthz)", ln.Addr())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Printf("iroh-relay shutting down (grace %s)", shutdownTimeout)
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
}
