package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	charter "github.com/corpollc/qntm/charter-registry"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8085", "HTTP listen address")
	data := flag.String("data-dir", "./data", "directory for registry.db (contains registrar signing key)")
	id := flag.String("registry", "localhost", "canonical registry audience; immutable for an existing database")
	admin := flag.String("admin-listen", "", "optional loopback-only metrics and private backup listener (contains signing key)")
	limits := charter.DefaultLimits()
	maxEntries := flag.Uint64("max-entries", limits.MaxEntries, "maximum accepted log entries")
	maxBytes := flag.Uint64("max-log-bytes", limits.MaxLogBytes, "maximum encoded log bytes")
	concurrent := flag.Int("max-concurrent", 4, "maximum concurrent public requests")
	flag.Parse()
	if *concurrent < 1 {
		log.Fatal("max-concurrent must be positive")
	}
	if *admin != "" {
		host, _, err := net.SplitHostPort(*admin)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			log.Fatal("admin-listen must use a numeric loopback address")
		}
	}
	store, err := charter.OpenWithLimits(filepath.Join(*data, "registry.db"), *id, charter.Limits{MaxEntries: *maxEntries, MaxLogBytes: *maxBytes})
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	operations := charter.NewOperations(store, *concurrent)
	server := &http.Server{Handler: operations.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	var adminServer *http.Server
	if *admin != "" {
		adminListener, err := net.Listen("tcp", *admin)
		if err != nil {
			log.Fatal(err)
		}
		adminServer = &http.Server{Handler: operations.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() {
			if err := adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
		}()
	}
	info, _ := json.Marshal(map[string]any{"listen": listener.Addr().String(), "registry": *id, "registrar": store.PublicKey(), "draft_version": charter.DraftVersion})
	fmt.Println(string(info))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if adminServer != nil {
			_ = adminServer.Shutdown(shutdown)
		}
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-shutdownDone
}
