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
	flag.Parse()
	store, err := charter.Open(filepath.Join(*data, "registry.db"), *id)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: store.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	info, _ := json.Marshal(map[string]any{"listen": listener.Addr().String(), "registry": *id, "registrar": store.PublicKey(), "draft_version": charter.DraftVersion})
	fmt.Println(string(info))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
