// SPDX-License-Identifier: EPL-2.0
package main

import (
	"arrowhead/ah5-support-go/translationmanager/internal/core"
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const defaultSystem = "TranslationManager"

func main() {
	system := defaultSystem
	path := flag.String("config", "config.json", "configuration file")
	port := flag.Int(core.PortFlag, 0, "listening port; overrides SERVER_PORT and \"listen\" in the configuration file")
	flag.Parse()
	cfg, e := core.LoadConfig(*path, system)
	if e == nil {
		e = core.ApplyPort(&cfg, *port)
	}
	if e != nil {
		log.Fatal(e)
	}
	tls, e := core.LoadTLS(cfg)
	if e != nil {
		log.Fatal(e)
	}
	store, e := core.OpenStore(cfg.State)
	if e != nil {
		log.Fatal(e)
	}
	defer store.Close()
	app, e := core.New(cfg, store, tls)
	if e != nil {
		log.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = app.RunBackground(ctx); e != nil {
		log.Fatal(e)
	}
	server := &http.Server{Addr: cfg.Listen, Handler: app, TLSConfig: tls, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(deadline)
	}()
	log.Printf("%s Go support system listening at %s with mandatory mutual TLS", system, cfg.Listen)
	if e = server.ListenAndServeTLS("", ""); e != nil && e != http.ErrServerClosed {
		stop()
		app.WaitBackground()
		log.Fatal(e)
	}
	stop()
	<-done
	app.WaitBackground()
}
