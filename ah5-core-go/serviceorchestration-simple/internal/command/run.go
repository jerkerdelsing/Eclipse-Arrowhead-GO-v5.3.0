// SPDX-License-Identifier: EPL-2.0
package command

import (
	"arrowhead/ah5-core-go/serviceorchestration-simple/internal/core"
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run(role string) {
	path := flag.String("config", "config.json", "configuration file")
	port := flag.Int(core.PortFlag, 0, "listening port; overrides SERVER_PORT and \"listen\" in the configuration file")
	flag.Parse()
	cfg, e := core.LoadConfig(*path, role)
	if e == nil {
		e = core.ApplyPort(&cfg, *port)
	}
	if e != nil {
		log.Fatal(e)
	}
	tc, e := core.LoadTLS(cfg)
	if e != nil {
		log.Fatal(e)
	}
	store, e := core.OpenStore(cfg.State)
	if e != nil {
		log.Fatal(e)
	}
	defer store.Close()
	app, e := core.New(cfg, store, tc)
	if e != nil {
		log.Fatal(e)
	}
	if role == "authentication" {
		if e = app.Bootstrap(); e != nil {
			log.Fatal(e)
		}
	}
	server := &http.Server{Addr: cfg.Listen, Handler: app, TLSConfig: tc, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = app.RunWorker(ctx); e != nil {
		log.Fatal(e)
	}
	app.RunRegistration(ctx)
	app.RunMQTT(ctx)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("%s Go core listening at %s with mandatory mutual TLS", role, cfg.Listen)
	if e = server.ListenAndServeTLS("", ""); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
	stop()
	<-shutdownDone
	app.WaitBackground()
}
