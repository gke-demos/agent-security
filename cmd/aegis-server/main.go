package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func main() {
	modeFlag := flag.String("mode", os.Getenv("AEGIS_MODE"), "Server mode: portal (default), remediator-actor, or ext-proc")
	addrFlag := flag.String("addr", "", "Optional listen address override")
	flag.Parse()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mode := strings.TrimSpace(*modeFlag)
	if mode == "ext-proc" {
		cfg := aegis.RuntimeConfigFromEnv()
		rt := aegis.NewRuntime(cfg)
		tlsAddr := strings.TrimSpace(*addrFlag)
		if tlsAddr == "" {
			tlsAddr = strings.TrimSpace(cfg.ExtProcTLSAddr)
		}
		if tlsAddr == "" {
			tlsAddr = ":8443"
		}
		lis, closeFn, err := aegis.StartExtProcTLSServer(tlsAddr, rt)
		if err != nil {
			log.Fatalf("ext-proc TLS server error: %v", err)
		}
		defer func() { _ = closeFn() }()
		log.Printf("AegisSRE Model Armor ext_proc TLS server listening on %s", lis.Addr().String())

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		return
	}

	var handler http.Handler
	if mode == "remediator-actor" {
		handler = aegis.NewRemediatorActorHandler(nil)
		log.Printf("AegisSRE Remediator Actor listening on :%s", port)
	} else {
		cfg := aegis.RuntimeConfigFromEnv()
		rt := aegis.NewRuntime(cfg)
		if tlsAddr := strings.TrimSpace(cfg.ExtProcTLSAddr); tlsAddr != "" && !strings.EqualFold(tlsAddr, "off") {
			if lis, closeFn, err := aegis.StartExtProcTLSServer(tlsAddr, rt); err != nil {
				log.Printf("warning: co-hosted ext_proc TLS listener on %s not started: %v", tlsAddr, err)
			} else {
				defer func() { _ = closeFn() }()
				log.Printf("AegisSRE Model Armor ext_proc TLS callout listening on %s", lis.Addr().String())
			}
		}
		handler = aegis.NewHandler(rt)
		log.Printf("AegisSRE listening on :%s", port)
	}

	listenAddr := ":" + port
	if strings.TrimSpace(*addrFlag) != "" {
		listenAddr = strings.TrimSpace(*addrFlag)
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
