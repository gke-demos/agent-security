package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func main() {
	modeFlag := flag.String("mode", os.Getenv("AEGIS_MODE"), "Server mode: portal (default) or remediator-actor")
	flag.Parse()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mode := strings.TrimSpace(*modeFlag)
	var handler http.Handler
	if mode == "remediator-actor" {
		handler = aegis.NewRemediatorActorHandler(nil)
		log.Printf("AegisSRE Remediator Actor listening on :%s", port)
	} else {
		rt := aegis.NewRuntime(aegis.RuntimeConfigFromEnv())
		handler = aegis.NewHandler(rt)
		log.Printf("AegisSRE listening on :%s", port)
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
