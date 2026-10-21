package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		ModelArmorEndpoint: os.Getenv("MODEL_ARMOR_ENDPOINT"),
		DLPEndpoint:        os.Getenv("DLP_ENDPOINT"),
		AgentRegistryURL:   os.Getenv("AGENT_REGISTRY_URL"),
	})
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: aegis.NewHandler(rt),
	}
	log.Printf("AegisSRE listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
