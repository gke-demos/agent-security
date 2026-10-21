KUBE_CONTEXT ?= $(shell kubectl config current-context 2>/dev/null)
PROJECT_ID ?= $(shell gcloud config get-value project 2>/dev/null)
REGION ?= us-central1
PORT ?= 8080

.PHONY: test evals build run deploy-gke seed-fixtures register-gemini-enterprise

test:
	go test -race ./...

evals:
	go test -v ./internal/evals/...

build:
	go build -o bin/aegis-server ./cmd/aegis-server

run:
	PORT=$(PORT) go run ./cmd/aegis-server

deploy-gke:
	KUBE_CONTEXT="$(KUBE_CONTEXT)" PROJECT_ID="$(PROJECT_ID)" REGION="$(REGION)" ./hack/deploy-gke.sh

seed-fixtures:
	KUBE_CONTEXT="$(KUBE_CONTEXT)" ./hack/seed-fixtures.sh

register-gemini-enterprise:
	PROJECT_ID="$(PROJECT_ID)" REGION="$(REGION)" ./hack/register-gemini-enterprise.sh
