KUBE_CONTEXT ?= $(shell kubectl config current-context 2>/dev/null)
PROJECT_ID ?= $(shell gcloud config get-value project 2>/dev/null)
REGION ?= us-central1
PORT ?= 8080

.PHONY: test evals build run setup-live run-live deploy-gke seed-fixtures seed-live register-gemini-enterprise

test:
	go test -race ./...

evals:
	go test -v ./internal/evals/...

build:
	go build -o bin/aegis-server ./cmd/aegis-server

run:
	PORT=$(PORT) go run ./cmd/aegis-server

setup-live:
	./hack/setup-live-sources.sh

run-live: build
	@set -a; [ -f .env.local ] && . ./.env.local; set +a; \
	PORT=$(PORT) LIVE_GITHUB=true LIVE_SUBSTRATE=true AGENT_PLATFORM_LIVE_LLM=true ./bin/aegis-server

deploy-gke:
	KUBE_CONTEXT="$(KUBE_CONTEXT)" PROJECT_ID="$(PROJECT_ID)" REGION="$(REGION)" ./hack/deploy-gke.sh

seed-fixtures:
	KUBE_CONTEXT="$(KUBE_CONTEXT)" ./hack/seed-fixtures.sh

seed-live:
	KUBE_CONTEXT="$(KUBE_CONTEXT)" ./hack/seed-fixtures.sh --live

register-gemini-enterprise:
	PROJECT_ID="$(PROJECT_ID)" REGION="$(REGION)" ./hack/register-gemini-enterprise.sh
