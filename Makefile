# Makefile: one entry point for building, testing and linting ZTC, used the
# same way locally and in CI. Run `make` to list the targets.

GO  ?= go
BIN := $(CURDIR)/bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build every Go service into ./bin
	cd services && CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/ ./cmd/...

.PHONY: test
test: ## Run the Go tests with the race detector
	cd services && $(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Run the tests with coverage and print the total
	cd services && $(GO) test -race -count=1 -coverprofile=coverage.out ./...
	cd services && $(GO) tool cover -func=coverage.out | tail -n 1

.PHONY: lint
lint: ## Check formatting, then run go vet and golangci-lint
	@test -z "$$(gofmt -l services)" || { echo "Files need gofmt:"; gofmt -l services; exit 1; }
	cd services && $(GO) vet ./...
	cd services && golangci-lint run ./...

.PHONY: fmt
fmt: ## Format all Go code
	gofmt -w services

.PHONY: run-pdp
run-pdp: build ## Build and start ztc-pdp on :8181
	$(BIN)/ztc-pdp

.PHONY: clean
clean: ## Remove build and coverage output
	rm -rf $(BIN) services/coverage.out
