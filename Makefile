# Binary names
SERVER_BINARY=fluxs
CLIENT_BINARY=fluxc
GO_FILES=$(shell find . -name "*.go")

VERSION=$(shell cat .version)
COMMIT=$(shell git rev-parse HEAD)
BUILD_DATE=$(shell date -u --rfc-3339=seconds)
GO_VERSION=$(shell go version | cut -d " " -f 3)

LDFLAGS_BASE=-X github.com/HT4w5/flux/pkg/meta.Version=$(VERSION) -X github.com/HT4w5/flux/pkg/meta.CommitHash=$(COMMIT) -X github.com/HT4w5/flux/pkg/meta.GoVersion=$(GO_VERSION) -X 'github.com/HT4w5/flux/pkg/meta.BuildDate=$(BUILD_DATE)'

.PHONY: all build build-server build-client run run-server run-client test clean

all: build

# Build both server and client
build: build-server build-client

# Build server only
build-server:
	@echo "Building $(SERVER_BINARY) for host..."
	go build -ldflags "$(LDFLAGS_BASE) -X github.com/HT4w5/flux/pkg/meta.Platform=$(shell go env GOOS)/$(shell go env GOARCH)" -o bin/$(SERVER_BINARY) cmd/fluxs/main.go

# Build client only
build-client:
	@echo "Building $(CLIENT_BINARY) for host..."
	go build -ldflags "$(LDFLAGS_BASE) -X github.com/HT4w5/flux/pkg/meta.Platform=$(shell go env GOOS)/$(shell go env GOARCH)" -o bin/$(CLIENT_BINARY) cmd/fluxc/main.go

# Run server (builds first)
run: run-server

# Run server only
run-server: build-server
	./bin/$(SERVER_BINARY)

# Run client only
run-client: build-client
	./bin/$(CLIENT_BINARY)

test:
	@echo "Running tests..."
	go test -v -race -cover ./...

clean:
	@echo "Cleaning up..."
	rm -rf bin/
	go clean
