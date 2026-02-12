.PHONY: all build build-all build-local clean test lint tidy version tag release-check

GOOS_ARCH := linux/amd64 linux/arm64 linux/386 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 windows/386
DIST_DIR := dist
BINARY_NAME := aigate

# Version information - can be overridden by environment variable
ifeq ($(origin VERSION), environment)
  # VERSION is set from environment
else
  VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
endif

BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

all: build-local

build: build-all

build-local:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY_NAME) .

build-all:
	@echo "Building binaries..."
	@echo "Version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo "Git commit: $(GIT_COMMIT)"
	@mkdir -p $(DIST_DIR)
	@for t in $(GOOS_ARCH); do \
		os=$${t%/*}; arch=$${t#*/}; \
		bin_name=$(BINARY_NAME)-$${os}-$${arch}; \
		if [ "$$os" = "windows" ]; then bin_name="$${bin_name}.exe"; fi; \
		bin_path=$(DIST_DIR)/$$bin_name; \
		echo "  Building for $$os/$$arch..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o $$bin_path .; \
	done
	@echo "Build complete. Binaries in $(DIST_DIR)/"

test:
	@echo "Running tests..."
	go test ./... -v
	@echo "All tests passed."

lint:
	@echo "Running linter..."
	golangci-lint run --timeout=5m

tidy:
	go mod tidy

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST_DIR)
	rm -f $(BINARY_NAME)
	@echo "Clean complete."

version:
	@echo "Current version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo "Git commit: $(GIT_COMMIT)"

tag:
	@if [ "$(VERSION)" = "dev" ]; then \
		echo "Error: Cannot tag dev version. Please set VERSION environment variable."; \
		exit 1; \
	fi
	@echo "Creating git tag: $(VERSION)"
	git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "Tag created. Push with: git push origin $(VERSION)"

release-check: build
	@echo "Running tests..."
	go test ./...
	@echo "All tests passed. Ready for release $(VERSION)"
