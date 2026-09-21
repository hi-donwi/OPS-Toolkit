GO ?= $(shell which go 2>/dev/null || echo /opt/homebrew/bin/go)
BINARY_NAME = opskit
BUILD_DIR = bin
VERSION = 0.1.0
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -s -w -X 'github.com/hi-donwi/OPS-Toolkit/cmd.Version=$(VERSION)' -X 'github.com/hi-donwi/OPS-Toolkit/cmd.GitCommit=$(COMMIT)' -X 'github.com/hi-donwi/OPS-Toolkit/cmd.BuildDate=$(DATE)'

.PHONY: all build test clean build-linux run help licenses licenses-check

all: build

help:
	@echo "opskit build commands:"
	@echo "  make build         - Build local binary for current OS/ARCH"
	@echo "  make build-linux   - Cross-compile for Linux (amd64 & arm64)"
	@echo "  make test          - Run unit tests"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make licenses      - Regenerate THIRD_PARTY_LICENSES.md"
	@echo "  make licenses-check- Fail if THIRD_PARTY_LICENSES.md is out of date"

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Done! Binary located at $(BUILD_DIR)/$(BINARY_NAME)"

build-linux:
	@echo "Cross-compiling for Linux amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Cross-compiling for Linux arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "Linux binaries generated in $(BUILD_DIR)/"

test:
	$(GO) test -v ./...

clean:
	@rm -rf $(BUILD_DIR)

# Attribution has to match what is actually shipped, so this is regenerated from
# the modules linked into the release binaries rather than maintained by hand.
licenses:
	@python3 scripts/gen-third-party-licenses.py

# Used by CI: adding a dependency without refreshing attribution is a licence
# compliance gap, not a style nit.
licenses-check: licenses
	@git diff --exit-code -- THIRD_PARTY_LICENSES.md \
		|| (echo "THIRD_PARTY_LICENSES.md is stale. Run 'make licenses' and commit the result." && exit 1)
