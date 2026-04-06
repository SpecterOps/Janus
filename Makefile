IMAGE   := janus
TAG     := latest

# Single source of truth for semver: pyproject.toml (Python bundles + local CLI).
JANUS_VERSION := $(shell sed -n 's/^version = "\([^"]*\)".*/\1/p' pyproject.toml | head -1)
ifeq ($(strip $(JANUS_VERSION)),)
$(error Could not read version from pyproject.toml)
endif
CLI_LDFLAGS := -ldflags="-s -w -X main.version=$(JANUS_VERSION)"

# Host OS from the Go toolchain — Windows needs .exe for PowerShell/cmd.
GOHOSTOS := $(shell go env GOOS)
ifeq ($(GOHOSTOS),windows)
CLI_OUT := ../../janus-cli.exe
else
CLI_OUT := ../../janus-cli
endif

.PHONY: build test shell clean help cli cli-all

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
	@echo ""
	@echo "Build the CLI: make cli"

build: ## Build the Docker image
	docker build -t $(IMAGE):$(TAG) .

test: build ## Run the test suite inside the container
	docker run --rm --entrypoint sh \
		-v $(CURDIR):/src:ro \
		-w /src \
		$(IMAGE):$(TAG) -c "pip install -q pytest && pytest Tests/"

shell: build ## Open a shell in the container
	docker run --rm -it --entrypoint /bin/bash \
		-v $(CURDIR)/out:/data/out \
		-v $(CURDIR)/Config:/config:ro \
		$(IMAGE):$(TAG)

clean: ## Remove all versioned output directories and loose output files
	rm -rf out/op-* out/latest out/latest.txt out/*.json out/*.ndjson out/*.html

cli: ## Build the Go CLI binary for the current platform (janus-cli.exe on Windows)
	cd cmd/janus-cli && go build $(CLI_LDFLAGS) -o $(CLI_OUT) .

cli-all: ## Cross-compile Go CLI for all platforms
	cd cmd/janus-cli && GOOS=linux GOARCH=amd64 go build $(CLI_LDFLAGS) -o ../../dist/janus-cli-linux-amd64 .
	cd cmd/janus-cli && GOOS=linux GOARCH=arm64 go build $(CLI_LDFLAGS) -o ../../dist/janus-cli-linux-arm64 .
	cd cmd/janus-cli && GOOS=darwin GOARCH=amd64 go build $(CLI_LDFLAGS) -o ../../dist/janus-cli-darwin-amd64 .
	cd cmd/janus-cli && GOOS=darwin GOARCH=arm64 go build $(CLI_LDFLAGS) -o ../../dist/janus-cli-darwin-arm64 .
	cd cmd/janus-cli && GOOS=windows GOARCH=amd64 go build $(CLI_LDFLAGS) -o ../../dist/janus-cli-windows-amd64.exe .
