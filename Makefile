# Vista Platform customer agents: the passive sensor and the device
# interrogation agent. `make help` lists the targets.
#
# Builds use the Go release go.mod names (GOTOOLCHAIN pinned to it, never
# "auto") and never a workspace (GOWORK=off).

GO_VERSION := $(shell sed -n 's/^go \([0-9][0-9.]*\)$$/\1/p' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)
export GOWORK := off
AGENT_VERSION ?= dev
# The leading "v" is stripped: the platform stores the bare version and shows
# it as v{version}. scripts/build.sh applies these flags.
AGENT_LDFLAGS := -X main.Version=$(patsubst v%,%,$(AGENT_VERSION))
export AGENT_VERSION AGENT_LDFLAGS

SENSOR_TARGETS := linux-amd64 linux-arm64 windows-amd64 windows-386 darwin-amd64 darwin-arm64
DEVICE_AGENT_TARGETS := linux-amd64 linux-arm64 windows-amd64 windows-386 darwin-amd64 darwin-arm64

.PHONY: help sensor device-agent sensor-all device-agent-all windows \
	$(addprefix sensor-,$(SENSOR_TARGETS)) $(addprefix device-agent-,$(DEVICE_AGENT_TARGETS)) \
	build vet test fmt-check tidy-check cgo-free scripts-deps generate generate-check \
	oui-registry-test classification-rules-test dcim-types-test sensor-no-ouiregistry-test installer-test check

help: ## List targets
	@awk -F':.*## ' '/^[a-z0-9-]+:.*## / { printf "  %-28s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# --- binaries ----------------------------------------------------------------

sensor: ## Build bin/crypto-sensor for this machine (CGO, libpcap)
	scripts/build.sh sensor native

device-agent: ## Build bin/device-agent for this machine
	scripts/build.sh device-agent native

sensor-linux-amd64: ## Build the sensor for Linux x86_64 (CGO, libpcap)
	scripts/build.sh sensor linux-amd64
sensor-linux-arm64: ## Build the sensor for Linux ARM64 (CGO: an arm64 C toolchain and libpcap, or a native runner)
	scripts/build.sh sensor linux-arm64
sensor-windows-amd64: ## Build the sensor for Windows x86_64 (Npcap at run time)
	scripts/build.sh sensor windows-amd64
sensor-windows-386: ## Build the sensor for Windows x86 (Npcap at run time)
	scripts/build.sh sensor windows-386
sensor-darwin-amd64: ## Build the sensor for macOS x86_64 (CGO: a macOS host)
	scripts/build.sh sensor darwin-amd64
sensor-darwin-arm64: ## Build the sensor for macOS ARM64 (CGO: a macOS host)
	scripts/build.sh sensor darwin-arm64

device-agent-linux-amd64: ## Build the device agent for Linux x86_64
	scripts/build.sh device-agent linux-amd64
device-agent-linux-arm64: ## Build the device agent for Linux ARM64
	scripts/build.sh device-agent linux-arm64
device-agent-windows-amd64: ## Build the device agent for Windows x86_64
	scripts/build.sh device-agent windows-amd64
device-agent-windows-386: ## Build the device agent for Windows x86
	scripts/build.sh device-agent windows-386
device-agent-darwin-amd64: ## Build the device agent for macOS x86_64
	scripts/build.sh device-agent darwin-amd64
device-agent-darwin-arm64: ## Build the device agent for macOS ARM64
	scripts/build.sh device-agent darwin-arm64

sensor-all: sensor-linux-amd64 sensor-linux-arm64 sensor-windows-amd64 sensor-darwin-amd64 sensor-darwin-arm64 ## Build the sensor for every released target

device-agent-all: device-agent-linux-amd64 device-agent-linux-arm64 device-agent-windows-amd64 device-agent-darwin-amd64 device-agent-darwin-arm64 ## Build the device agent for every released target

windows: sensor-windows-amd64 device-agent-windows-amd64 ## Build both agents for Windows x86_64

# --- checks ------------------------------------------------------------------

build: ## go build ./... (CGO on: the sensor needs libpcap-dev)
	CGO_ENABLED=1 go build ./...

vet: ## go vet ./...
	CGO_ENABLED=1 go vet ./...

test: scripts-deps ## go test ./... (the generator drift test needs node and scripts/node_modules)
	CGO_ENABLED=1 go test ./...

fmt-check: ## Fail when gofmt would change a file
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt:"; echo "$$out"; exit 1; fi

tidy-check: ## Fail when go.mod or go.sum is not tidy
	go mod tidy -diff

cgo-free: ## The device agent and shared/ build with CGO off on every target
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		echo "CGO_ENABLED=0 $$t"; \
		CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} go build ./cmd/device-agent/... ./internal/deviceagent/... ./shared/... || exit 1; \
	done

scripts-deps: scripts/node_modules/.package-lock.json ## Install the generators' npm dependencies

scripts/node_modules/.package-lock.json: scripts/package.json scripts/package-lock.json
	cd scripts && npm ci --no-audit --no-fund

generate: scripts-deps ## Regenerate the Go tables from standards/
	node scripts/generate-asset-classes.mjs
	node scripts/generate-classification-rules.mjs
	node scripts/generate-dcim-types.mjs
	node scripts/generate-fact-keys.mjs
	node scripts/generate-oui-registry.mjs
	node scripts/generate-vocabulary.mjs

generate-check: scripts-deps ## Fail when a generated Go table is out of date
	node scripts/generate-asset-classes.mjs --check
	node scripts/generate-classification-rules.mjs --check
	node scripts/generate-dcim-types.mjs --check
	node scripts/generate-fact-keys.mjs --check
	node scripts/generate-oui-registry.mjs --check
	node scripts/generate-vocabulary.mjs --check

oui-registry-test: scripts-deps ## Test + mutation-test the OUI vendor-map generator
	node --test ./scripts/generate-oui-registry.test.mjs

classification-rules-test: scripts-deps ## Test + mutation-test the classification-rule generator
	node --test ./scripts/generate-classification-rules.test.mjs

dcim-types-test: scripts-deps ## Test + mutation-test the DCIM type-registry generator and its Go mirror
	node --test ./scripts/generate-dcim-types.test.mjs
	go test ./shared/dcim/

sensor-no-ouiregistry-test: ## Guard (self-mutation-tested) that the sensor never imports shared/ouiregistry
	node ./scripts/test-sensor-no-ouiregistry.mjs

installer-test: ## Test the sensor and device-agent installers
	node --test ./scripts/test-sensor-installer-dependencies.mjs
	node --test ./scripts/test-device-agent-installer.mjs
	node --test ./scripts/test-sensor-installer-registration.mjs

check: fmt-check tidy-check build vet test cgo-free generate-check oui-registry-test classification-rules-test dcim-types-test sensor-no-ouiregistry-test installer-test ## Every check above
