# rvlscan build + helper packaging.
#
# The scanner binary discovers its language retriever helpers (goindex,
# pyindex) at runtime in this order: an env override (RVLSCAN_GOINDEX /
# RVLSCAN_PYINDEX), then a helper sitting NEXT TO the rvlscan binary, then
# PATH. The `helpers` target populates that adjacent slot so a locally built
# `rvlscan scan` needs no env var — the same layout a release archive ships.
#
# Overridable: PROFILE (debug|release), CARGO, GO (e.g. `make helpers
# GO='env -u GOROOT go'` on a gvm box whose GOROOT is mismatched).

PROFILE ?= debug
CARGO   ?= cargo
GO      ?= go

ifeq ($(PROFILE),release)
CARGO_FLAGS := --release
else
CARGO_FLAGS :=
endif

BIN_DIR := target/$(PROFILE)

.PHONY: build helpers dev test lint fmt fmt-check clippy clean help

## build: compile the rvlscan workspace binaries
build:
	$(CARGO) build $(CARGO_FLAGS)

## helpers: build goindex and place goindex + pyindex next to the rvlscan binary
helpers: build
	$(GO) build -C helpers/goindex -o $(abspath $(BIN_DIR))/goindex .
	cp helpers/pyindex/pyindex.py $(BIN_DIR)/pyindex.py
	@echo "helpers installed next to $(BIN_DIR)/rvlscan (goindex, pyindex.py)"

## dev: build the binary and its helpers for local zero-env `rvlscan scan`
dev: helpers
	@echo "run: $(BIN_DIR)/rvlscan scan <path>"

## test: run the workspace test suite
test:
	$(CARGO) test --workspace

## lint: clippy with warnings denied
lint clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

## fmt: format the workspace
fmt:
	$(CARGO) fmt --all

## fmt-check: verify formatting without writing
fmt-check:
	$(CARGO) fmt --all --check

## clean: remove build artifacts
clean:
	$(CARGO) clean

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
