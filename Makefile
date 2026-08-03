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
# Where `install` puts the binary + its helpers. Override with
# `make install BINDIR=/usr/local/bin` (may need sudo).
PREFIX  ?= $(HOME)/.local
BINDIR  ?= $(PREFIX)/bin

ifeq ($(PROFILE),release)
CARGO_FLAGS := --release
else
CARGO_FLAGS :=
endif

BIN_DIR := target/$(PROFILE)

.PHONY: build rebuild install uninstall helpers dev test lint fmt fmt-check clippy clean help

## build: compile the rvlscan workspace binaries
build:
	$(CARGO) build $(CARGO_FLAGS)

## rebuild: force a clean recompile of the rvlscan binary
rebuild:
	$(CARGO) build $(CARGO_FLAGS) -p rvlscan

## install: release-build rvlscan + goindex/pyindex and put them on PATH (BINDIR)
install:
	$(CARGO) build --release -p rvlscan
	$(GO) build -C helpers/goindex -o $(abspath target/release)/goindex .
	install -d "$(BINDIR)"
	install -m 0755 target/release/rvlscan "$(BINDIR)/rvlscan"
	install -m 0755 target/release/goindex "$(BINDIR)/goindex"
	install -m 0644 helpers/pyindex/pyindex.py "$(BINDIR)/pyindex.py"
	@echo "installed rvlscan + goindex + pyindex.py to $(BINDIR)"
	@echo "  Go + Python scanning work out of the box (helpers are adjacent to the binary)."
	@echo "  TypeScript needs its node deps, so until TS packaging (po-3t3oj.26):"
	@echo "    RVLSCAN_TSINDEX=$(abspath helpers/tsindex/tsindex.js)  (run 'npm --prefix helpers/tsindex install' once)"
	@case ":$$PATH:" in *":$(BINDIR):"*) : ;; *) echo "  NOTE: $(BINDIR) is not on your PATH — add it, then: rvlscan scan <path>";; esac

## uninstall: remove the installed binary + helpers from BINDIR
uninstall:
	rm -f "$(BINDIR)/rvlscan" "$(BINDIR)/goindex" "$(BINDIR)/pyindex.py"
	@echo "removed rvlscan + goindex + pyindex.py from $(BINDIR)"

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
