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

.PHONY: build rebuild install uninstall helpers helpers-csindex dev test lint fmt fmt-check clippy clean help

## build: compile the rvlscan workspace binaries
build:
	$(CARGO) build $(CARGO_FLAGS)

## rebuild: force a clean recompile of the rvlscan binary
rebuild:
	$(CARGO) build $(CARGO_FLAGS) -p rvlscan

## install: release-build rvlscan + goindex/pyindex/cindex and put them on PATH (BINDIR)
install:
	$(CARGO) build --release -p rvlscan -p cindex
	$(GO) build -C helpers/goindex -o $(abspath target/release)/goindex .
	install -d "$(BINDIR)"
	install -m 0755 target/release/rvlscan "$(BINDIR)/rvlscan"
	install -m 0755 target/release/goindex "$(BINDIR)/goindex"
	install -m 0755 target/release/cindex "$(BINDIR)/cindex"
	install -m 0644 helpers/pyindex/pyindex.py "$(BINDIR)/pyindex.py"
	@# TypeScript: tsindex is a Node script needing `typescript`. Install
	@# tsindex.js adjacent to the binary and put its `typescript` dep in
	@# $(PREFIX)/node_modules, which Node resolves by walking up from BINDIR.
	@# Zero-env once installed; skipped (Go/Python still work) if Node is absent.
	@if command -v node >/dev/null 2>&1; then \
	  npm --prefix helpers/tsindex install --no-audit --no-fund --silent >/dev/null 2>&1 || true; \
	  install -m 0644 helpers/tsindex/tsindex.js "$(BINDIR)/tsindex.js"; \
	  mkdir -p "$(PREFIX)/node_modules"; \
	  cp -R helpers/tsindex/node_modules/typescript "$(PREFIX)/node_modules/"; \
	  echo "installed rvlscan + goindex + pyindex.py + tsindex.js to $(BINDIR)"; \
	  echo "  Go, Python, and TypeScript scanning all work with zero env."; \
	else \
	  echo "installed rvlscan + goindex + pyindex.py to $(BINDIR)"; \
	  echo "  Go + Python work out of the box; TypeScript needs Node (install it, then re-run 'make install')."; \
	fi
	@case ":$$PATH:" in *":$(BINDIR):"*) : ;; *) echo "  NOTE: $(BINDIR) is not on your PATH — add it, then: rvlscan scan <path>";; esac

## uninstall: remove the installed binary + helpers from BINDIR
uninstall:
	rm -f "$(BINDIR)/rvlscan" "$(BINDIR)/goindex" "$(BINDIR)/cindex" "$(BINDIR)/pyindex.py" "$(BINDIR)/tsindex.js"
	rm -rf "$(PREFIX)/node_modules/typescript"
	@echo "removed rvlscan + goindex + cindex + pyindex.py + tsindex.js from $(BINDIR)"

## helpers: build goindex and place goindex + pyindex next to the rvlscan binary
## (cindex is a workspace bin: `build` already drops it in the adjacent slot;
## scanning C/C++ additionally needs a system libclang until releases vendor
## a pinned LLVM)
helpers: build
	$(GO) build -C helpers/goindex -o $(abspath $(BIN_DIR))/goindex .
	cp helpers/pyindex/pyindex.py $(BIN_DIR)/pyindex.py
	@echo "helpers installed next to $(BIN_DIR)/rvlscan (goindex, pyindex.py, cindex)"

## helpers-csindex: build the C# retriever (needs a .NET 8 SDK + NuGet for Roslyn)
helpers-csindex:
	dotnet build helpers/csindex -c Release -o $(BIN_DIR)/csindex-build
	@echo "csindex built; C# scanning works via RVLSCAN_CSINDEX=$(abspath $(BIN_DIR))/csindex-build/csindex.dll"

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
