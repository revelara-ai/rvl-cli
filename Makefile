# rvlscan build + helper packaging.
#
# The scanner binary discovers its language retriever helpers (goindex,
# pyindex, tsindex, javaindex, rustindex) at runtime in this order: an env
# override (RVLSCAN_GOINDEX / RVLSCAN_PYINDEX / RVLSCAN_TSINDEX /
# RVLSCAN_JAVAINDEX / RVLSCAN_RUSTINDEX), then a helper sitting NEXT TO the
# rvlscan binary, then the copy the binary CARRIES and extracts to
# ~/.revelara/helpers/<version>/, then PATH.
#
# Since po-aml3h the scripted helpers (pyindex.py, tsindex.js, javaindex.java)
# are embedded in the binary, so `make helpers` is no longer needed to scan
# those languages — it is now for DEVELOPING them: the adjacent copy outranks
# the embedded one, so an edit to helpers/pyindex/pyindex.py takes effect
# without a rebuild of rvlscan. (A rebuild re-embeds it either way.)
#
# `helpers` still matters for goindex, which is a Go binary this Makefile is
# the only local way to produce. rustindex and cindex are workspace crates, so
# a plain `cargo build` already lands them next to rvlscan; rustindex needs
# rust-analyzer at runtime (`rustup component add rust-analyzer`) and cindex
# needs a system libclang.
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

## install: release-build rvlscan + goindex/pyindex/cindex/rustindex and put them on PATH (BINDIR)
install:
	$(CARGO) build --release -p rvlscan -p cindex -p rustindex
	$(GO) build -C helpers/goindex -o $(abspath target/release)/goindex .
	install -d "$(BINDIR)"
	install -m 0755 target/release/rvlscan "$(BINDIR)/rvlscan"
	install -m 0755 target/release/goindex "$(BINDIR)/goindex"
	install -m 0755 target/release/cindex "$(BINDIR)/cindex"
	install -m 0755 target/release/rustindex "$(BINDIR)/rustindex"
	install -m 0644 helpers/pyindex/pyindex.py "$(BINDIR)/pyindex.py"
	@# Java: javaindex is a single source file run in JEP 330 source-file mode
	@# (`java javaindex.java`) -- no build step; scanning Java needs a JDK 11+.
	install -m 0644 helpers/javaindex/javaindex.java "$(BINDIR)/javaindex.java"
	@# TypeScript: tsindex is a Node script needing `typescript`. Install
	@# tsindex.js adjacent to the binary and put its `typescript` dep in
	@# $(PREFIX)/node_modules, which Node resolves by walking up from BINDIR.
	@# Zero-env once installed; skipped (Go/Python still work) if Node is absent.
	@if command -v node >/dev/null 2>&1; then \
	  npm --prefix helpers/tsindex install --no-audit --no-fund --silent >/dev/null 2>&1 || true; \
	  install -m 0644 helpers/tsindex/tsindex.js "$(BINDIR)/tsindex.js"; \
	  mkdir -p "$(PREFIX)/node_modules"; \
	  cp -R helpers/tsindex/node_modules/typescript "$(PREFIX)/node_modules/"; \
	  echo "installed rvlscan + goindex + pyindex.py + tsindex.js + javaindex.java to $(BINDIR)"; \
	  echo "  Go, Python, and TypeScript scanning work with zero env; Java needs a JDK 11+ on PATH."; \
	else \
	  echo "installed rvlscan + goindex + pyindex.py + javaindex.java to $(BINDIR)"; \
	  echo "  Go + Python work out of the box; TypeScript needs Node; Java needs a JDK 11+."; \
	fi
	@case ":$$PATH:" in *":$(BINDIR):"*) : ;; *) echo "  NOTE: $(BINDIR) is not on your PATH — add it, then: rvlscan scan <path>";; esac

## uninstall: remove the installed binary + helpers from BINDIR
uninstall:
	rm -f "$(BINDIR)/rvlscan" "$(BINDIR)/goindex" "$(BINDIR)/cindex" "$(BINDIR)/rustindex" "$(BINDIR)/pyindex.py" "$(BINDIR)/tsindex.js" "$(BINDIR)/javaindex.java"
	rm -rf "$(PREFIX)/node_modules/typescript"
	@echo "removed rvlscan + goindex + cindex + rustindex + pyindex.py + tsindex.js + javaindex.java from $(BINDIR)"

## helpers: build goindex and place goindex + pyindex + javaindex next to the rvlscan binary
## (cindex and rustindex are workspace bins: `build` already drops them in the
## adjacent slot; scanning C/C++ additionally needs a system libclang until
## releases vendor a pinned LLVM; scanning Rust needs rust-analyzer at runtime)
helpers: build
	$(GO) build -C helpers/goindex -o $(abspath $(BIN_DIR))/goindex .
	cp helpers/pyindex/pyindex.py $(BIN_DIR)/pyindex.py
	cp helpers/javaindex/javaindex.java $(BIN_DIR)/javaindex.java
	@echo "helpers installed next to $(BIN_DIR)/rvlscan (goindex, pyindex.py, javaindex.java, cindex, rustindex)"

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
