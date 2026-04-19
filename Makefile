.PHONY: build install clean

GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	go build -ldflags "-X main.version=$(GIT_VERSION) -X main.gitHash=$(GIT_HASH)" -o rvl ./cmd/rvl

install: build
	sudo cp rvl /usr/local/bin/rvl
	@echo "Installed rvl CLI to /usr/local/bin/rvl"

clean:
	rm -f rvl
