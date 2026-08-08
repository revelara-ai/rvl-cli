package main

import (
	"os"
	"path/filepath"
	"testing"
)

// po-av01j.131: goindex loaded packages from the scan root and assumed a module
// lived there. On a monorepo whose services each carry their own go.mod it
// found none, returned an empty stream, and exited 0 -- so the scan reported
// "Go was scanned and is clean" when Go had never been looked at. Measured on
// two real repos: 0 sites where 4 modules existed.

func TestDiscoverModulesFindsPerServiceModules(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"src/checkout", "src/frontend", "src/nested/deep"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := discoverModules(root)
	if len(got) != 3 {
		t.Fatalf("want 3 modules, got %d: %v", len(got), got)
	}
}

func TestDiscoverModulesPrefersARootModuleAndDoesNotDescend(t *testing.T) {
	// A repo with a root go.mod is ONE module; nested go.mod files inside it
	// would be separate modules, but the common single-module repo must not
	// fan out into its own vendored copies.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "vendor", "dep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "go.mod"), []byte("module dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := discoverModules(root)
	if len(got) != 1 || got[0] != root {
		t.Fatalf("a root module must be the only module, got %v", got)
	}
}

func TestDiscoverModulesReturnsEmptyWhenThereIsNoModule(t *testing.T) {
	// THE CASE THAT MATTERS. Empty here must reach an ABSTENTION at the call
	// site, never a silent success -- that distinction is the whole bug.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := discoverModules(root); len(got) != 0 {
		t.Fatalf("want no modules, got %v", got)
	}
}

func TestDiscoverModulesSkipsVendorAndNodeModules(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"vendor/x", "node_modules/y", ".git/z"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := discoverModules(root); len(got) != 0 {
		t.Fatalf("vendored/ignored trees must not count as modules, got %v", got)
	}
}
