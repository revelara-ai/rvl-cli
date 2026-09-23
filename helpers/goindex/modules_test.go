package main

import (
	"os"
	"path/filepath"
	"strings"
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

// po-pk3fp.12: dolthub/dolt reported the whole Go lane FAILED because its
// FIRST module by walk order, proto/, is protobuf-only -- `go list ./...`
// matches no packages there. goindex turned that into a load error, returned
// on it, and exit 2'd, discarding go/ and its 201 packages. Discovery was
// never the bug; classification was. An EMPTY module is a third state: not
// "loaded and clean", not "failed to load", but "there was nothing here to
// examine". It belongs with abstain, not with FAILED.

// twoModuleRepo builds a repo whose first module by walk order is empty
// (a go.mod beside a single .proto file, the dolt proto/ shape) and whose
// second carries one package with a client call. "aproto" sorts before "go"
// so the empty one is reached first, which is the condition that broke.
func twoModuleRepo(t *testing.T, populate bool) string {
	t.Helper()
	root := t.TempDir()

	empty := filepath.Join(root, "aproto")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(empty, "go.mod"), []byte("module proto\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(empty, "svc.proto"), []byte("syntax = \"proto3\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	second := filepath.Join(root, "go")
	if err := os.MkdirAll(second, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "go.mod"), []byte("module product\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !populate {
		if err := os.WriteFile(filepath.Join(second, "svc.proto"), []byte("syntax = \"proto3\";\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	src := "package product\n\nimport \"log/slog\"\n\nfunc Handle() {\n\tslog.Info(\"served\")\n}\n"
	if err := os.WriteFile(filepath.Join(second, "svc.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRetrieveAllKeepsGoingPastAnEmptyFirstModule(t *testing.T) {
	// THE BEAD. The empty module must cost nothing: the populated module's
	// sites still come back, and the run is not an error.
	root := twoModuleRepo(t, true)
	sites, scan := runRetrieveAll(root, "t")

	if scan.Err != nil {
		t.Fatalf("an empty module is not a load failure, got %v (module %s)", scan.Err, scan.FailedDir)
	}
	if len(scan.Discovered) != 2 {
		t.Fatalf("want 2 discovered modules, got %v", scan.Discovered)
	}
	if len(scan.Loaded) != 1 || filepath.Base(scan.Loaded[0]) != "go" {
		t.Fatalf("want only the populated module loaded, got %v", scan.Loaded)
	}
	if len(scan.Empty) != 1 || filepath.Base(scan.Empty[0]) != "aproto" {
		t.Fatalf("want the protobuf-only module counted empty, got %v", scan.Empty)
	}
	if len(sites) == 0 {
		t.Fatal("the populated module's sites were discarded by the empty one -- this is the dolt bug")
	}
	for _, s := range sites {
		if !strings.HasPrefix(s.File, "go/") {
			t.Fatalf("sites must stay repo-relative across modules, got %q", s.File)
		}
	}
}

func TestRetrieveAllWithEveryModuleEmptyAbstainsRatherThanReportingClean(t *testing.T) {
	// The negative. Nothing loaded, so there is nothing to call clean. This
	// must reach the caller as Loaded == 0 with no error, which main maps to
	// ABSTAIN -- never an empty stream at exit 0.
	root := twoModuleRepo(t, false)
	sites, scan := runRetrieveAll(root, "t")

	if scan.Err != nil {
		t.Fatalf("empty modules are not load failures, got %v", scan.Err)
	}
	if len(scan.Discovered) != 2 {
		t.Fatalf("want 2 discovered modules, got %v", scan.Discovered)
	}
	if len(scan.Loaded) != 0 {
		t.Fatalf("no module carried Go, so none may count as loaded, got %v", scan.Loaded)
	}
	if len(scan.Empty) != 2 {
		t.Fatalf("want both modules counted empty, got %v", scan.Empty)
	}
	if len(sites) != 0 {
		t.Fatalf("want no sites, got %d", len(sites))
	}
}

func TestRetrieveAllWithNoModuleDiscoversNothing(t *testing.T) {
	// Discovered == 0 is a DIFFERENT abstention from "every module is empty":
	// there was no go.mod to load at all. main keeps them on separate
	// messages so the operator can tell "not a Go repo" from "no Go here".
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sites, scan := runRetrieveAll(root, "t")
	if len(scan.Discovered) != 0 || len(scan.Loaded) != 0 || scan.Err != nil {
		t.Fatalf("want a bare discovery miss, got %+v", scan)
	}
	if len(sites) != 0 {
		t.Fatalf("want no sites, got %d", len(sites))
	}
}

func TestRetrieveAllStillFailsOnAGenuineLoadErrorAndNamesTheModule(t *testing.T) {
	// REGRESSION GUARD for po-av01j.209. Relaxing the empty case must not
	// relax the broken case: a module whose package graph cannot be loaded
	// still errors, because there Go source DOES exist and was not read.
	root := t.TempDir()
	broken := filepath.Join(root, "broken")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "go.mod"), []byte("this is not a go.mod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "a.go"), []byte("package broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, scan := runRetrieveAll(root, "t")
	if scan.Err == nil {
		t.Fatal("a module that cannot be loaded must still fail the lane (po-av01j.209)")
	}
	if scan.FailedDir != broken {
		t.Fatalf("the failing module must be named, want %s got %q", broken, scan.FailedDir)
	}
	if len(scan.Loaded) != 0 {
		t.Fatalf("a failed load must not count as loaded, got %v", scan.Loaded)
	}
}
