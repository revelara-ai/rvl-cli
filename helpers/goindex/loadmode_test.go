package main

import (
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// po-av01j.133.11: goindex peak RSS tracked the DEPENDENCY graph, not the repo.
// NeedDeps next to NeedSyntax|NeedTypesInfo makes go/packages parse and
// type-check every transitive dependency -- the standard library and every
// imported module -- from source, keeping every function body's AST and type
// facts. goindex only reads the ROOT packages' bodies, so all of that was dead
// weight: 2.26 GB on a 28 MB prometheus checkout, 3.8 GB on a 57 MB temporal
// one. A pre-commit hook that can OOM the machine it protects gets uninstalled.
//
// Dependencies are still type-checked from source (export data would need a
// compile, which on a cold build cache blows the hook's 10s cap), but their
// function bodies are dropped at parse time. Roots keep everything.

// loadFixture loads testdata/fixture through `dir` with the config every
// goindex load uses.
func loadFixture(t *testing.T, dir string) []*packages.Package {
	t.Helper()
	pkgs, err := packages.Load(loadConfig(dir), "./...")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("fixture loaded no packages")
	}
	return pkgs
}

// bodies counts function declarations with and without a body in p.
func bodies(p *packages.Package) (with, without int) {
	for _, f := range p.Syntax {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if fd.Body != nil {
					with++
				} else {
					without++
				}
			}
		}
	}
	return with, without
}

// assertRootsKeepBodies is the half that must never regress: a root file
// parsed without bodies loses its call sites silently.
func assertRootsKeepBodies(t *testing.T, pkgs []*packages.Package) {
	t.Helper()
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			t.Errorf("root package %s must carry type info", p.ID)
		}
		if with, _ := bodies(p); with == 0 {
			t.Errorf("root package %s lost its function bodies; its call sites are unreadable", p.ID)
		}
	}
}

func TestLoadConfigDropsDependencyBodiesAndKeepsRootBodies(t *testing.T) {
	// Relative on purpose: the existing retrieval tests pass relative roots,
	// and go/packages reports absolute filenames.
	pkgs := loadFixture(t, "testdata/fixture")
	assertRootsKeepBodies(t, pkgs)

	fixture, err := filepath.Abs("testdata/fixture")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		// Anything under the module directory keeps its bodies: that covers
		// the roots and the in-tree stubcron module the fixture `replace`s,
		// which is the safe direction to err in.
		if len(p.GoFiles) == 0 || strings.HasPrefix(p.GoFiles[0], fixture+string(filepath.Separator)) {
			return
		}
		with, without := bodies(p)
		checked += without
		if with > 0 {
			t.Errorf("dependency %s kept %d function bodies; only root packages may, "+
				"or peak RSS tracks the dependency graph", p.ID, with)
		}
	})
	// The fixture imports net/http and database/sql. If no dependency
	// declaration was seen at all, the assertion above held vacuously.
	if checked == 0 {
		t.Fatal("no dependency function declarations were visible, so the check above proved nothing")
	}
}

// The module is recognised by path prefix. A repo reached through a symlink
// must still count as the module, or every root file loses its bodies and the
// scan reports nothing without saying why.
func TestLoadConfigKeepsRootBodiesThroughASymlink(t *testing.T) {
	abs, err := filepath.Abs("testdata/fixture")
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(abs, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	assertRootsKeepBodies(t, loadFixture(t, link))
}
