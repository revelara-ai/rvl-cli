package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A spec for a function the scanned repository declares itself is useful to
// that one repository only, so the packet says where the CALLED function is
// declared. The receiver type is the wrong test: a repository type that embeds
// *sql.DB has the standard library's ExecContext, and that call is a real
// database/sql surface.
func TestAPIInRepoMarksCallsToFunctionsTheRepositoryDeclares(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Two modules, as in a monorepo: a call from one into the other is still
	// a call into the repository.
	write("svc/go.mod", "module example.com/shop/svc\n\ngo 1.21\n\n"+
		"require example.com/shop/lib v0.0.0\n\nreplace example.com/shop/lib => ../lib\n")
	write("lib/go.mod", "module example.com/shop/lib\n\ngo 1.21\n")
	write("lib/lib.go", `package lib

func Get(key string) string { return key }
`)
	write("svc/svc.go", `package svc

import (
	"context"
	"database/sql"

	"example.com/shop/lib"
)

type Store struct{ *sql.DB }

type Ledger struct{}

func (Ledger) Query(q string) error { return nil }

func Local(l Ledger) error { return l.Query("x") }

func Promoted(ctx context.Context, s Store) { s.ExecContext(ctx, "x") }

func Dependency(ctx context.Context, db *sql.DB) { db.ExecContext(ctx, "x") }

func Sibling() string { return lib.Get("k") }
`)
	sites, scan := runRetrieveAll(root, "shop")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	got := map[string]RetrievedSite{}
	for _, s := range sites {
		got[s.Symbol] = s
	}
	for symbol, want := range map[string]bool{
		"Local":      true,
		"Promoted":   false,
		"Dependency": false,
		"Sibling":    true,
	} {
		s, ok := got[symbol]
		if !ok {
			t.Fatalf("no site retrieved in %s; got %+v", symbol, sites)
		}
		if s.Prov.APIInRepo != want {
			t.Errorf("%s: %s.%s api_in_repo = %v, want %v",
				symbol, s.ClientType, s.Method, s.Prov.APIInRepo, want)
		}
	}

	// On the wire the mark is present only when true, so a packet from a
	// repository with no such call is byte-identical to what it was.
	for symbol, want := range map[string]bool{"Local": true, "Dependency": false} {
		b, err := json.Marshal(got[symbol])
		if err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(string(b), `"api_in_repo":true`); has != want {
			t.Errorf("%s: api_in_repo on the wire = %v, want %v: %s", symbol, has, want, b)
		}
		if !want && strings.Contains(string(b), "api_in_repo") {
			t.Errorf("%s: a false mark must be absent: %s", symbol, b)
		}
	}
}

func TestInRepoMatchesAModulePathOnAPathBoundary(t *testing.T) {
	mods := []string{"example.com/shop"}
	for path, want := range map[string]bool{
		"example.com/shop":          true,
		"example.com/shop/internal": true,
		"example.com/shopping":      false,
		"example.com":               false,
		"net/http":                  false,
	} {
		if got := inRepo(mods, path); got != want {
			t.Errorf("inRepo(%q) = %v, want %v", path, got, want)
		}
	}
}
