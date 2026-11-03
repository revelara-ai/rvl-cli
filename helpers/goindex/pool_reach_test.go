package main

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// A pool is built inside a constructor and returned. Seeded at that
// construction, the forward trace has to leave the constructor through its
// return and reach the variables and fields the callers keep the pool in,
// and so the functions that use it.
//
// The fixture marks lines: "// seed: x" is where the trace starts,
// "// reached: x" a variable it must reach, "// not: x" one it must not.
func TestForwardTraceLeavesTheConstructorThroughItsReturn(t *testing.T) {
	dir := "testdata/poolfixture"
	pkgs, err := packages.Load(loadConfig(dir), "./...")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load %s: %v", dir, err)
	}
	ix := newReachIndex(pkgs)
	src := &srcIndex{files: map[string][]byte{}}
	rel := func(p *packages.Package, n ast.Node) (string, int) {
		pos := p.Fset.Position(n.Pos())
		return filepath.Base(pos.Filename), pos.Line
	}
	// marked["server.go:18"]["seed"] = ["db"]
	marked := map[string]map[string][]string{}
	defs := map[string]*types.Var{} // "server.go:18 db" -> the variable defined there
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			ix.collect(p, f, src, rel)
			for _, cg := range f.Comments {
				file, line := rel(p, cg)
				for _, part := range strings.Split(strings.TrimPrefix(cg.Text(), "//"), ";") {
					kind, names, ok := strings.Cut(strings.TrimSpace(part), ":")
					if !ok || (kind != "seed" && kind != "reached" && kind != "not") {
						continue
					}
					at := file + ":" + strconv.Itoa(line)
					if marked[at] == nil {
						marked[at] = map[string][]string{}
					}
					for _, n := range strings.Split(names, ",") {
						marked[at][kind] = append(marked[at][kind], strings.TrimSpace(n))
					}
				}
			}
			for id, o := range p.TypesInfo.Defs {
				if v, ok := o.(*types.Var); ok {
					file, line := rel(p, id)
					defs[file+":"+strconv.Itoa(line)+" "+id.Name] = v
				}
			}
		}
	}
	ix.finish()

	// users are the functions whose body names a variable the pool reached.
	users := func(reached map[*types.Var]bool) map[string]bool {
		out := map[string]bool{}
		for _, p := range pkgs {
			for _, f := range p.Syntax {
				for _, d := range f.Decls {
					fd, ok := d.(*ast.FuncDecl)
					if !ok || fd.Body == nil {
						continue
					}
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							if v, ok := p.TypesInfo.Uses[id].(*types.Var); ok && reached[v] {
								out[fd.Name.Name] = true
							}
						}
						return true
					})
				}
			}
		}
		return out
	}
	lookup := func(at, name string) *types.Var {
		v := defs[at+" "+name]
		if v == nil {
			t.Fatalf("%s: no variable %s defined there", at, name)
		}
		return v
	}

	cases := []struct {
		seed      string // file:line of the construction
		file      string // the file whose marks this seed answers to
		wantUsers []string
	}{
		// nakama server/db.go:122: returned, then returned again, then kept
		// in the server whose method serves requests.
		{"server.go:18", "server.go", []string{"GetAccount", "dbConnect", "serve"}},
		// crowdsec pkg/database/database.go:46: returned beside an error.
		{"database.go:9", "database.go", []string{"Flush", "NewClient", "openDB"}},
	}
	for _, tc := range cases {
		var seeds []*types.Var
		for _, n := range marked[tc.seed]["seed"] {
			seeds = append(seeds, lookup(tc.seed, n))
		}
		if len(seeds) == 0 {
			t.Fatalf("%s: no seed marked", tc.seed)
		}
		reached := ix.forward(seeds)
		for at, kinds := range marked {
			if !strings.HasPrefix(at, tc.file+":") {
				continue
			}
			for _, n := range kinds["reached"] {
				if !reached[lookup(at, n)] {
					t.Errorf("seed %s: %s at %s is not reached", tc.seed, n, at)
				}
			}
			for _, n := range kinds["not"] {
				if reached[lookup(at, n)] {
					t.Errorf("seed %s: %s at %s is reached, and must not be", tc.seed, n, at)
				}
			}
		}
		var got []string
		for u := range users(reached) {
			got = append(got, u)
		}
		sort.Strings(got)
		if strings.Join(got, " ") != strings.Join(tc.wantUsers, " ") {
			t.Errorf("seed %s: users %v, want %v", tc.seed, got, tc.wantUsers)
		}
	}
}
