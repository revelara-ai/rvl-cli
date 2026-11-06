// Protective sites: a call where an in-code protective mechanism decides
// whether work proceeds -- a rate limiter's Allow, Wait or Reserve. They ride
// the same stream as call sites, stamped site_kind: "protective_site", one
// packet per call.
//
// Retrieval only. The packet is the call and the function around it, because
// the branch that refuses the work (the 429, the dropped job) is in the
// caller, not in the limiter. Whether the limit is calibrated, and whether
// its refusal can become the outage, is judged downstream; no spec judges
// these packets and rvl reports them as they are.
//
// TEST FILES ARE READ FOR THESE. goindex loads without tests, so no call site
// comes from a _test.go file. A protective site in a test is still a fact
// (its path gives its scope), so the test files of the packages that can
// reach a listed type are loaded a second time, with tests. A module that
// imports no listed package pays for no second load.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// siteKindProtective mirrors rvl_core::SITE_KIND_PROTECTIVE.
const siteKindProtective = "protective_site"

// protectiveCall is one row of the protective_calls table in
// extractor_corpus.json: a method of a type whose call decides whether work
// proceeds, and the mechanism the type is.
type protectiveCall struct {
	Package   string `json:"package"`
	Type      string `json:"type"`
	Method    string `json:"method"`
	Mechanism string `json:"mechanism"`
}

// protectiveCallFor matches a callee on its declared receiver type, so a
// limiter embedded in a struct of the repository is still the limiter's
// method, and a local type with an Allow method is not.
func protectiveCallFor(callee *types.Func) (protectiveCall, bool) {
	if callee == nil {
		return protectiveCall{}, false
	}
	sig, ok := callee.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return protectiveCall{}, false
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return protectiveCall{}, false
	}
	for _, k := range extractor.ProtectiveCalls {
		if named.Obj().Pkg().Path() == k.Package && named.Obj().Name() == k.Type && callee.Name() == k.Method {
			return k, true
		}
	}
	return protectiveCall{}, false
}

// collectProtective returns the protective sites in pkgs: of the non-test
// files, or with tests set, of the _test.go files only. Vendored code is left
// out.
func collectProtective(pkgs []*packages.Package, src *srcIndex, root, snapshot string, tests bool) []RetrievedSite {
	var out []RetrievedSite
	// A file reached through two package variants is read once.
	seen := map[string]bool{}
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			filename := p.Fset.Position(f.Pos()).Filename
			rel := relPath(root, filename)
			if seen[filename] || strings.HasSuffix(rel, "_test.go") != tests || strings.HasPrefix(rel, "vendor/") {
				continue
			}
			seen[filename] = true
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
					out = append(out, functionProtective(p, src, fd, rel, snapshot)...)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// functionProtective returns the protective sites in one function. The
// enclosing function is chosen as for a call site: the declaration, or the
// innermost literal around the call when the declaration is over the snippet
// budget.
func functionProtective(p *packages.Package, src *srcIndex, fd *ast.FuncDecl, rel, snapshot string) []RetrievedSite {
	info := p.TypesInfo
	var out []RetrievedSite
	var lits []*ast.FuncLit
	var stack []ast.Node
	ast.Inspect(fd.Body, func(x ast.Node) bool {
		if x == nil {
			if _, ok := stack[len(stack)-1].(*ast.FuncLit); ok {
				lits = lits[:len(lits)-1]
			}
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, x)
		if fl, ok := x.(*ast.FuncLit); ok {
			lits = append(lits, fl)
		}
		c, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		callee, _ := info.Uses[sel.Sel].(*types.Func)
		k, ok := protectiveCallFor(callee)
		if !ok {
			return true
		}
		var enclosing ast.Node = fd
		if len(lits) > 0 && src.span(p, fd) > maxSnippetBytes {
			enclosing = lits[len(lits)-1]
		}
		out = append(out, RetrievedSite{
			SiteKind:   siteKindProtective,
			Snapshot:   snapshot,
			File:       rel,
			Line:       p.Fset.Position(c.Pos()).Line,
			Symbol:     fd.Name.Name,
			Method:     k.Method,
			Receiver:   exprString(sel.X),
			ClientType: k.Package + "." + k.Type,
			CallSite:   src.text(p, c, c),
			Enclosing:  src.text(p, enclosing, enclosing),
			Callers:    []Snippet{},
			Callees:    []Snippet{},
			ConstArgs: append(constArgs(info, c),
				ConstArg{Name: "protective_mechanism", Value: k.Mechanism, How: "aggregate"}),
			Prov: Provenance{ClientTypeKnown: true},
		})
		return true
	})
	return out
}

// protectiveTestPatterns returns the package patterns, relative to
// moduleDir, whose test files can hold a protective site: a directory with a
// _test.go file whose package reaches a listed package, or whose test files
// import one. Nil when there is none, and then there is no second load.
func protectiveTestPatterns(moduleDir string, pkgs []*packages.Package) []string {
	listed := map[string]bool{}
	for _, k := range extractor.ProtectiveCalls {
		listed[k.Package] = true
	}
	memo := map[string]bool{}
	var reaches func(p *packages.Package) bool
	reaches = func(p *packages.Package) bool {
		if r, ok := memo[p.PkgPath]; ok {
			return r
		}
		memo[p.PkgPath] = false
		r := listed[p.PkgPath]
		for _, imp := range p.Imports {
			if r {
				break
			}
			r = reaches(imp)
		}
		memo[p.PkgPath] = r
		return r
	}
	reachDirs := map[string]bool{}
	for _, p := range pkgs {
		if len(p.GoFiles) > 0 && reaches(p) {
			reachDirs[filepath.Dir(p.GoFiles[0])] = true
		}
	}

	abs, err := filepath.Abs(moduleDir)
	if err != nil {
		return nil
	}
	want := map[string]bool{}
	_ = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != abs && (name == "vendor" || name == "testdata" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			// A nested module is not this module's package.
			if _, e := os.Stat(filepath.Join(path, "go.mod")); e == nil && path != abs {
				return filepath.SkipDir
			}
			return nil
		}
		dir := filepath.Dir(path)
		if !strings.HasSuffix(path, "_test.go") || want[dir] {
			return nil
		}
		if reachDirs[dir] || importsListed(path, listed) {
			want[dir] = true
		}
		return nil
	})
	var patterns []string
	for dir := range want {
		r, err := filepath.Rel(abs, dir)
		if err != nil {
			continue
		}
		patterns = append(patterns, "./"+filepath.ToSlash(r))
	}
	sort.Strings(patterns)
	return patterns
}

// importsListed reports whether the Go file at path imports a listed package.
func importsListed(path string, listed map[string]bool) bool {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return false
	}
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && listed[p] {
			return true
		}
	}
	return false
}

// loadProtectiveTests loads the packages protectiveTestPatterns names, with
// their tests. Nil, nil when there is nothing to load.
func loadProtectiveTests(moduleDir string, pkgs []*packages.Package) ([]*packages.Package, error) {
	patterns := protectiveTestPatterns(moduleDir, pkgs)
	if len(patterns) == 0 {
		return nil, nil
	}
	cfg := loadConfig(moduleDir)
	cfg.Tests = true
	return packages.Load(cfg, patterns...)
}
