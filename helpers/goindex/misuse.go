// Misuse-shape inventory: error-handling shapes that are wrong where they
// stand, emitted on the SAME packet stream as call sites, distinguished by
// site_kind: "misuse_shape".
//
// Go contributes discarded_error here: an error-typed call result assigned to
// the blank identifier (`_ = f.Close()`, `n, _ := strconv.Atoi(s)`). The
// retry, SQL, print and metric shapes are in misuse_shapes.go. The other
// error-handling and async classes of the lane do not exist in Go. It has no typed catch, so
// there is no overbroad one, and it has no async/await, so there is no
// blocking-in-async and no missing await. A swallowed panic is the
// recover_block fact in emission.go, not this.
//
// The retrieval/judgment split holds. A discard is often legitimate (Close on
// a file opened for reading), and which callees those are is spec knowledge
// (MisuseSpec, role "allowed"). Nothing here keeps a discard back.
//
// VOLUME CONTROL is the same as for emission points: packets are AGGREGATES,
// one per (enclosing function, class, identity), with the count in const_args
// (misuse_class / misuse_count, how: "aggregate").
//
// Out of scope on purpose: a call statement that ignores every result
// (`f.Close()`), and `_ = err` on a variable. The first has no discard to
// see without a list of functions whose error matters. The second is the
// compiler's "declared and not used" workaround far more often than a
// decision about an error.
package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// siteKindMisuse mirrors rvl_core::SITE_KIND_MISUSE.
const siteKindMisuse = "misuse_shape"

// misuseDynamicCallee is the identity of a call the type checker does not
// resolve to a declared function: a function value, a field of function type.
const misuseDynamicCallee = "func value"

var errorType = types.Universe.Lookup("error").Type()

type misuseAgg struct {
	site  RetrievedSite
	class string
	count int
}

// calleeIdentity names the function a call invokes: "<pkg path>.<Func>" for a
// package-level function, "<receiver type>.<Method>" for a method, with the
// pointer star dropped like every other client type. ok is false when the
// callee is not a declared function.
func calleeIdentity(info *types.Info, call *ast.CallExpr) (identity, name string, ok bool) {
	fun := ast.Unparen(call.Fun)
	// A generic instantiation: f[T](...).
	switch ix := fun.(type) {
	case *ast.IndexExpr:
		fun = ix.X
	case *ast.IndexListExpr:
		fun = ix.X
	}
	var callee *types.Func
	var recv ast.Expr
	switch f := fun.(type) {
	case *ast.Ident:
		callee, _ = info.Uses[f].(*types.Func)
	case *ast.SelectorExpr:
		callee, _ = info.Uses[f.Sel].(*types.Func)
		recv = f.X
	}
	if callee == nil || callee.Pkg() == nil {
		return misuseDynamicCallee, "", false
	}
	if sig, isSig := callee.Type().(*types.Signature); isSig && sig.Recv() != nil && recv != nil {
		if t := info.TypeOf(recv); t != nil {
			return strings.TrimPrefix(t.String(), "*") + "." + callee.Name(), callee.Name(), true
		}
	}
	return callee.Pkg().Path() + "." + callee.Name(), callee.Name(), true
}

// discardedErrorCalls returns the calls whose error result an assignment
// sends to the blank identifier, once per discarded error.
func discardedErrorCalls(info *types.Info, as *ast.AssignStmt) []*ast.CallExpr {
	blank := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "_"
	}
	isError := func(t types.Type) bool { return t != nil && types.Identical(t, errorType) }

	var out []*ast.CallExpr
	// One call on the right, its results spread over the left: `n, _ := f()`.
	if len(as.Rhs) == 1 {
		call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return nil
		}
		switch t := info.TypeOf(call).(type) {
		case *types.Tuple:
			for i, lhs := range as.Lhs {
				if i < t.Len() && blank(lhs) && isError(t.At(i).Type()) {
					out = append(out, call)
				}
			}
		default:
			if len(as.Lhs) == 1 && blank(as.Lhs[0]) && isError(t) {
				out = append(out, call)
			}
		}
		return out
	}
	// A parallel assignment: `_, _ = f(), g()`.
	for i, rhs := range as.Rhs {
		call, ok := ast.Unparen(rhs).(*ast.CallExpr)
		if ok && i < len(as.Lhs) && blank(as.Lhs[i]) && isError(info.TypeOf(call)) {
			out = append(out, call)
		}
	}
	return out
}

// shapeNote records one occurrence of a shape: its class, the identity it
// was seen on, the method name for the packet, whether the identity is
// type-resolved, and the node the packet sits on.
type shapeNote func(class, identity, method string, known bool, at ast.Node)

// collectMisuse walks every scanned function and returns the misuse
// aggregates. Paths are repo-relative, and test and vendored files are left
// out, as in collectEmissions.
func collectMisuse(pkgs []*packages.Package, src *srcIndex, root, snapshot string) []RetrievedSite {
	var out []RetrievedSite
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		info := p.TypesInfo
		for _, f := range p.Syntax {
			rel := relPath(root, p.Fset.Position(f.Pos()).Filename)
			if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "vendor/") {
				continue
			}
			// One aggregate per (function, class, identity). Package-level
			// declarations share the empty function name.
			aggs := map[[3]string]*misuseAgg{}
			noteIn := func(symbol string) shapeNote {
				return func(class, identity, method string, known bool, at ast.Node) {
					key := [3]string{symbol, class, identity}
					agg, seen := aggs[key]
					if !seen {
						agg = &misuseAgg{class: class, site: RetrievedSite{
							SiteKind:   siteKindMisuse,
							Snapshot:   snapshot,
							File:       rel,
							Line:       p.Fset.Position(at.Pos()).Line,
							Symbol:     symbol,
							Method:     method,
							ClientType: identity,
							CallSite:   src.text(p, at, at),
							Callers:    []Snippet{},
							Callees:    []Snippet{},
							Prov:       Provenance{ClientTypeKnown: known},
						}}
						aggs[key] = agg
					}
					agg.count++
				}
			}
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					note := noteIn(d.Name.Name)
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if as, ok := n.(*ast.AssignStmt); ok {
							for _, call := range discardedErrorCalls(info, as) {
								identity, name, known := calleeIdentity(info, call)
								note("discarded_error", identity, name, known, as)
							}
						}
						return true
					})
					collectLocalShapes(info, d.Body, note)
				case *ast.GenDecl:
					// A metric is often registered in a package-level var.
					collectLocalShapes(info, d, noteIn(""))
				}
			}
			for _, a := range aggs {
				a.site.ConstArgs = []ConstArg{
					{Index: 0, Name: "misuse_class", Value: a.class, How: "aggregate"},
					{Index: 0, Name: "misuse_count", Value: fmt.Sprint(a.count), How: "aggregate"},
				}
				out = append(out, a.site)
			}
		}
	}
	// Deterministic order, for the same reason as collectEmissions.
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].ClientType != out[j].ClientType {
			return out[i].ClientType < out[j].ClientType
		}
		return out[i].ConstArgs[0].Value < out[j].ConstArgs[0].Value
	})
	return out
}
