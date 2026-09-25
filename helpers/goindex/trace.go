package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Receiver tracing: which values reach the receiver of a call.
//
// A call is bounded by the client it is made on, not by the clients the
// repository happens to construct. Attaching every construction of the type
// let one bounded net/http.Client vouch for every unbounded one, so the site
// now carries the values that reach its own receiver whenever the type checker
// can say which those are: a local variable, a package variable or a struct
// field, followed through plain copies and one hop into an in-repo
// constructor. Everything else (parameters, call results, fields never set in
// this repository) is left untraced, and the caller falls back to candidates
// of the type, marked as such.

// traceMaxAlias bounds how many plain copies (d := c) are followed.
const traceMaxAlias = 3

// reachingValue is one value that reaches an object.
type reachingValue struct {
	snip  Snippet
	alias types.Object // a plain copy of another object: follow it
	ctor  string       // the result of this in-repo function: its body is the construction
}

type reachIndex struct {
	values map[types.Object][]reachingValue
	repo   map[string]bool // package paths loaded from this repository
}

func newReachIndex(pkgs []*packages.Package) *reachIndex {
	ix := &reachIndex{values: map[types.Object][]reachingValue{}, repo: map[string]bool{}}
	for _, p := range pkgs {
		ix.repo[p.PkgPath] = true
	}
	return ix
}

func typeKey(t types.Type) string {
	if t == nil {
		return ""
	}
	return strings.TrimPrefix(t.String(), "*")
}

// varOf resolves an expression naming a variable (a local, a package variable
// or a struct field) to its object, through parentheses, & and *.
func varOf(info *types.Info, x ast.Expr) *types.Var {
	switch e := x.(type) {
	case *ast.ParenExpr:
		return varOf(info, e.X)
	case *ast.StarExpr:
		return varOf(info, e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return varOf(info, e.X)
		}
	case *ast.Ident:
		if e.Name == "_" {
			return nil
		}
		v, _ := info.ObjectOf(e).(*types.Var)
		return v
	case *ast.SelectorExpr:
		v, _ := info.ObjectOf(e.Sel).(*types.Var)
		return v
	}
	return nil
}

// collect records every value that reaches a variable in one file.
func (ix *reachIndex) collect(p *packages.Package, f *ast.File, src *srcIndex,
	rel func(*packages.Package, ast.Node) (string, int)) {
	info := p.TypesInfo
	add := func(to *types.Var, v reachingValue) {
		if to != nil {
			ix.values[to] = append(ix.values[to], v)
		}
	}
	// valueOf describes rhs, the tuple element idx of it when it yields several.
	valueOf := func(rhs ast.Expr, idx int) reachingValue {
		t := info.TypeOf(rhs)
		if tup, ok := t.(*types.Tuple); ok && idx < tup.Len() {
			t = tup.At(idx).Type()
		}
		file, line := rel(p, rhs)
		v := reachingValue{snip: Snippet{File: file, Line: line, Symbol: typeKey(t),
			Source: src.text(p, rhs, rhs)}}
		switch e := ast.Unparen(rhs).(type) {
		case *ast.Ident, *ast.SelectorExpr:
			if o := varOf(info, e); o != nil {
				v.alias = o
			}
		case *ast.CallExpr:
			var fn *types.Func
			switch fun := ast.Unparen(e.Fun).(type) {
			case *ast.Ident:
				fn, _ = info.Uses[fun].(*types.Func)
			case *ast.SelectorExpr:
				fn, _ = info.Uses[fun.Sel].(*types.Func)
			}
			if fn != nil && fn.Pkg() != nil && ix.repo[fn.Pkg().Path()] {
				v.ctor = fn.FullName()
			}
		}
		return v
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				var rhs ast.Expr
				idx := 0
				switch {
				case len(s.Rhs) == len(s.Lhs):
					rhs = s.Rhs[i]
				case len(s.Rhs) == 1:
					rhs, idx = s.Rhs[0], i
				default:
					continue
				}
				add(varOf(info, lhs), valueOf(rhs, idx))
				// c.Timeout = x sets a field of c after construction: that
				// statement is part of how c was built.
				if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
					if owner := varOf(info, sel.X); owner != nil {
						file, line := rel(p, s)
						add(owner, reachingValue{snip: Snippet{File: file, Line: line,
							Symbol: typeKey(info.TypeOf(sel.X)), Source: src.text(p, s, s)}})
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range s.Names {
				v, _ := info.Defs[name].(*types.Var)
				switch {
				case len(s.Values) == 0:
					// var c http.Client: the zero value is the construction.
					file, line := rel(p, s)
					add(v, reachingValue{snip: Snippet{File: file, Line: line,
						Symbol: typeKey(info.TypeOf(name)), Source: src.text(p, s, s)}})
				case len(s.Values) == len(s.Names):
					add(v, valueOf(s.Values[i], 0))
				case len(s.Values) == 1:
					add(v, valueOf(s.Values[0], i))
				}
			}
		case *ast.CompositeLit:
			for _, el := range s.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if fv, ok := info.ObjectOf(key).(*types.Var); ok && fv.IsField() {
					add(fv, valueOf(kv.Value, 0))
				}
			}
		}
		return true
	})
}

// trace returns the constructions that reach v, and whether v could be traced
// at all. A package variable declared outside this repository is the
// library's own value: traced, with no construction here to read.
func (ix *reachIndex) trace(v *types.Var, funcs map[string]*retFunc, src *srcIndex, depth int) ([]Snippet, bool) {
	if v == nil || v.Pkg() == nil {
		return nil, false
	}
	vals := ix.values[v]
	if len(vals) == 0 {
		external := !ix.repo[v.Pkg().Path()] && !v.IsField() && v.Parent() == v.Pkg().Scope()
		return nil, external
	}
	var out []Snippet
	for _, rv := range vals {
		switch {
		case rv.alias != nil:
			if depth >= traceMaxAlias {
				return nil, false
			}
			a, _ := rv.alias.(*types.Var)
			got, ok := ix.trace(a, funcs, src, depth+1)
			if !ok {
				return nil, false
			}
			out = append(out, got...)
		case rv.ctor != "" && funcs[rv.ctor] != nil:
			rf := funcs[rv.ctor]
			out = append(out, Snippet{File: rf.file, Line: rf.line, Symbol: rv.snip.Symbol,
				Source: src.text(rf.pkg, rf.decl, rf.decl)})
		default:
			out = append(out, rv.snip)
		}
	}
	return out, true
}
