// Unsized-construction inventory: an object that takes a bound was built
// here -- a connection pool, a cache, a read of a whole body -- emitted on
// the SAME packet stream as call sites, distinguished by
// site_kind: "unsized_construction". One packet per construction.
//
// The retrieval/judgment split holds. Nothing here decides that a pool is
// unbounded. The packet lists what was OBSERVED in the constructing function:
// the constructor's arguments, the methods called on the constructed value,
// the calls a read's argument passes through. Which of those names is a
// bound, and which values of it mean "no limit", is spec knowledge
// (ConstructionBoundSpec downstream).
//
// A VALUE IS REPORTED ONLY WHEN THE TYPE CHECKER FOLDS IT. An argument that
// is not a constant (db.SetMaxOpenConns(cfg.Max)) is reported with
// how: "name": its source text, never a resolved value. Downstream credits a
// name as a bound and compares nothing against it.
//
// A constructed value that LEAVES the function (returned, stored, passed on,
// or never named) can be bounded where this function cannot see. Such a
// packet carries bound_escapes, plus every method the module calls on the
// same type anywhere, labeled how: "type". That label is evidence to abstain
// on. It never reads as an in-scope bound.
//
// make(chan T) is deliberately NOT here. An unbuffered Go channel is a
// rendezvous: the sender blocks until a receiver is ready, which is the
// opposite of an unbounded queue.
package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// siteKindUnsized mirrors rvl_core::SITE_KIND_UNSIZED.
const siteKindUnsized = "unsized_construction"

// boundClassRead is the class whose "construction" is a call that reads a
// whole body: its observations are the calls the argument passes through,
// not setters on a result.
const boundClassRead = "read"

// maxPassThroughDepth caps how far a read's argument is followed through
// local assignments and nested calls.
const maxPassThroughDepth = 4

var boundClasses = map[string]bool{"pool": true, "queue": true, "cache": true, boundClassRead: true}

// boundConstructor is one row of the bound_constructors table in
// extractor_corpus.json: a package-level function whose call is inventoried.
// Like ioMethods it selects WHICH sites to surface, never what they mean.
type boundConstructor struct {
	Class   string `json:"class"`
	Package string `json:"package"`
	Func    string `json:"func"`
}

func boundConstructorFor(callee *types.Func) (boundConstructor, bool) {
	if callee == nil || callee.Pkg() == nil {
		return boundConstructor{}, false
	}
	if sig, ok := callee.Type().(*types.Signature); !ok || sig.Recv() != nil {
		return boundConstructor{}, false
	}
	for _, b := range extractor.BoundConstructors {
		if callee.Pkg().Path() == b.Package && callee.Name() == b.Func {
			return b, true
		}
	}
	return boundConstructor{}, false
}

// unsizedSite is one construction found in a function, before the type-level
// observations (which need the whole module) are attached.
type unsizedSite struct {
	site     RetrievedSite
	escapes  string // "" when the value stays in the constructing function
	typeName string
}

// collectUnsized walks every scanned function and returns the
// unsized-construction packets.
func collectUnsized(pkgs []*packages.Package, src *srcIndex, root, snapshot string) []RetrievedSite {
	var found []unsizedSite
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || !scannedFile(p, root, fd) {
					continue
				}
				found = append(found, functionUnsized(p, src, fd, relPath(root, p.Fset.Position(fd.Pos()).Filename), snapshot)...)
			}
		}
	}

	// The type-level pass runs only when a value escapes, and only for the
	// types that did.
	wanted := map[string]bool{}
	for _, u := range found {
		if u.escapes != "" {
			wanted[u.typeName] = true
		}
	}
	methods := methodsCalledOn(pkgs, root, wanted)

	out := make([]RetrievedSite, 0, len(found))
	for _, u := range found {
		if u.escapes != "" {
			u.site.ConstArgs = append(u.site.ConstArgs,
				ConstArg{Name: "bound_escapes", Value: u.escapes, How: "aggregate"})
			for _, m := range methods[u.typeName] {
				u.site.ConstArgs = append(u.site.ConstArgs, ConstArg{Name: m, How: "type"})
			}
		}
		out = append(out, u.site)
	}
	return out
}

// scannedFile applies the emission inventory's file filter: no tests, no
// vendored code.
func scannedFile(p *packages.Package, root string, n ast.Node) bool {
	rel := relPath(root, p.Fset.Position(n.Pos()).Filename)
	return !strings.HasSuffix(rel, "_test.go") && !strings.HasPrefix(rel, "vendor/")
}

// methodsCalledOn returns, for each wanted type, the sorted names of the
// methods the module calls on a value of that type anywhere in scanned code.
func methodsCalledOn(pkgs []*packages.Package, root string, wanted map[string]bool) map[string][]string {
	out := map[string][]string{}
	if len(wanted) == 0 {
		return out
	}
	seen := map[string]map[string]bool{}
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			if !scannedFile(p, root, f) {
				continue
			}
			ast.Inspect(f, func(x ast.Node) bool {
				call, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if s := p.TypesInfo.Selections[sel]; s == nil || s.Kind() != types.MethodVal {
					return true
				}
				t := typeKey(p.TypesInfo.TypeOf(sel.X))
				if !wanted[t] {
					return true
				}
				if seen[t] == nil {
					seen[t] = map[string]bool{}
				}
				seen[t][sel.Sel.Name] = true
				return true
			})
		}
	}
	for t, names := range seen {
		for n := range names {
			out[t] = append(out[t], n)
		}
		sort.Strings(out[t])
	}
	return out
}

// valueObservation reports one argument as an observation named `name`: its
// folded value when the type checker has one, its source text as a NAME
// when it does not.
func valueObservation(p *packages.Package, src *srcIndex, name string, index int, arg ast.Expr) ConstArg {
	if tv, ok := p.TypesInfo.Types[arg]; ok && tv.Value != nil {
		how := "named_constant"
		if _, isLit := arg.(*ast.BasicLit); isLit {
			how = "literal"
		}
		return ConstArg{Index: index, Name: name, Value: tv.Value.ExactString(), How: how}
	}
	return ConstArg{Index: index, Name: name, Value: src.text(p, arg, arg), How: "name"}
}

func functionUnsized(p *packages.Package, src *srcIndex, fd *ast.FuncDecl, rel, snapshot string) []unsizedSite {
	info := p.TypesInfo

	// What each call's first result is assigned to, when it is assigned.
	targets := map[*ast.CallExpr]ast.Expr{}
	ast.Inspect(fd.Body, func(x ast.Node) bool {
		switch st := x.(type) {
		case *ast.AssignStmt:
			if len(st.Rhs) == 1 && len(st.Lhs) >= 1 {
				if c, ok := ast.Unparen(st.Rhs[0]).(*ast.CallExpr); ok {
					targets[c] = st.Lhs[0]
				}
			}
		case *ast.ValueSpec:
			if len(st.Values) == 1 && len(st.Names) >= 1 {
				if c, ok := ast.Unparen(st.Values[0]).(*ast.CallExpr); ok {
					targets[c] = st.Names[0]
				}
			}
		}
		return true
	})

	var out []unsizedSite
	ast.Inspect(fd.Body, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := calleeFunc(info, call)
		entry, ok := boundConstructorFor(callee)
		if !ok {
			return true
		}
		u := unsizedSite{site: RetrievedSite{
			SiteKind: siteKindUnsized,
			Snapshot: snapshot,
			File:     rel,
			Line:     p.Fset.Position(call.Pos()).Line,
			Symbol:   fd.Name.Name,
			Method:   callee.Name(),
			CallSite: src.text(p, call, call),
			Callers:  []Snippet{},
			Callees:  []Snippet{},
			ConstArgs: []ConstArg{
				{Name: "bound_class", Value: entry.Class, How: "aggregate"},
			},
			Prov: Provenance{ClientTypeKnown: true},
		}}
		if entry.Class == boundClassRead {
			u.typeName = entry.Package + "." + entry.Func
			if len(call.Args) > 0 {
				for _, name := range passesThrough(info, fd.Body, call.Args[0]) {
					u.site.ConstArgs = append(u.site.ConstArgs, ConstArg{Name: name, How: "call"})
				}
			}
		} else {
			sig := callee.Type().(*types.Signature)
			if sig.Results().Len() == 0 {
				return true
			}
			u.typeName = typeKey(sig.Results().At(0).Type())
			for i, a := range call.Args {
				u.site.ConstArgs = append(u.site.ConstArgs,
					valueObservation(p, src, fmt.Sprintf("arg%d", i), i, a))
			}
			target, named := targets[call]
			var setters []ConstArg
			setters, u.escapes = settersInScope(p, src, fd.Body, target, named)
			u.site.ConstArgs = append(u.site.ConstArgs, setters...)
		}
		u.site.ClientType = u.typeName
		out = append(out, u)
		return true
	})
	return out
}

// settersInScope returns the methods called in `body` on the value assigned
// to `target`, and how the value leaves the function ("" when it does not).
//
// A local variable is followed by object identity, and escapes when it is
// used as anything but the receiver of a method call. Any other target (a
// field, a package variable, no name at all) is visible outside the function
// by construction; its setters are matched on the target's expression text.
func settersInScope(p *packages.Package, src *srcIndex, body *ast.BlockStmt, target ast.Expr, named bool) ([]ConstArg, string) {
	info := p.TypesInfo
	if !named {
		return nil, "unnamed"
	}
	var local *types.Var
	escapes := "stored"
	if id, ok := target.(*ast.Ident); ok {
		v, _ := info.ObjectOf(id).(*types.Var)
		if v == nil {
			// The blank identifier: the value is dropped where it is built.
			return nil, ""
		}
		local = v
		if v.Parent() != v.Pkg().Scope() {
			escapes = ""
		}
	}
	targetText := types.ExprString(target)
	isTarget := func(x ast.Expr) bool {
		if id, ok := x.(*ast.Ident); ok && local != nil {
			return info.ObjectOf(id) == local
		}
		return local == nil && types.ExprString(x) == targetText
	}

	var setters []ConstArg
	seen := map[string]bool{}
	receivers := map[*ast.Ident]bool{}
	ast.Inspect(body, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isTarget(sel.X) {
			return true
		}
		if s := info.Selections[sel]; s == nil || s.Kind() != types.MethodVal {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			receivers[id] = true
		}
		obs := ConstArg{Name: sel.Sel.Name, How: "name"}
		if len(call.Args) > 0 {
			obs = valueObservation(p, src, sel.Sel.Name, 0, call.Args[0])
		}
		key := obs.Name + "\x00" + obs.Value + "\x00" + obs.How
		if !seen[key] {
			seen[key] = true
			setters = append(setters, obs)
		}
		return true
	})

	if local != nil && escapes == "" {
		ast.Inspect(body, func(x ast.Node) bool {
			id, ok := x.(*ast.Ident)
			if ok && id != target && info.Uses[id] == local && !receivers[id] {
				escapes = "leaves"
			}
			return escapes == ""
		})
	}
	return setters, escapes
}

// passesThrough names every call the expression's value passes through
// inside `body`: calls written inline around it, and calls assigned to the
// local or the selector expression it is read from. Flow-insensitive, one
// function, capped in depth. A callee the type checker does not resolve is
// skipped.
func passesThrough(info *types.Info, body *ast.BlockStmt, x ast.Expr) []string {
	names := map[string]bool{}
	visited := map[ast.Node]bool{}
	var follow func(x ast.Expr, depth int)
	follow = func(x ast.Expr, depth int) {
		x = ast.Unparen(x)
		if depth > maxPassThroughDepth || visited[x] {
			return
		}
		visited[x] = true
		switch e := x.(type) {
		case *ast.CallExpr:
			if name := qualifiedCallee(info, e); name != "" {
				names[name] = true
			}
			for _, a := range e.Args {
				follow(a, depth+1)
			}
		case *ast.Ident, *ast.SelectorExpr:
			var obj types.Object
			if id, ok := e.(*ast.Ident); ok {
				obj = info.ObjectOf(id)
			}
			text := types.ExprString(x)
			ast.Inspect(body, func(n ast.Node) bool {
				st, ok := n.(*ast.AssignStmt)
				if !ok || visited[st] {
					return true
				}
				for i, lhs := range st.Lhs {
					same := types.ExprString(lhs) == text
					if id, isID := lhs.(*ast.Ident); isID && obj != nil {
						same = info.ObjectOf(id) == obj
					}
					if !same {
						continue
					}
					visited[st] = true
					rhs := st.Rhs[0]
					if len(st.Rhs) == len(st.Lhs) {
						rhs = st.Rhs[i]
					}
					follow(rhs, depth+1)
				}
				return true
			})
		}
	}
	follow(x, 0)
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// qualifiedCallee is "<import path>.<Func>" for a package-level function and
// "<receiver type>.<Method>" for a method, or "" when the callee does not
// resolve to a function.
func qualifiedCallee(info *types.Info, call *ast.CallExpr) string {
	callee := calleeFunc(info, call)
	if callee == nil || callee.Pkg() == nil {
		return ""
	}
	if sig, ok := callee.Type().(*types.Signature); ok && sig.Recv() != nil {
		return typeKey(sig.Recv().Type()) + "." + callee.Name()
	}
	return callee.Pkg().Path() + "." + callee.Name()
}
