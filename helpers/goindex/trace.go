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
// constructor. A parameter is followed to the arguments its callers pass,
// when every call of the function is visible: see bindParams. Everything else
// (a parameter of a function with unseen callers, fields never set in this
// repository) is left untraced, and the caller falls back to candidates of the
// type, marked as such. A value that is the result of a call this repository
// cannot read is a third case, traceOpaque: the client is known, and its
// construction is somewhere the retriever cannot look.

// traceMaxAlias bounds how many plain copies (d := c) are followed.
const traceMaxAlias = 3

// reachingValue is one value that reaches an object.
type reachingValue struct {
	snip   Snippet
	alias  types.Object // a plain copy of another object: follow it
	ctor   string       // the result of this in-repo function: its body is the construction
	opaque bool         // the result of a call whose construction is not in this repository
}

// traceStatus says what a trace found.
type traceStatus int

const (
	// traceNone: the values that reach the object could not be enumerated.
	traceNone traceStatus = iota
	// traceOK: the constructions returned are the values that reach it.
	traceOK
	// traceOpaque: a value that reaches it was built outside this repository
	// (the result of a dependency's function, or of a call through a function
	// value), so there is no construction here to read.
	traceOpaque
)

// indirectCall is a call made through a function-typed variable.
type indirectCall struct {
	args []reachingValue
	ok   bool // the arguments map one to one onto parameters
}

type reachIndex struct {
	values map[types.Object][]reachingValue
	repo   map[string]bool // package paths loaded from this repository

	// Parameter binding (bindParams). paramOwner maps a parameter to the
	// function declaring it; a parameter is traced only while every call of
	// that function is visible, which `open` records the exceptions to.
	paramOwner map[*types.Var]*types.Func
	open       map[*types.Func]bool
	flows      map[*types.Var][]*types.Func // parameter <- function passed as that argument
	passes     map[*types.Var][]*types.Var  // parameter <- function-typed variable passed on
	leaked     map[*types.Var]bool          // function-typed variable used other than by calling or passing it
	indirect   map[*types.Var][]indirectCall
	ifaceNames map[string]bool // method names called through an interface
}

func newReachIndex(pkgs []*packages.Package) *reachIndex {
	ix := &reachIndex{values: map[types.Object][]reachingValue{}, repo: map[string]bool{},
		paramOwner: map[*types.Var]*types.Func{}, open: map[*types.Func]bool{},
		flows: map[*types.Var][]*types.Func{}, passes: map[*types.Var][]*types.Var{},
		leaked: map[*types.Var]bool{}, indirect: map[*types.Var][]indirectCall{},
		ifaceNames: map[string]bool{}}
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
			fn := calleeFunc(info, e)
			switch {
			case fn != nil && fn.Pkg() != nil && ix.repo[fn.Pkg().Path()]:
				v.ctor = fn.FullName()
			case fn != nil:
				// A dependency's constructor of its OWN type is called with
				// the options that configure it, and the call is the
				// construction (redis.NewClient(&redis.Options{...})). One
				// that returns another package's type built that value where
				// this repository cannot read it.
				v.opaque = foreignResult(t, fn)
			default:
				// Neither a conversion nor a builtin: a call through a
				// function value, whose body is not known here.
				tv := info.Types[e.Fun]
				v.opaque = !tv.IsType() && !tv.IsBuiltin()
			}
		}
		return v
	}
	accounted := map[*ast.Ident]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.FuncDecl:
			if fn, ok := info.Defs[s.Name].(*types.Func); ok {
				params := fn.Signature().Params()
				for i := 0; i < params.Len(); i++ {
					ix.paramOwner[params.At(i)] = fn
				}
			}
		case *ast.CallExpr:
			ix.bindParams(info, s, valueOf, accounted)
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
	// Every other mention of a function, or of a function-typed variable, is
	// a place it can be called from that the binding above did not see.
	ast.Inspect(f, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || accounted[id] {
			return true
		}
		switch o := info.Uses[id].(type) {
		case *types.Func:
			ix.open[o.Origin()] = true
		case *types.Var:
			if _, isFunc := o.Type().Underlying().(*types.Signature); isFunc {
				ix.leaked[o] = true
			}
		}
		return true
	})
}

// calleeFunc resolves the declared function or method a call invokes, or nil
// when the call goes through a value, a conversion or a builtin.
func calleeFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	if id := calleeIdent(call); id != nil {
		fn, _ := info.Uses[id].(*types.Func)
		return fn
	}
	return nil
}

func calleeIdent(call *ast.CallExpr) *ast.Ident { return nameIdent(call.Fun) }

// nameIdent is the identifier an expression names something by: x, or the
// Sel of pkg.x and recv.x.
func nameIdent(x ast.Expr) *ast.Ident {
	switch fun := ast.Unparen(x).(type) {
	case *ast.Ident:
		return fun
	case *ast.SelectorExpr:
		return fun.Sel
	}
	return nil
}

// foreignResult reports whether t is a named type declared outside fn's
// package: fn hands back a value of someone else's type.
func foreignResult(t types.Type, fn *types.Func) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg() != fn.Pkg()
}

// bindParams records what one call passes: each argument reaches the
// parameter it is bound to. A parameter is then traced like any other
// variable, through the values every call gives it.
//
// The function itself can travel too. `p.asyncSearch(keyword, p.doSearch)`
// hands doSearch to a function-typed parameter, and the call that passes a
// client is `search(p.client, keyword)` inside asyncSearch. Those are followed
// while the function value only ever moves as a direct argument to an in-repo
// function and is only ever called: finish resolves them once every file has
// been read.
func (ix *reachIndex) bindParams(info *types.Info, call *ast.CallExpr,
	valueOf func(ast.Expr, int) reachingValue, accounted map[*ast.Ident]bool) {
	id := calleeIdent(call)
	if id == nil {
		return
	}
	// One argument that yields several values (f(g())) binds no parameter.
	spread := false
	if len(call.Args) == 1 {
		_, spread = info.TypeOf(call.Args[0]).(*types.Tuple)
	}
	switch callee := info.Uses[id].(type) {
	case *types.Func:
		accounted[id] = true
		fn := callee.Origin()
		sig := fn.Signature()
		if recv := sig.Recv(); recv != nil && types.IsInterface(recv.Type()) {
			ix.ifaceNames[fn.Name()] = true
			return
		}
		if fn.Pkg() == nil || !ix.repo[fn.Pkg().Path()] {
			return
		}
		if spread {
			ix.open[fn] = true
			return
		}
		for i, arg := range call.Args {
			if i >= sig.Params().Len() || (sig.Variadic() && i >= sig.Params().Len()-1) {
				break
			}
			param := sig.Params().At(i)
			ix.values[param] = append(ix.values[param], valueOf(arg, 0))
			argID := nameIdent(arg)
			if argID == nil {
				continue
			}
			switch a := info.Uses[argID].(type) {
			case *types.Func:
				accounted[argID] = true
				ix.flows[param] = append(ix.flows[param], a.Origin())
			case *types.Var:
				if _, isFunc := a.Type().Underlying().(*types.Signature); isFunc {
					accounted[argID] = true
					ix.passes[param] = append(ix.passes[param], a)
				}
			}
		}
	case *types.Var:
		if _, isFunc := callee.Type().Underlying().(*types.Signature); !isFunc {
			return
		}
		accounted[id] = true
		ic := indirectCall{ok: !spread}
		for _, arg := range call.Args {
			ic.args = append(ic.args, valueOf(arg, 0))
		}
		ix.indirect[callee] = append(ix.indirect[callee], ic)
	}
}

// finish resolves the calls made through function-typed parameters, once
// every file has been collected: which functions reach each such parameter,
// and so which arguments reach THEIR parameters.
func (ix *reachIndex) finish() {
	reach := map[*types.Var]map[*types.Func]bool{}
	add := func(v *types.Var, fn *types.Func) bool {
		if reach[v] == nil {
			reach[v] = map[*types.Func]bool{}
		}
		if reach[v][fn] {
			return false
		}
		reach[v][fn] = true
		return true
	}
	for v, fns := range ix.flows {
		for _, fn := range fns {
			add(v, fn)
		}
	}
	for changed := true; changed; {
		changed = false
		for to, froms := range ix.passes {
			for _, from := range froms {
				for fn := range reach[from] {
					changed = add(to, fn) || changed
				}
			}
		}
	}
	for v, fns := range reach {
		// Only a parameter's callers are enumerable. A function that reached
		// anything else, or a parameter that was then stored or returned, can
		// be called from somewhere this index did not look.
		if _, isParam := ix.paramOwner[v]; !isParam || ix.leaked[v] {
			for fn := range fns {
				ix.open[fn] = true
			}
			continue
		}
		for fn := range fns {
			sig := fn.Signature()
			for _, ic := range ix.indirect[v] {
				if !ic.ok || sig.Variadic() || len(ic.args) != sig.Params().Len() {
					ix.open[fn] = true
					continue
				}
				for i, arg := range ic.args {
					param := sig.Params().At(i)
					ix.values[param] = append(ix.values[param], arg)
				}
			}
		}
	}
}

// unseenCallers reports whether fn can be called from somewhere the index
// did not bind arguments at. The repository is read as a closed world, as it
// is for struct fields; within it, a function used as a value outside the
// shapes bindParams follows is open, and so is a method that an interface can
// dispatch to: an exported one can satisfy any interface, an unexported one
// only an interface that names it.
func (ix *reachIndex) unseenCallers(fn *types.Func) bool {
	if ix.open[fn] {
		return true
	}
	if fn.Signature().Recv() == nil {
		return false
	}
	return fn.Exported() || ix.ifaceNames[fn.Name()]
}

// trace returns the constructions that reach v, and whether v could be traced
// at all. A package variable declared outside this repository is the
// library's own value: traced, with no construction here to read.
func (ix *reachIndex) trace(v *types.Var, funcs map[string]*retFunc, src *srcIndex, depth int) ([]Snippet, traceStatus) {
	if v == nil || v.Pkg() == nil {
		return nil, traceNone
	}
	if owner, isParam := ix.paramOwner[v]; isParam && ix.unseenCallers(owner) {
		return nil, traceNone
	}
	vals := ix.values[v]
	if len(vals) == 0 {
		if !ix.repo[v.Pkg().Path()] && !v.IsField() && v.Parent() == v.Pkg().Scope() {
			return nil, traceOK
		}
		return nil, traceNone
	}
	var out []Snippet
	opaque := false
	for _, rv := range vals {
		switch {
		case rv.alias != nil:
			if depth >= traceMaxAlias {
				return nil, traceNone
			}
			a, _ := rv.alias.(*types.Var)
			got, st := ix.trace(a, funcs, src, depth+1)
			if st == traceNone {
				return nil, traceNone
			}
			opaque = opaque || st == traceOpaque
			out = append(out, got...)
		case rv.opaque:
			opaque = true
		case rv.ctor != "" && funcs[rv.ctor] != nil:
			rf := funcs[rv.ctor]
			out = append(out, Snippet{File: rf.file, Line: rf.line, Symbol: rv.snip.Symbol,
				Source: src.text(rf.pkg, rf.decl, rf.decl)})
		default:
			out = append(out, rv.snip)
		}
	}
	// One unreadable value leaves the whole receiver unreadable: the
	// constructions that were found cannot speak for it.
	if opaque {
		return nil, traceOpaque
	}
	return out, traceOK
}
