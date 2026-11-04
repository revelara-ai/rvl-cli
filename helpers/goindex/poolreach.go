package main

// Pool entry-point reachability: which entry points reach the pool a call
// site is made on, each classed as a handler or a job.
//
// One pool for a dependency can serve request paths and background work at
// once: the same *sql.DB reaches an RPC handler and a ticker loop. Nothing in
// the one-hop facts of a packet says so. This file computes the fact once per
// pool and attaches it to every call site whose receiver traces to that pool.
// docs/pool-reachability.md is the measurement it is built on.
//
// Three walks, each over the facts goindex already has.
//
//  1. The join, backward from the site. The receiver, or a variable it is
//     selected from (c.Ent in c.Ent.Alert.Query()), is followed through
//     copies, parameters, return flow and wrapping calls to the values that
//     reach it. A value of a type declared outside this repository is a
//     construction: that is the pool. A value of this repository's own type
//     only holds one, so its operands are followed instead.
//  2. Forward from the pool, the variables it flows into (reachIndex.forward),
//     and the functions that name one of them: the users.
//  3. Upward from the users, over the static calls, calls through this
//     repository's interfaces (to every method that implements one), and the
//     links a registration makes. The walk stops at an entry.
//
// An entry is a handler or a job, and Via says which rule classed it. Like
// jobFrameworks and serverEntryFrameworks these are retrieval facts, not a
// verdict: whether a pool shared by both needs separate bounds is for the
// judge.
//
//	handler  route          a function value passed to a route registration
//	         route_literal  a function literal passed to one
//	         grpc           a method of a type passed to Register*Server, named
//	                        in the interface that parameter takes
//	         http_handler   ServeHTTP of a type passed as an http.Handler, or a
//	                        function converted to http.HandlerFunc
//	job      go             a function started by a go statement
//	         go_literal     a function literal started by one
//	         job_framework  a function value passed to a jobFrameworks
//	                        registration (gocron.NewTask, cron.AddFunc)
//	         job_literal    a function literal passed to one
//	         ticker         a function that receives from a time.Ticker's
//	                        channel or from time.Tick in its own body, outside
//	                        any function literal: the loop, not the
//	                        constructor that stores the ticker

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// maxPoolEntriesEmitted bounds the sample entries per class in a fact.
var maxPoolEntriesEmitted = 3

const (
	entryHandler = "handler"
	entryJob     = "job"
)

// EntryRef names one entry point that reaches a pool.
type EntryRef struct {
	Symbol string `json:"symbol"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Via    string `json:"via"`
}

// PoolReach is the fact on a site: the pool its receiver traces to, and the
// entry points that reach that pool. File, Line and Symbol are the pool's
// construction and its type. The counts are the whole walk; the entry lists
// are a sample of maxPoolEntriesEmitted each, in file order.
type PoolReach struct {
	File           string     `json:"file"`
	Line           int        `json:"line"`
	Symbol         string     `json:"symbol"`
	Handlers       int        `json:"handlers"`
	Jobs           int        `json:"jobs"`
	HandlerEntries []EntryRef `json:"handler_entries"`
	JobEntries     []EntryRef `json:"job_entries"`
	// Users is how many functions name a variable the pool flows into.
	Users int `json:"users"`
	// UnclassifiedRoots counts the functions the upward walk reached that
	// nothing in this repository calls and no rule classes (main excepted):
	// an entry the walk could not see may sit behind one.
	UnclassifiedRoots int `json:"unclassified_roots"`
	// JoinOpen: a parameter on the way from the site to the pool belongs to
	// a function with callers this repository does not show, so another
	// value may reach the site as well.
	JoinOpen bool `json:"join_open,omitempty"`
}

// litContext is a function literal that a goroutine or a framework runs,
// rather than the function it is written in.
type litContext struct {
	via  string
	file string
	line int
}

type poolUse struct {
	fn  *retFunc
	ctx *litContext
}

type poolEdge struct {
	caller *retFunc
	ctx    *litContext // the call sits in such a literal
	goCall bool        // the call is a go statement's
}

// poolFacts is the walk for one pool, shared by every site on it.
type poolFacts struct {
	handlers, jobs []EntryRef
	users, roots   int
}

type poolIndex struct {
	pkgs  []*packages.Package
	ix    *reachIndex
	funcs map[string]*retFunc
	rel   func(*packages.Package, ast.Node) (string, int)

	built bool
	uses  map[*types.Var][]poolUse
	up    map[string][]poolEdge
	class map[string][]EntryRef
	memo  map[*types.Var]*poolFacts

	// Interface dispatch: in-repo named types by method name, and the
	// implementers found per interface.
	byMethod map[string][]*types.Named
	impls    map[*types.Named][]*types.Named
}

func newPoolIndex(pkgs []*packages.Package, ix *reachIndex, funcs map[string]*retFunc,
	rel func(*packages.Package, ast.Node) (string, int)) *poolIndex {
	return &poolIndex{pkgs: pkgs, ix: ix, funcs: funcs, rel: rel}
}

// at returns the pool facts for the call site whose receiver is recv, or nil
// when the receiver traces to no pool.
func (pi *poolIndex) at(info *types.Info, recv ast.Expr) []PoolReach {
	var origins []poolOrigin
	open := false
	for _, v := range receiverChain(info, recv) {
		j := &poolJoin{ix: pi.ix, state: map[*types.Var]int{}}
		if j.visit(v) {
			origins, open = j.origins, j.open
			break
		}
	}
	if len(origins) == 0 {
		return nil
	}
	if !pi.built {
		pi.build()
	}
	sort.Slice(origins, func(a, b int) bool {
		if origins[a].snip.File != origins[b].snip.File {
			return origins[a].snip.File < origins[b].snip.File
		}
		return origins[a].snip.Line < origins[b].snip.Line
	})
	var out []PoolReach
	seen := map[*types.Var]bool{}
	for _, o := range origins {
		if seen[o.seed] || len(out) >= maxCtorsEmitted {
			continue
		}
		seen[o.seed] = true
		f := pi.walk(o.seed)
		out = append(out, PoolReach{File: o.snip.File, Line: o.snip.Line, Symbol: o.snip.Symbol,
			Handlers: len(f.handlers), Jobs: len(f.jobs),
			HandlerEntries: sample(f.handlers), JobEntries: sample(f.jobs),
			Users: f.users, UnclassifiedRoots: f.roots, JoinOpen: open})
	}
	return out
}

// sample is the first maxPoolEntriesEmitted entries, [] rather than null
// when there are none.
func sample(es []EntryRef) []EntryRef {
	if len(es) > maxPoolEntriesEmitted {
		es = es[:maxPoolEntriesEmitted]
	}
	return append([]EntryRef{}, es...)
}

// receiverChain is the receiver and the variables it is selected or called
// from, outermost first: c.Ent.Alert.Query() gives Alert, Ent, c.
func receiverChain(info *types.Info, x ast.Expr) []*types.Var {
	var out []*types.Var
	seen := map[*types.Var]bool{}
	for x != nil {
		x = ast.Unparen(x)
		if v := varOf(info, x); v != nil && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
		switch e := x.(type) {
		case *ast.SelectorExpr:
			x = e.X
		case *ast.StarExpr:
			x = e.X
		case *ast.UnaryExpr:
			x = e.X
		case *ast.CallExpr:
			sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			if !ok {
				return out
			}
			x = sel.X
		default:
			return out
		}
	}
	return out
}

// poolOrigin is a construction of a pool: the variable it is first held in,
// which the forward walk starts from.
type poolOrigin struct {
	seed *types.Var
	snip Snippet
}

// poolJoin is one backward search from a site's receiver.
type poolJoin struct {
	ix      *reachIndex
	state   map[*types.Var]int // 1 in progress, 2 found a pool, 3 found none
	origins []poolOrigin
	open    bool
}

// visit reports whether any construction reaches u. A value that wraps
// variables is followed into them, and is a construction itself only when
// none of them leads to one: entsql.OpenDB(dialect, db) is db's pool.
func (j *poolJoin) visit(u *types.Var) bool {
	if u == nil {
		return false
	}
	if st, ok := j.state[u]; ok {
		return st == 2
	}
	j.state[u] = 1
	if owner, isParam := j.ix.paramOwner[u]; isParam && j.ix.unseenCallers(owner) {
		j.open = true
	}
	found := false
	vals := j.ix.values[u]
	if lv := j.ix.litValues[u]; len(lv) > 0 {
		vals = append(append([]reachingValue(nil), vals...), lv...)
	}
	for _, rv := range vals {
		if rv.alias != nil {
			a, _ := rv.alias.(*types.Var)
			found = j.visit(a) || found
			continue
		}
		sub := false
		for _, w := range rv.wraps {
			sub = j.visit(w) || sub
		}
		if rv.result != nil {
			sub = j.visit(rv.result) || sub
		}
		if !sub && rv.result == nil && !rv.fieldSet && j.ix.foreignClient(u.Type(), rv.zero) {
			j.origins = append(j.origins, poolOrigin{seed: u, snip: rv.snip})
			sub = true
		}
		found = found || sub
	}
	j.state[u] = 3
	if found {
		j.state[u] = 2
	}
	return found
}

// foreignClient reports whether a value of type t is a dependency's client:
// a named type declared outside this repository that can hold one. A zero
// pointer or interface is nil, not a construction.
func (ix *reachIndex) foreignClient(t types.Type, zero bool) bool {
	if !canHoldClient(t) {
		return false
	}
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Interface:
		if zero {
			return false
		}
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && !ix.repo[named.Obj().Pkg().Path()]
}

// walk computes the facts for the pool first held in seed, once.
func (pi *poolIndex) walk(seed *types.Var) *poolFacts {
	if f := pi.memo[seed]; f != nil {
		return f
	}
	// One entry per function or literal and class; a second rule that
	// classes it adds its Via (go,ticker).
	entries := map[string]*EntryRef{}
	add := func(e EntryRef) {
		k := viaClass[e.Via] + "|" + e.File + "|" + strconv.Itoa(e.Line) + "|" + e.Symbol
		if have := entries[k]; have == nil {
			entries[k] = &e
		} else if vias := strings.Split(have.Via, ","); !slices.Contains(vias, e.Via) {
			vias = append(vias, e.Via)
			sort.Strings(vias)
			have.Via = strings.Join(vias, ",")
		}
	}
	visited := map[string]bool{}
	var queue []*retFunc
	users := map[string]bool{}
	for v := range pi.ix.forward([]*types.Var{seed}) {
		for _, u := range pi.uses[v] {
			users[u.fn.id] = true
			if u.ctx != nil {
				add(EntryRef{Symbol: u.fn.name, File: u.ctx.file, Line: u.ctx.line, Via: u.ctx.via})
			} else if !visited[u.fn.id] {
				visited[u.fn.id] = true
				queue = append(queue, u.fn)
			}
		}
	}
	roots := 0
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, e := range pi.class[f.id] {
			add(e)
		}
		edges := pi.up[f.id]
		if len(edges) == 0 && len(pi.class[f.id]) == 0 && !(f.pkgName == "main" && f.name == "main") && f.name != "init" {
			roots++
		}
		for _, e := range edges {
			switch {
			case e.goCall:
				add(EntryRef{Symbol: f.name, File: f.file, Line: f.line, Via: "go"})
			case e.ctx != nil:
				add(EntryRef{Symbol: e.caller.name, File: e.ctx.file, Line: e.ctx.line, Via: e.ctx.via})
			case !visited[e.caller.id]:
				visited[e.caller.id] = true
				queue = append(queue, e.caller)
			}
		}
	}
	out := &poolFacts{users: len(users), roots: roots}
	for k, e := range entries {
		if strings.HasPrefix(k, entryHandler+"|") {
			out.handlers = append(out.handlers, *e)
		} else {
			out.jobs = append(out.jobs, *e)
		}
	}
	sortEntries(out.handlers)
	sortEntries(out.jobs)
	pi.memo[seed] = out
	return out
}

// viaClass is the class of each Via.
var viaClass = map[string]string{
	"route": entryHandler, "route_literal": entryHandler, "grpc": entryHandler, "http_handler": entryHandler,
	"go": entryJob, "go_literal": entryJob, "job_framework": entryJob, "job_literal": entryJob, "ticker": entryJob,
}

func sortEntries(es []EntryRef) {
	sort.Slice(es, func(a, b int) bool {
		if es[a].File != es[b].File {
			return es[a].File < es[b].File
		}
		if es[a].Line != es[b].Line {
			return es[a].Line < es[b].Line
		}
		return es[a].Symbol+es[a].Via < es[b].Symbol+es[b].Via
	})
}

// build reads every function once: the variables it names, the calls it
// makes, the literals a goroutine or a framework runs, and the functions a
// registration or a ticker classes as entries.
func (pi *poolIndex) build() {
	pi.built = true
	pi.uses = map[*types.Var][]poolUse{}
	pi.up = map[string][]poolEdge{}
	pi.class = map[string][]EntryRef{}
	pi.memo = map[*types.Var]*poolFacts{}
	pi.impls = map[*types.Named][]*types.Named{}
	pi.indexTypes()
	for _, p := range pi.pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				obj, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				if me := pi.funcs[obj.FullName()]; me != nil && me.decl == fd {
					pi.readFunc(p, me)
				}
			}
		}
	}
}

// readFunc records one function declaration.
func (pi *poolIndex) readFunc(p *packages.Package, me *retFunc) {
	info := p.TypesInfo
	lits := map[*ast.FuncLit]*litContext{}
	goCalls := map[*ast.CallExpr]bool{}
	mark := func(x ast.Expr, via string) {
		if fl, ok := ast.Unparen(x).(*ast.FuncLit); ok {
			file, line := pi.rel(p, fl)
			lits[fl] = &litContext{via: via, file: file, line: line}
		}
	}
	// classify records a function named as a value, x, as an entry.
	classify := func(x ast.Expr, via string) {
		id := nameIdent(x)
		if id == nil {
			return
		}
		if fn, ok := info.Uses[id].(*types.Func); ok {
			if rf := pi.funcs[fn.Origin().FullName()]; rf != nil {
				pi.class[rf.id] = append(pi.class[rf.id], EntryRef{Symbol: rf.name, File: rf.file, Line: rf.line, Via: via})
			}
		}
	}
	handlerValue := func(x ast.Expr) {
		x = ast.Unparen(x)
		if c, ok := x.(*ast.CallExpr); ok && len(c.Args) == 1 && isHTTPType(info.TypeOf(c.Fun), "HandlerFunc") &&
			info.Types[c.Fun].IsType() {
			classify(c.Args[0], "http_handler")
			mark(c.Args[0], "http_handler")
			return
		}
		pi.typeMethods(info.TypeOf(x), []string{"ServeHTTP"}, "http_handler")
	}
	ast.Inspect(me.decl.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.GoStmt:
			if _, ok := ast.Unparen(s.Call.Fun).(*ast.FuncLit); ok {
				mark(s.Call.Fun, "go_literal")
			} else {
				goCalls[s.Call] = true
			}
		case *ast.CompositeLit:
			if !isHTTPType(info.TypeOf(s), "Server") {
				return true
			}
			for _, el := range s.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Handler" {
						handlerValue(kv.Value)
					}
				}
			}
		case *ast.CallExpr:
			callee := calleeFunc(info, s)
			if callee == nil {
				return true
			}
			_, isServer := serverEntryPkgFuncs[callee.FullName()]
			if sel, ok := ast.Unparen(s.Fun).(*ast.SelectorExpr); ok {
				_, isServer = serverEntryClientType(info, sel, callee)
			}
			job := jobFrameworkType(callee)
			switch {
			case isServer:
				for _, a := range s.Args {
					classify(a, "route")
					mark(a, "route_literal")
				}
			case job == "time.Ticker":
				// A ticker classes the loop that receives from it: isTick.
			case job != "":
				for _, a := range s.Args {
					classify(a, "job_framework")
					mark(a, "job_literal")
				}
			}
			sig := callee.Signature()
			if strings.HasPrefix(callee.Name(), "Register") && strings.HasSuffix(callee.Name(), "Server") {
				for i, a := range s.Args {
					if i < sig.Params().Len() {
						if it, ok := sig.Params().At(i).Type().Underlying().(*types.Interface); ok && it.NumMethods() > 0 {
							var names []string
							for m := 0; m < it.NumMethods(); m++ {
								names = append(names, it.Method(m).Name())
							}
							pi.typeMethods(info.TypeOf(a), names, "grpc")
						}
					}
				}
			}
			for i, a := range s.Args {
				if i < sig.Params().Len() && !(sig.Variadic() && i >= sig.Params().Len()-1) {
					pt := sig.Params().At(i).Type()
					if isHTTPType(pt, "Handler") || isHTTPType(pt, "HandlerFunc") {
						handlerValue(a)
						mark(a, "http_handler")
					}
				}
			}
		}
		return true
	})

	// The second pass knows every literal's context: the innermost one
	// that has one holds the node.
	var stack []*litContext
	var nodes []ast.Node
	seenUse := map[poolUse]map[*types.Var]bool{}
	ticks := false
	ast.Inspect(me.decl.Body, func(n ast.Node) bool {
		if n == nil {
			if _, ok := nodes[len(nodes)-1].(*ast.FuncLit); ok {
				stack = stack[:len(stack)-1]
			}
			nodes = nodes[:len(nodes)-1]
			return true
		}
		nodes = append(nodes, n)
		var ctx *litContext
		if len(stack) > 0 {
			ctx = stack[len(stack)-1]
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			if c := lits[x]; c != nil {
				ctx = c
			}
			stack = append(stack, ctx)
		case *ast.Ident:
			if v, ok := info.Uses[x].(*types.Var); ok {
				key := poolUse{fn: me, ctx: ctx}
				if seenUse[key] == nil {
					seenUse[key] = map[*types.Var]bool{}
				}
				if !seenUse[key][v] {
					seenUse[key][v] = true
					pi.uses[v] = append(pi.uses[v], key)
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.ARROW && len(stack) == 0 && !ticks && isTick(info, x.X) {
				ticks = true
				pi.class[me.id] = append(pi.class[me.id], EntryRef{Symbol: me.name, File: me.file, Line: me.line, Via: "ticker"})
			}
		case *ast.RangeStmt:
			if len(stack) == 0 && !ticks && isTick(info, x.X) {
				ticks = true
				pi.class[me.id] = append(pi.class[me.id], EntryRef{Symbol: me.name, File: me.file, Line: me.line, Via: "ticker"})
			}
		case *ast.CallExpr:
			callee := calleeFunc(info, x)
			if callee == nil {
				return true
			}
			for _, target := range pi.targets(callee) {
				pi.up[target.id] = append(pi.up[target.id], poolEdge{caller: me, ctx: ctx, goCall: goCalls[x]})
			}
		}
		return true
	})
}

// targets is the in-repo functions a call of callee can run: the function
// itself, or, for a method of an interface this repository declares, every
// method of a repository type that implements it.
func (pi *poolIndex) targets(callee *types.Func) []*retFunc {
	callee = callee.Origin()
	if rf := pi.funcs[callee.FullName()]; rf != nil {
		return []*retFunc{rf}
	}
	recv := callee.Signature().Recv()
	if recv == nil {
		return nil
	}
	iface, ok := recv.Type().(*types.Named)
	if !ok || !types.IsInterface(iface) || iface.Obj().Pkg() == nil || !pi.ix.repo[iface.Obj().Pkg().Path()] {
		return nil
	}
	impls, done := pi.impls[iface]
	if !done {
		it := iface.Underlying().(*types.Interface)
		for _, t := range pi.byMethod[callee.Name()] {
			if types.Implements(t, it) || types.Implements(types.NewPointer(t), it) {
				impls = append(impls, t)
			}
		}
		pi.impls[iface] = impls
	}
	var out []*retFunc
	for _, t := range impls {
		obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(t), true, callee.Pkg(), callee.Name())
		if m, ok := obj.(*types.Func); ok {
			if rf := pi.funcs[m.Origin().FullName()]; rf != nil {
				out = append(out, rf)
			}
		}
	}
	return out
}

// indexTypes lists this repository's named concrete types by the names of
// their methods.
func (pi *poolIndex) indexTypes() {
	pi.byMethod = map[string][]*types.Named{}
	for _, p := range pi.pkgs {
		if p.Types == nil || p.TypesInfo == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok || types.IsInterface(named) {
				continue
			}
			ms := types.NewMethodSet(types.NewPointer(named))
			for i := 0; i < ms.Len(); i++ {
				n := ms.At(i).Obj().Name()
				pi.byMethod[n] = append(pi.byMethod[n], named)
			}
		}
	}
}

// typeMethods classes the named methods of t's in-repo type as handlers.
func (pi *poolIndex) typeMethods(t types.Type, names []string, via string) {
	if t == nil {
		return
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || types.IsInterface(named) || named.Obj().Pkg() == nil || !pi.ix.repo[named.Obj().Pkg().Path()] {
		return
	}
	for _, n := range names {
		obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(named), true, named.Obj().Pkg(), n)
		if m, ok := obj.(*types.Func); ok {
			if rf := pi.funcs[m.Origin().FullName()]; rf != nil {
				pi.class[rf.id] = append(pi.class[rf.id], EntryRef{Symbol: rf.name, File: rf.file, Line: rf.line, Via: via})
			}
		}
	}
}

// isTick reports whether x is a ticker's channel: t.C of a time.Ticker, or
// time.Tick(d).
func isTick(info *types.Info, x ast.Expr) bool {
	x = ast.Unparen(x)
	if c, ok := x.(*ast.CallExpr); ok {
		fn := calleeFunc(info, c)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "time" && fn.Name() == "Tick"
	}
	sel, ok := x.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "C" {
		return false
	}
	t := info.TypeOf(sel.X)
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "time" && named.Obj().Name() == "Ticker"
}

// isHTTPType reports whether t is net/http's type of that name.
func isHTTPType(t types.Type, name string) bool {
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == name
}
