// Local shapes of the misuse lane that are not about a discarded error. Each
// class is named for the SHAPE the retriever reads, never for the defect a
// reader may infer from it:
//
//	retry_shape            a wait on the failure path of an attempt loop.
//	                       Identity: constant_delay, no_jitter or
//	                       unbounded_attempts.
//	sql_concat_in_call     a query call whose SQL argument is built in that
//	                       same expression. Identity: the query method.
//	print_logging          output through fmt.Print*, the print builtins, or
//	                       fmt.Fprint* to a standard stream. Identity: the callee.
//	latency_scalar_metric  a Prometheus gauge or counter registered with a
//	                       latency name. Identity: the constructor.
//
// The retrieval/judgment split holds: nothing here says a shape is a finding.
//
// What each rule does NOT see is part of the rule:
//
//   - retry_shape reads the delay expression. It does not decide that a loop
//     is a retry from its intent. A loop over a collection gives each item one
//     attempt and is not a retry loop. A sleep that is not on the failure path
//     is a poll interval. A delay that a function computes has no shape in
//     this expression, and is not reported.
//   - sql_concat_in_call is the same-expression form only. SQL text built in
//     one statement and run in another needs data flow, and is not claimed.
//   - print_logging leaves the standard `log` package out. The emission lane
//     counts log.Print* as a log emission (emission.go), and one line cannot
//     be both a log emission and a missing one.
//   - There is no N+1 class here. The form this lane can reach is a query
//     method on a relation of the loop variable, and Go ORMs do not load
//     relations through the receiver.
package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"
)

const (
	classRetryShape    = "retry_shape"
	classSQLConcat     = "sql_concat_in_call"
	classPrintLogging  = "print_logging"
	classLatencyScalar = "latency_scalar_metric"

	retryConstantDelay = "constant_delay"
	retryNoJitter      = "no_jitter"
	retryUnbounded     = "unbounded_attempts"
)

// latencyName matches a metric name that says it measures latency. A bare
// `_seconds` is not enough: `process_cpu_seconds_total` is a correct counter.
var latencyName = regexp.MustCompile(`(?i)latency|duration|response_time|elapsed`)

// sqlHandlePrefixes are the type prefixes of database handles whose query
// methods take SQL text.
var sqlHandlePrefixes = []string{
	"database/sql.",
	"github.com/jmoiron/sqlx.",
	"github.com/jackc/pgx/",
}

var sqlQueryMethods = map[string]bool{
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Exec": true, "ExecContext": true, "Prepare": true, "PrepareContext": true,
}

const promPkg = "github.com/prometheus/client_golang/prometheus"

var promScalarCtors = map[string]bool{
	"NewGauge": true, "NewGaugeVec": true, "NewCounter": true, "NewCounterVec": true,
}

// collectLocalShapes reports every local shape under root, which is a
// function body or a package-level declaration.
func collectLocalShapes(info *types.Info, root ast.Node, note shapeNote) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			printCall(info, n, note)
			sqlBuiltInCall(info, n, note)
			latencyScalar(info, n, note)
		case *ast.ForStmt:
			retryLoop(info, n, n.Body, n.Cond != nil, note)
		case *ast.RangeStmt:
			// `for attempt := range 4` counts attempts. A range over a
			// collection does not.
			if basicIs(info.TypeOf(n.X), types.IsInteger) {
				retryLoop(info, n, n.Body, true, note)
			}
		}
		return true
	})
}

// basicIs reports whether a type is a basic type of the given kind. An
// expression the type checker could not type is not.
func basicIs(t types.Type, kind types.BasicInfo) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&kind != 0
}

func printCall(info *types.Info, call *ast.CallExpr, note shapeNote) {
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if b, isBuiltin := info.Uses[id].(*types.Builtin); isBuiltin && (b.Name() == "print" || b.Name() == "println") {
			note(classPrintLogging, b.Name(), b.Name(), true, call)
		}
		return
	}
	identity, name, known := calleeIdentity(info, call)
	if !known {
		return
	}
	switch identity {
	case "fmt.Print", "fmt.Printf", "fmt.Println":
		note(classPrintLogging, identity, name, true, call)
	case "fmt.Fprint", "fmt.Fprintf", "fmt.Fprintln":
		if len(call.Args) == 0 {
			return
		}
		sel, ok := ast.Unparen(call.Args[0]).(*ast.SelectorExpr)
		if !ok {
			return
		}
		v, ok := info.Uses[sel.Sel].(*types.Var)
		if ok && v.Pkg() != nil && v.Pkg().Path() == "os" && (v.Name() == "Stdout" || v.Name() == "Stderr") {
			note(classPrintLogging, identity+"(os."+v.Name()+")", name, true, call)
		}
	}
}

func sqlBuiltInCall(info *types.Info, call *ast.CallExpr, note shapeNote) {
	identity, name, known := calleeIdentity(info, call)
	if !known || !sqlQueryMethods[name] {
		return
	}
	isHandle := false
	for _, p := range sqlHandlePrefixes {
		isHandle = isHandle || strings.HasPrefix(identity, p)
	}
	if !isHandle {
		return
	}
	// The SQL text is the first string argument (a context may come first).
	for _, arg := range call.Args {
		if !basicIs(info.TypeOf(arg), types.IsString) {
			continue
		}
		if builtString(info, arg) {
			note(classSQLConcat, identity, name, true, call)
		}
		return
	}
}

// builtString reports whether a string expression is put together where it
// stands from a part that is not a constant: a concatenation, or a
// fmt.Sprintf with arguments.
func builtString(info *types.Info, e ast.Expr) bool {
	e = ast.Unparen(e)
	if tv, ok := info.Types[e]; ok && tv.Value != nil {
		return false
	}
	switch e := e.(type) {
	case *ast.BinaryExpr:
		return e.Op == token.ADD
	case *ast.CallExpr:
		identity, _, known := calleeIdentity(info, e)
		return known && identity == "fmt.Sprintf" && len(e.Args) > 1
	}
	return false
}

func latencyScalar(info *types.Info, call *ast.CallExpr, note shapeNote) {
	var sel *ast.Ident
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		sel = f
	case *ast.SelectorExpr:
		sel = f.Sel
	}
	if sel == nil || !promScalarCtors[sel.Name] || len(call.Args) == 0 {
		return
	}
	// promauto has the same constructors, as functions and on its Factory.
	fn, ok := info.Uses[sel].(*types.Func)
	if !ok || fn.Pkg() == nil || !strings.HasPrefix(fn.Pkg().Path(), promPkg) {
		return
	}
	opts, ok := ast.Unparen(call.Args[0]).(*ast.CompositeLit)
	if !ok {
		return
	}
	for _, el := range opts.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, isIdent := kv.Key.(*ast.Ident); !isIdent || key.Name != "Name" {
			continue
		}
		tv := info.Types[kv.Value]
		if tv.Value != nil && latencyName.MatchString(tv.Value.ExactString()) {
			note(classLatencyScalar, fn.Pkg().Path()+"."+fn.Name(), fn.Name(), true, call)
		}
	}
}

// --- retry_shape ---------------------------------------------------------------

// retryFacts is what one loop body says about its own variables.
type retryFacts struct {
	info *types.Info
	// mutated holds the variables the loop changes in place (`d *= 2`, `i++`,
	// the loop counter).
	mutated map[types.Object]bool
	// defs holds every value the loop assigns to a variable.
	defs map[types.Object][]ast.Expr
}

// inLoop walks a loop without the function literals and the inner loops in
// it: those run on their own terms.
func inLoop(root ast.Node, visit func(ast.Node)) {
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if n != root {
			switch n.(type) {
			case *ast.FuncLit, *ast.ForStmt, *ast.RangeStmt:
				return false
			}
		}
		visit(n)
		return true
	})
}

func (r *retryFacts) object(e ast.Expr) types.Object {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return nil
	}
	if o := r.info.Defs[id]; o != nil {
		return o
	}
	return r.info.Uses[id]
}

func (r *retryFacts) read(loop ast.Stmt) {
	mark := func(e ast.Expr) {
		if o := r.object(e); o != nil {
			r.mutated[o] = true
		}
	}
	// The header of the loop: its counter.
	switch l := loop.(type) {
	case *ast.ForStmt:
		for _, s := range []ast.Stmt{l.Init, l.Post} {
			switch s := s.(type) {
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					mark(lhs)
				}
			case *ast.IncDecStmt:
				mark(s.X)
			}
		}
	case *ast.RangeStmt:
		if l.Key != nil {
			mark(l.Key)
		}
	}
	inLoop(loop, func(n ast.Node) {
		switch s := n.(type) {
		case *ast.IncDecStmt:
			mark(s.X)
		case *ast.AssignStmt:
			if s == loopInit(loop) || len(s.Lhs) != len(s.Rhs) {
				return
			}
			for i, lhs := range s.Lhs {
				o := r.object(lhs)
				if o == nil {
					continue
				}
				r.defs[o] = append(r.defs[o], s.Rhs[i])
				if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
					r.mutated[o] = true
				}
			}
		}
	})
}

func loopInit(loop ast.Stmt) ast.Stmt {
	if l, ok := loop.(*ast.ForStmt); ok {
		return l.Init
	}
	return nil
}

// delayShape is what a delay expression is made of.
type delayShape struct{ varying, random, opaque bool }

// shape reads a delay expression, following the loop's own assignments to
// the variables in it. A variable whose value depends on itself varies.
func (r *retryFacts) shape(e ast.Expr, resolving map[types.Object]bool, out *delayShape) {
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			o := r.info.Uses[n]
			if o == nil {
				return true
			}
			if r.mutated[o] || resolving[o] {
				out.varying = true
			}
			if !resolving[o] {
				resolving[o] = true
				for _, def := range r.defs[o] {
					r.shape(def, resolving, out)
				}
				delete(resolving, o)
			}
		case *ast.CallExpr:
			if tv, ok := r.info.Types[n.Fun]; ok && (tv.IsType() || tv.IsBuiltin()) {
				return true
			}
			identity, _, known := calleeIdentity(r.info, n)
			switch {
			case !known:
				out.opaque = true
			case strings.HasPrefix(identity, "math/rand") || strings.HasPrefix(identity, "crypto/rand."):
				out.random = true
			case strings.HasPrefix(identity, "math.") || strings.HasPrefix(identity, "time.Duration."):
				// Arithmetic on the delay: the shape is in the arguments.
			default:
				out.opaque = true
			}
		}
		return true
	})
}

// errTest classifies a condition: +1 for `err != nil`, -1 for `err == nil`
// on a value of type error, 0 for anything else.
func errTest(info *types.Info, cond ast.Expr) int {
	b, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || (b.Op != token.NEQ && b.Op != token.EQL) {
		return 0
	}
	isNil := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && id.Name == "nil"
	}
	var val ast.Expr
	switch {
	case isNil(b.Y):
		val = b.X
	case isNil(b.X):
		val = b.Y
	default:
		return 0
	}
	if t := info.TypeOf(val); t == nil || !types.Identical(t, errorType) {
		return 0
	}
	if b.Op == token.NEQ {
		return 1
	}
	return -1
}

// leaves reports whether a block ends by leaving the iteration.
func leaves(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch s := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok == token.BREAK || s.Tok == token.CONTINUE
	}
	return false
}

// failureWaits returns the delay expression of every wait (time.Sleep, or a
// receive from time.After) that the loop body reaches only after a failed
// attempt: under an `err != nil` test, or after an `err == nil` test that
// leaves the iteration.
func failureWaits(info *types.Info, body *ast.BlockStmt) (delays []ast.Expr, at []ast.Node) {
	timeCall := func(e ast.Expr, want string) ast.Expr {
		call, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return nil
		}
		if identity, _, known := calleeIdentity(info, call); !known || identity != want {
			return nil
		}
		return call.Args[0]
	}
	var walk func(list []ast.Stmt, onFail bool)
	walk = func(list []ast.Stmt, onFail bool) {
		for _, stmt := range list {
			switch s := stmt.(type) {
			case *ast.IfStmt:
				k := errTest(info, s.Cond)
				walk(s.Body.List, onFail || k > 0)
				if s.Else != nil {
					walk([]ast.Stmt{s.Else}, onFail || k < 0)
				}
				if k < 0 && leaves(s.Body) {
					onFail = true
				}
			case *ast.BlockStmt:
				walk(s.List, onFail)
			case *ast.LabeledStmt:
				walk([]ast.Stmt{s.Stmt}, onFail)
			case *ast.ExprStmt:
				if d := timeCall(s.X, "time.Sleep"); d != nil && onFail {
					delays, at = append(delays, d), append(at, s.X)
				}
			case *ast.SelectStmt:
				for _, c := range s.Body.List {
					cc := c.(*ast.CommClause)
					var recv ast.Expr
					switch comm := cc.Comm.(type) {
					case *ast.ExprStmt:
						recv = comm.X
					case *ast.AssignStmt:
						if len(comm.Rhs) == 1 {
							recv = comm.Rhs[0]
						}
					}
					if u, ok := recv.(*ast.UnaryExpr); ok && u.Op == token.ARROW && onFail {
						if d := timeCall(u.X, "time.After"); d != nil {
							delays, at = append(delays, d), append(at, u.X)
						}
					}
					walk(cc.Body, onFail)
				}
			case *ast.SwitchStmt:
				for _, c := range s.Body.List {
					walk(c.(*ast.CaseClause).Body, onFail)
				}
			}
		}
	}
	walk(body.List, false)
	return delays, at
}

// attemptsLimited reports whether a loop with no condition limits its
// attempts in the body: a test of a counter the loop changes that leaves the
// loop, or a wait on a `Done()` channel.
func (r *retryFacts) attemptsLimited(loop ast.Stmt) bool {
	limited := false
	exits := func(b *ast.BlockStmt) bool {
		found := false
		inLoop(b, func(n ast.Node) {
			switch s := n.(type) {
			case *ast.ReturnStmt:
				found = true
			case *ast.BranchStmt:
				found = found || s.Tok == token.BREAK || s.Tok == token.GOTO
			}
		})
		return found
	}
	inLoop(loop, func(n ast.Node) {
		switch s := n.(type) {
		case *ast.IfStmt:
			counter := false
			ast.Inspect(s.Cond, func(c ast.Node) bool {
				if id, ok := c.(*ast.Ident); ok {
					if o := r.info.Uses[id]; o != nil && r.mutated[o] && basicIs(o.Type(), types.IsInteger) {
						counter = true
					}
				}
				return true
			})
			limited = limited || (counter && exits(s.Body))
		case *ast.SelectorExpr:
			limited = limited || s.Sel.Name == "Done"
		}
	})
	return limited
}

func retryLoop(info *types.Info, loop ast.Stmt, body *ast.BlockStmt, hasBound bool, note shapeNote) {
	delays, at := failureWaits(info, body)
	if len(delays) == 0 {
		return
	}
	r := &retryFacts{info: info, mutated: map[types.Object]bool{}, defs: map[types.Object][]ast.Expr{}}
	r.read(loop)
	for i, d := range delays {
		var s delayShape
		r.shape(d, map[types.Object]bool{}, &s)
		switch {
		case s.opaque || s.random:
			// A function computes the delay, or it has a random term.
		case s.varying:
			note(classRetryShape, retryNoJitter, "Sleep", true, at[i])
		default:
			note(classRetryShape, retryConstantDelay, "Sleep", true, at[i])
		}
	}
	if !hasBound && !r.attemptsLimited(loop) {
		note(classRetryShape, retryUnbounded, "Sleep", true, at[0])
	}
}
