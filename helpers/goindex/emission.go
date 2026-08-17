// G4 emission-point inventory (po-av01j.5): log statements, span/trace
// instrumentation, and error-handling sites, emitted on the SAME packet
// stream as call sites, distinguished by site_kind: "emission_point".
//
// The retrieval/judgment split holds: nothing here decides whether the
// repository's observability is adequate. The emitter reports mechanical
// facts — "this function makes 3 log/slog.Logger log calls", "this function
// recovers a panic and emits nothing" — and the spec layer (EmissionSpec)
// says what a shape means for RC-027/RC-046/RC-061.
//
// VOLUME CONTROL is the load-bearing design constraint. Log statements are
// the highest-volume site class in any codebase, so emission packets are
// AGGREGATES: one per (enclosing function, framework identity, category),
// with the category and call count riding const_args entries
// (emission_category / emission_count, how: "aggregate") rather than one
// packet per log line. A large backend repo must not produce tens of
// thousands of emission sites.
//
// Classification is TYPE-DRIVEN: a call is an emission only when the type
// checker resolves its callee into a known telemetry framework package.
// Unresolved callees are skipped — abstain rather than guess.
package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// siteKindEmission mirrors rvl_core::SITE_KIND_EMISSION.
const siteKindEmission = "emission_point"

// emissionFramework classifies a callee's PACKAGE into an emission category.
// The framework list is the candidate extractor (like ioMethods for G1): it
// decides what gets inventoried, never what a match means.
// COVERAGE HERE IS A FALSE-POSITIVE SURFACE, not just missing inventory
// (po-av01j.142). The recover_block swallow fact is "recovers and emits
// NOTHING RECOGNIZED", so a logger this list does not know turns correct code
// into a finding: consul logs every recovered panic through
// hashicorp/go-hclog and was reported as swallowing them. The standard `log`
// package was missing too, which is the most common logging call in Go.
// Adding a framework can only ever REMOVE false swallows, never invent a
// finding.
func emissionFramework(pkgPath string) (string, bool) {
	switch {
	case pkgPath == "log/slog" || strings.HasPrefix(pkgPath, "log/slog/"):
		return "log", true
	// The standard library logger. Exact match: HasPrefix("log") would also
	// swallow log/slog above and any other log/* subpackage.
	case pkgPath == "log":
		return "log", true
	case strings.HasPrefix(pkgPath, "github.com/hashicorp/go-hclog"):
		return "log", true
	case strings.HasPrefix(pkgPath, "k8s.io/klog"):
		return "log", true
	case strings.HasPrefix(pkgPath, "github.com/go-kit/log"),
		strings.HasPrefix(pkgPath, "github.com/go-kit/kit/log"):
		return "log", true
	case strings.HasPrefix(pkgPath, "github.com/golang/glog"):
		return "log", true
	case strings.HasPrefix(pkgPath, "go.uber.org/zap"):
		return "log", true
	case strings.HasPrefix(pkgPath, "github.com/sirupsen/logrus"):
		return "log", true
	case strings.HasPrefix(pkgPath, "github.com/rs/zerolog"):
		return "log", true
	case strings.HasPrefix(pkgPath, "github.com/getsentry/sentry-go"):
		return "error_capture", true
	case strings.HasPrefix(pkgPath, "go.opentelemetry.io/otel"):
		return "trace", true
	}
	return "", false
}

// Emit-verb allowlists per category: a framework package also exports
// non-emitting surface (zap's With/Named, otel's propagators) that must not
// count as emission calls.
var logEmitMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DPanic": true, "Panic": true, "Fatal": true, "Trace": true,
	"Print": true, "Printf": true, "Println": true,
	// The -f / -ln variants the standard library, klog and glog use.
	"Debugf": true, "Infof": true, "Warnf": true, "Errorf": true,
	"Fatalf": true, "Fatalln": true, "Panicf": true, "Panicln": true,
	"Infoln": true, "Errorln": true, "Warning": true, "Warningf": true,
	"Log": true, "LogAttrs": true,
	"Msg": true, "Msgf": true, "Send": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true,
	"ErrorContext": true,
}

var traceEmitMethods = map[string]bool{"Start": true}

var captureEmitMethods = map[string]bool{
	"CaptureException": true, "CaptureMessage": true, "CaptureEvent": true,
	"Recover": true,
}

func emissionMethodOK(category, method string) bool {
	switch category {
	case "log":
		return logEmitMethods[method]
	case "trace":
		return traceEmitMethods[method]
	case "error_capture":
		return captureEmitMethods[method]
	}
	return false
}

// emissionAgg accumulates one (function, framework, category) aggregate.
type emissionAgg struct {
	file       string
	line       int
	symbol     string
	method     string
	clientType string
	category   string
	snippet    string
	count      int
}

func (a *emissionAgg) site(snapshot string) RetrievedSite {
	return RetrievedSite{
		SiteKind:   siteKindEmission,
		Snapshot:   snapshot,
		File:       a.file,
		Line:       a.line,
		Symbol:     a.symbol,
		Method:     a.method,
		ClientType: a.clientType,
		CallSite:   a.snippet,
		Callers:    []Snippet{},
		Callees:    []Snippet{},
		ConstArgs: []ConstArg{
			{Index: 0, Name: "emission_category", Value: a.category, How: "aggregate"},
			{Index: 0, Name: "emission_count", Value: fmt.Sprint(a.count), How: "aggregate"},
		},
		Prov: Provenance{ClientTypeKnown: true},
	}
}

// collectEmissions walks every scanned function and returns the emission
// aggregates. `snapshot` stamps the packets; paths are repo-relative like
// every other packet.
func collectEmissions(pkgs []*packages.Package, src *srcIndex, root, snapshot string) []RetrievedSite {
	var out []RetrievedSite
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		info := p.TypesInfo
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				pos := p.Fset.Position(fd.Pos())
				rel := relPath(root, pos.Filename)
				if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "vendor/") {
					continue
				}
				out = append(out, functionEmissions(p, info, src, fd, rel, snapshot)...)
			}
		}
	}
	// Deterministic order: the stream must be stable across runs so the
	// incremental index's reuse-vs-changed diff is content-driven.
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].ClientType < out[j].ClientType
	})
	return out
}

// errorOutParams returns the identifiers of parameters through which a
// recovered panic can be handed BACK to the caller: a pointer to an error, or
// a pointer to a slice of them.
//
// Found on nats-server (po-av01j.142): the first version of this check only
// understood named RESULTS, so it still flagged
//
//	// use in defer to recover from panic and turn it into an error
//	func convertPanicToError(lastToken *token, e *error) {
//	    ... else if err := recover(); err == nil { return
//	    } else { *e = &configErr{*lastToken, fmt.Sprint(err)} }
//
// which is the same idiom one indirection over. A `defer f(&tok, &err)` helper
// is the ordinary Go way to share panic-to-error conversion across call sites,
// and the function name says so outright.
func errorOutParams(ft *ast.FuncType) map[string]bool {
	out := map[string]bool{}
	if ft == nil || ft.Params == nil {
		return out
	}
	for _, f := range ft.Params.List {
		star, ok := f.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		// *error, or *[]error.
		isErr := func(e ast.Expr) bool {
			if id, ok := e.(*ast.Ident); ok {
				return id.Name == "error"
			}
			return false
		}
		ok = isErr(star.X)
		if !ok {
			if arr, isArr := star.X.(*ast.ArrayType); isArr {
				ok = isErr(arr.Elt)
			}
		}
		if !ok {
			continue
		}
		for _, n := range f.Names {
			if n.Name != "" && n.Name != "_" {
				out[n.Name] = true
			}
		}
	}
	return out
}

// namedResults returns the identifiers of a function type's named return
// values. A function with unnamed results cannot propagate a recovered panic
// by assignment, only by re-panicking.
func namedResults(ft *ast.FuncType) map[string]bool {
	out := map[string]bool{}
	if ft == nil || ft.Results == nil {
		return out
	}
	for _, f := range ft.Results.List {
		for _, n := range f.Names {
			if n.Name != "" && n.Name != "_" {
				out[n.Name] = true
			}
		}
	}
	return out
}

// recoverPropagates reports whether a recovered panic LEAVES the function
// rather than being discarded (po-av01j.142).
//
// WHY THIS EXISTS. The swallow fact used to be "calls recover() and logs
// nothing", which flags the standard Go idiom for not panicking across an API
// boundary:
//
//	func PatchStruct(...) (result K, e error) {
//	    defer func() {
//	        if err := recover(); err != nil {
//	            e = fmt.Errorf("unexpected panic: %v", err)   // NOT a swallow
//	        }
//	    }()
//
// The caller receives the error. Nothing is hidden, and nothing needs a log
// emission to make it visible. Measured on hashicorp/consul, every site the
// old rule reported was this shape.
//
// The vocabulary always knew this for other languages -- catch_clause is "a
// catch that neither emits NOR RE-THROWS", except_handler is "nor re-raises"
// -- and Go's equivalent of re-throw is exactly assigning the named result or
// re-panicking. Only the Go rule omitted it.
//
// SCOPED TO THE BLOCK THAT RECOVERS, not the whole function. A function whose
// normal path assigns `err = doThing()` and whose deferred block discards the
// panic IS a swallow, and looking at the whole body would wrongly clear it.
func recoverPropagates(info *types.Info, fd *ast.FuncDecl) bool {
	// True when `n` is a recover() call: the builtin, not a method named
	// "recover" on some type.
	isRecover := func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := c.Fun.(*ast.Ident)
		if !ok {
			return false
		}
		b, ok := info.Uses[id].(*types.Builtin)
		return ok && b.Name() == "recover"
	}
	// True when `n` re-raises, or hands the failure to a named result of the
	// scope named by `named`.
	escapes := func(n ast.Node, named map[string]bool) bool {
		switch s := n.(type) {
		case *ast.CallExpr:
			id, ok := s.Fun.(*ast.Ident)
			if !ok {
				return false
			}
			b, isB := info.Uses[id].(*types.Builtin)
			return isB && b.Name() == "panic"
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				// A named result: `err = ...`
				if id, ok := lhs.(*ast.Ident); ok && named[id.Name] {
					return true
				}
				// An error out-parameter: `*e = ...` / `*errors = append(...)`
				if star, ok := lhs.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok && named[id.Name] {
						return true
					}
				}
			}
		}
		return false
	}
	// SHALLOW: stops at nested function literals, so each literal is judged in
	// its own scope. A deep walk conflates a deferred block's recover() with an
	// unrelated normal-path `err = ...` and clears a genuine swallow.
	scopeHas := func(body ast.Node, named map[string]bool) (recovers, out bool) {
		first := true
		ast.Inspect(body, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			if _, isLit := n.(*ast.FuncLit); isLit && !first {
				return false // its own scope; handled by the recursion
			}
			first = false
			if isRecover(n) {
				recovers = true
			}
			if escapes(n, named) {
				out = true
			}
			return true
		})
		return
	}

	// Each function scope judges the literals DIRECTLY inside it against its
	// OWN named results. That is what makes the returned-closure shape work:
	// in consul's ServerRateLimiterMiddleware the recovering block assigns
	// `retErr`, a named result of the RETURNED closure, not of the outer
	// function, so judging it against the outer scope finds nothing.
	var walk func(body *ast.BlockStmt, named map[string]bool) bool
	walk = func(body *ast.BlockStmt, named map[string]bool) bool {
		if body == nil {
			return false
		}
		prop := false
		ast.Inspect(body, func(n ast.Node) bool {
			fl, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			if r, o := scopeHas(fl.Body, named); r && o {
				prop = true
			}
			inner := namedResults(fl.Type)
			for k := range errorOutParams(fl.Type) {
				inner[k] = true
			}
			if walk(fl.Body, inner) {
				prop = true
			}
			return false
		})
		if r, o := scopeHas(body, named); r && o {
			prop = true
		}
		return prop
	}
	// Propagation targets for a scope are its named results AND its error
	// out-parameters: both hand the failure back to the caller.
	targets := namedResults(fd.Type)
	for k := range errorOutParams(fd.Type) {
		targets[k] = true
	}
	return walk(fd.Body, targets)
}

// functionEmissions aggregates one function's emission calls, plus the
// recover_block swallow fact: a function that calls recover(), emits NOTHING
// recognized, AND does not propagate the recovered panic is an error path with
// no capture — the combined mechanical fact RC-027's capture-vs-swallow
// question needs. A function that recovers AND emits is instrumented; one that
// recovers and RETURNS the failure is propagating, which is not a swallow
// either (po-av01j.142).
func functionEmissions(
	p *packages.Package,
	info *types.Info,
	src *srcIndex,
	fd *ast.FuncDecl,
	rel, snapshot string,
) []RetrievedSite {
	aggs := map[string]*emissionAgg{}
	recoverCount := 0
	recoverLine := 0
	sawEmission := false

	ast.Inspect(fd.Body, func(x ast.Node) bool {
		c, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		var callee *types.Func
		switch fun := c.Fun.(type) {
		case *ast.Ident:
			if b, isB := info.Uses[fun].(*types.Builtin); isB && b.Name() == "recover" {
				recoverCount++
				if recoverLine == 0 {
					recoverLine = p.Fset.Position(c.Pos()).Line
				}
				return true
			}
			callee, _ = info.Uses[fun].(*types.Func)
		case *ast.SelectorExpr:
			callee, _ = info.Uses[fun.Sel].(*types.Func)
		}
		if callee == nil || callee.Pkg() == nil {
			return true
		}
		category, ok := emissionFramework(callee.Pkg().Path())
		if !ok || !emissionMethodOK(category, callee.Name()) {
			return true
		}
		// Framework identity: the receiver TYPE for method calls
		// (log/slog.Logger), the package path for package-level calls
		// (log/slog). Both resolve through the type checker; nothing is
		// guessed from names.
		clientType := callee.Pkg().Path()
		if sig, isSig := callee.Type().(*types.Signature); isSig && sig.Recv() != nil {
			if sel, isSel := c.Fun.(*ast.SelectorExpr); isSel {
				if t := info.TypeOf(sel.X); t != nil {
					clientType = strings.TrimPrefix(t.String(), "*")
				}
			}
		}
		sawEmission = true
		key := clientType + "\x00" + category
		agg, exists := aggs[key]
		if !exists {
			agg = &emissionAgg{
				file:       rel,
				line:       p.Fset.Position(c.Pos()).Line,
				symbol:     fd.Name.Name,
				method:     callee.Name(),
				clientType: clientType,
				category:   category,
				snippet:    src.text(p, c, c),
			}
			aggs[key] = agg
		}
		agg.count++
		return true
	})

	if recoverCount > 0 && !sawEmission && !recoverPropagates(info, fd) {
		aggs["recover_block\x00error_capture"] = &emissionAgg{
			file:       rel,
			line:       recoverLine,
			symbol:     fd.Name.Name,
			method:     "recover",
			clientType: "recover_block",
			category:   "error_capture",
			count:      recoverCount,
		}
	}

	out := make([]RetrievedSite, 0, len(aggs))
	for _, a := range aggs {
		out = append(out, a.site(snapshot))
	}
	return out
}

// relPath mirrors the rel() closure in runRetrieve (filepath.Rel + ToSlash)
// for callers outside it.
func relPath(root, filename string) string {
	r, err := filepath.Rel(root, filename)
	if err != nil {
		return filepath.ToSlash(filename)
	}
	return filepath.ToSlash(r)
}
