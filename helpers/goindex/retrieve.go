// Retrieval mode: emit the SOURCE that bears on a call site, never a verdict.
//
// The split this enforces
//
// Per-language work is RETRIEVAL: mechanical, semantically neutral, no
// reliability opinion. "Here is the function that calls this one." "Here is
// where this client was constructed." That is compiler work and it is genuinely
// cheap to add per language.
//
// JUDGEMENT stays semantic -- the LLM panel now, a distilled student later.
//
// Everything in main.go that crossed that line is deliberately absent here.
// There is no ancestor_bounded, no client_phase_only, no derivesDeadline in the
// output. Those encoded reliability knowledge in hand-written name lists, which
// is how a matcher gets rebuilt inside an AST. The moment the panel discovered
// that DialTimeout bounds only the connection phase, the right move was to let
// the model learn it; freezing it into a wholeCallFields map was the drift.
//
// Selection must stay neutral too. Callers are included by GRAPH PROXIMITY and a
// byte budget, never by whether their contents look relevant -- filtering on
// content would smuggle the judgement back in through the retrieval policy. When
// the budget truncates, the provenance block says so, so the reader can tell
// "searched everything and found nothing" from "ran out of room".
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Retrieval policy knobs. Hard-coding these would just be another hand-tuned
// guess; they are the natural sweep axes for an auto-research loop whose
// objective is abstention rate (and, later, student accuracy) per token spent.
var (
	maxCallersEmitted = 4
	maxCtorsEmitted   = 2
	maxCalleesEmitted = 4
	maxSnippetBytes   = 2400
)

// Snippet is a piece of retrieved source with enough provenance to cite it.
type Snippet struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol"`
	Source string `json:"source"`
	// Whether the ctx this caller PASSES to the callee was assigned from
	// context.WithTimeout/WithDeadline in this caller's body. This is the
	// dataflow question, and it is the one that matters: main() contains a
	// WithTimeout in almost every Go program, which made the coarser
	// DerivesDeadline flag useless as a verdict input.
	PassesBoundedCtx bool `json:"passes_bounded_ctx,omitempty"`
	// Whether this function itself calls context.WithTimeout/WithDeadline.
	// A FACT about the code, resolved through the type checker so a local
	// helper named WithTimeout cannot spoof it. The judgement -- whether the
	// site is therefore bounded -- stays downstream. Emitting the conclusion
	// instead of the fact is the mistake that produced ancestor_bounded, which
	// failed its own sanity check at 50% (chance).
	DerivesDeadline bool `json:"derives_deadline,omitempty"`
}

// RootFact describes a function the upward walk stopped at because nothing in
// this repository calls it. Whether that makes it a genuine program entrypoint
// (so the chain really is complete) or an externally-invoked API (so it is not)
// is a JUDGEMENT, and it belongs to the panel. The previous entrypointish()
// name list -- matching "Handler", "Middleware", main, Run -- made that call
// here, in a hand-written matcher, and it was the single thing licensing every
// reason-from-absence verdict. These are the structural facts instead.
type RootFact struct {
	Symbol      string `json:"symbol"`
	Package     string `json:"package"`
	Signature   string `json:"signature"`
	Doc         string `json:"doc,omitempty"`
	Exported    bool   `json:"exported"`
	InPkgMain   bool   `json:"in_package_main"`
	RefAsValue  int    `json:"referenced_as_value"` // passed/assigned, not called
}

// Provenance describes what the retriever looked at and what it had to leave
// out. This is metadata about the SEARCH, not a claim about the code.
type Provenance struct {
	CallersTotal    int        `json:"callers_total"`
	CallersIncluded int        `json:"callers_included"`
	AncestryDepth   int        `json:"ancestry_depth_searched"`
	ChainRoots      []RootFact `json:"chain_roots"`
	HitDepthCap     bool       `json:"hit_depth_cap"`
	HitCallerBudget bool       `json:"hit_caller_budget"`
	ClientTypeKnown bool       `json:"client_type_resolved"`
	CalleesTotal    int        `json:"callees_total"`
	CalleesIncluded int        `json:"callees_included"`

	// The context question, answered structurally. Twelve of twenty-five sites
	// a human reviewed came down to "does the ctx flowing in already carry a
	// deadline?", and it is unanswerable from the call site by construction.
	// These count the traced ancestry rather than concluding from it: how many
	// distinct functions were reached, and how many of them establish a
	// deadline. All-of-them and none-of-them are very different situations and
	// the difference belongs to the reader.
	AncestorsTraced       int  `json:"ancestors_traced"`
	AncestorsWithDeadline int  `json:"ancestors_with_deadline"`
	EnclosingTakesCtx     bool `json:"enclosing_takes_context"`
	// Direct callers resolved by DATAFLOW rather than by body presence: how
	// many pass a ctx traced to a WithTimeout, out of how many were checked.
	DirectCallers         int  `json:"direct_callers"`
	DirectPassingBounded  int  `json:"direct_callers_passing_bounded_ctx"`
}

// RetrievedSite is what the labeller's evidence packet is built from.
// PacketSchema is the version of the emitted packet contract. rvlscan
// absorbs helper churn behind this number: a consumer that does not know a
// version refuses the stream rather than guessing at its shape. It MUST
// agree with pyindex's and tsindex's PACKET_SCHEMA and rvl_core::PACKET_SCHEMA.
//
// v2 adds const_args (constant-valued arguments at the call site) and
// macro_expansion (always false for Go, which has no macros; mechanical for
// C/C++). v2 is a strict superset of v1.
const PacketSchema = 2

// ConstArg is a constant-valued argument observed at the call site (schema
// v2). Evidence, never a verdict: WHAT the value means (CURLOPT_TIMEOUT vs
// CURLOPT_URL) is library knowledge and belongs to the spec layer. Only
// literals and constants the type checker folds for free are reported — no
// deep constant propagation.
type ConstArg struct {
	// Index is the zero-based position of the argument as written.
	Index int `json:"index"`
	// Name is the keyword/parameter name where the language surface has one;
	// Go calls are purely positional, so it is always absent here.
	Name string `json:"name,omitempty"`
	// Value is the source-level rendering of the folded constant
	// (go/constant's String: `"SELECT 1"` for strings, `50` for ints).
	Value string `json:"value"`
	// How the value was determined: "literal" for a literal token at the
	// call, "named_constant" for a resolved constant reference or folded
	// constant expression (2*time.Second).
	How string `json:"how"`
}

type RetrievedSite struct {
	// Schema is stamped on every record so a stream is self-describing even
	// when lines are split, filtered, or concatenated across helpers.
	Schema int `json:"packet_schema"`
	// SiteKey uniquely identifies this site. A file:line is NOT unique: one
	// location can resolve to several sites with different client types (and
	// different verdicts), so downstream indexes and joins key on this.
	SiteKey string `json:"site_key"`

	Snapshot   string `json:"snapshot_id"`
	File       string `json:"file_path"`
	Line       int    `json:"line_number"`
	Symbol     string `json:"symbol"`
	Method     string `json:"func"`
	Receiver   string `json:"receiver"`
	ClientType string `json:"client_type"`

	CallSite  string `json:"snippet"`
	Enclosing string `json:"enclosing_function_body"`

	Callers      []Snippet `json:"callers"`
	// Callees: in-repo functions the enclosing function CALLS. Retrieval only
	// ever walked upward, and all three sites a human could not decide during
	// adjudication needed evidence DOWNSTREAM instead -- the rate limiter's
	// implementation, the redis client's constructor, the handler's underlying
	// function. A deadline can be established below the call as easily as above
	// it, so a one-directional walk is structurally half-blind.
	Callees      []Snippet `json:"callees"`
	Construction []Snippet `json:"client_construction"`
	Prov         Provenance `json:"provenance"`

	// ConstArgs: constant-valued arguments at this call site (schema v2).
	// Emitted as [] when none resolve, so the packet shape is stable.
	ConstArgs []ConstArg `json:"const_args"`
	// MacroExpansion: whether the site sits inside a macro expansion. Go has
	// no macros, so always false here; C/C++ retrievers set it mechanically
	// from expansion locations.
	MacroExpansion bool `json:"macro_expansion"`
	// SiteKind marks what KIND of surface this is: empty for the classic G1
	// client call site, "background_job" for a G3 scheduler/queue
	// registration or worker-loop entry (po-av01j.4). Additive
	// default-carrying field within the v2 packet train — not a schema bump.
	SiteKind string `json:"site_kind,omitempty"`
}

// --- G3 background-job registration surfaces (po-av01j.4) ---
//
// jobFrameworks lists the scheduler/queue surfaces whose registration calls
// (and worker-loop entries) are emitted as background_job sites. Like
// ioMethods this is a RETRIEVAL selection table, not a judgment: it picks
// WHICH sites to surface; whether a registration needs a bound is spec
// knowledge (ApiSpec.site_kinds downstream). Detection is TYPE-driven — the
// callee must RESOLVE into the framework's package path — so an unresolved or
// same-named local method is never guessed at (abstain-by-omission).
var jobFrameworks = []struct {
	pkg        string          // exact package path, or a path prefix (versioned modules append /vN)
	methods    map[string]bool // registration / loop-entry functions
	clientType string          // canonical identity when the receiver is not a typed value (package funcs)
}{
	{"github.com/robfig/cron", map[string]bool{"AddFunc": true, "AddJob": true, "Schedule": true}, "github.com/robfig/cron.Cron"},
	{"github.com/hibiken/asynq", map[string]bool{"HandleFunc": true, "Handle": true}, "github.com/hibiken/asynq.ServeMux"},
	{"github.com/riverqueue/river", map[string]bool{"AddWorker": true, "AddWorkerSafely": true}, "github.com/riverqueue/river"},
	{"time", map[string]bool{"NewTicker": true, "Tick": true}, "time.Ticker"},
}

// jobFrameworkType returns the canonical framework identity for a callee that
// registers background work, or "" when the callee is not a recognized
// registration surface. Matching is on the callee's RESOLVED package path
// (exact, or a subpackage/versioned suffix), never on the receiver's text.
func jobFrameworkType(callee *types.Func) string {
	pkg := callee.Pkg()
	if pkg == nil {
		return ""
	}
	path := pkg.Path()
	for _, fw := range jobFrameworks {
		if !fw.methods[callee.Name()] {
			continue
		}
		if path == fw.pkg || strings.HasPrefix(path, fw.pkg+"/") {
			return fw.clientType
		}
	}
	return ""
}

type srcIndex struct {
	files map[string][]byte
}

func (s *srcIndex) text(pkg *packages.Package, from, to ast.Node) string {
	p1 := pkg.Fset.Position(from.Pos())
	p2 := pkg.Fset.Position(to.End())
	b, ok := s.files[p1.Filename]
	if !ok {
		raw, err := os.ReadFile(p1.Filename)
		if err != nil {
			return ""
		}
		s.files[p1.Filename] = raw
		b = raw
	}
	if p1.Offset < 0 || p2.Offset > len(b) || p1.Offset >= p2.Offset {
		return ""
	}
	out := string(b[p1.Offset:p2.Offset])
	if len(out) > maxSnippetBytes {
		out = out[:maxSnippetBytes] + "\n// ... truncated"
	}
	return out
}

type retFunc struct {
	id        string
	name      string
	file      string
	line      int
	pkg       *packages.Package
	decl      *ast.FuncDecl
	pkgName   string
	sig       string
	doc       string
	exported  bool
	refAsVal  int
	derivesDl bool
	takesCtx  bool
}

func (f *retFunc) root() RootFact {
	return RootFact{Symbol: f.name, Package: f.pkgName, Signature: f.sig,
		Doc: f.doc, Exported: f.exported, InPkgMain: f.pkgName == "main",
		RefAsValue: f.refAsVal}
}

// ctxArg returns the identifier passed in the context.Context position, if the
// argument is a plain variable. Anything more complex (a call result, a field
// selector) is not traced and reports false, which keeps the analysis sound in
// the direction that matters: unknown never becomes bounded.
func ctxArg(info *types.Info, call *ast.CallExpr) *ast.Ident {
	for _, a := range call.Args {
		t := info.TypeOf(a)
		if t == nil || !strings.HasSuffix(t.String(), "context.Context") {
			continue
		}
		if id, ok := a.(*ast.Ident); ok {
			return id
		}
		return nil
	}
	return nil
}

// assignedFromDeadline reports whether `name` was assigned from
// context.WithTimeout/WithDeadline anywhere in this body.
//
// Deliberately does not model shadowing or reassignment order: a name assigned
// from WithTimeout and later reassigned to something unbounded would read as
// bounded here. That is a known unsoundness, it is rare in practice, and the
// alternative is a full CFG. It is recorded rather than hidden.
func assignedFromDeadline(info *types.Info, body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		names := false
		for _, l := range as.Lhs {
			if id, ok := l.(*ast.Ident); ok && id.Name == name {
				names = true
			}
		}
		if !names {
			return true
		}
		for _, r := range as.Rhs {
			if c, ok := r.(*ast.CallExpr); ok && isContextDeadline(info, c) {
				found = true
			}
		}
		return true
	})
	return found
}

// passesBoundedCtx reports whether EVERY call from `caller` to `callee` passes a
// ctx traced to a deadline. Every, not any: one unbounded call path is real
// exposure, and reporting the caller as bounded would hide it.
func passesBoundedCtx(info *types.Info, caller *ast.FuncDecl, calleeID string,
	funcs map[string]*retFunc) bool {
	if caller.Body == nil {
		return false
	}
	sawCall, allBounded := false, true
	ast.Inspect(caller.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var fn *types.Func
		switch f := c.Fun.(type) {
		case *ast.Ident:
			fn, _ = info.Uses[f].(*types.Func)
		case *ast.SelectorExpr:
			fn, _ = info.Uses[f.Sel].(*types.Func)
		}
		if fn == nil || fn.FullName() != calleeID {
			return true
		}
		sawCall = true
		id := ctxArg(info, c)
		if id == nil || !assignedFromDeadline(info, caller.Body, id.Name) {
			allBounded = false
		}
		return true
	})
	return sawCall && allBounded
}

// constArgs reports the arguments of `call` whose values the type checker
// folds to constants, for free (schema v2). A literal token reports as
// "literal"; a resolved constant reference or folded constant expression
// (maxRetries, 2*time.Second) reports as "named_constant". Retrieval only:
// no deep constant propagation, no opinion about what a value means.
func constArgs(info *types.Info, call *ast.CallExpr) []ConstArg {
	out := []ConstArg{}
	for i, a := range call.Args {
		tv, ok := info.Types[a]
		if !ok || tv.Value == nil {
			continue
		}
		how := "named_constant"
		if _, isLit := a.(*ast.BasicLit); isLit {
			how = "literal"
		}
		out = append(out, ConstArg{Index: i, Value: tv.Value.ExactString(), How: how})
	}
	return out
}

// runRetrieve builds the index and emits retrieved source per I/O call site.
var lastRepoConfig RepoConfig

func runRetrieve(root, name string) []RetrievedSite {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir: root, Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load failed:", err)
		return nil
	}
	src := &srcIndex{files: map[string][]byte{}}
	var configFacts []ConfigFact
	funcs := map[string]*retFunc{}
	callers := map[string][]*retFunc{}
	ctorsByType := map[string][]*retFunc{}   // type -> functions returning it
	litsByType := map[string][]Snippet{}     // type -> composite literal sites
	// Assignments whose RHS produces the type, keyed by type AND by the field
	// or variable assigned. This is what reaches third-party clients: the
	// constructor lives in the dependency (redis.NewClient, stripe.New) so it
	// is absent from ctorsByType, but the CALL to it is in this repo along with
	// the options literal carrying the timeouts. Owner: "most of our issue is
	// with errant dependencies" -- and the configuration of those dependencies
	// is written here, which is the part that has to be retrieved. What those
	// options MEAN is library knowledge and belongs to the spec layer.
	assignsByType := map[string][]Snippet{}
	assignsByName := map[string][]Snippet{}

	rel := func(p *packages.Package, n ast.Node) (string, int) {
		pos := p.Fset.Position(n.Pos())
		r, _ := filepath.Rel(root, pos.Filename)
		return filepath.ToSlash(r), pos.Line
	}

	// pass 1: declarations, constructors, composite literals
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			fp, _ := rel(p, f)
			if strings.HasSuffix(fp, "_test.go") || strings.HasPrefix(fp, "vendor/") {
				continue
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				obj, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				file, line := rel(p, fd)
				doc := ""
				if fd.Doc != nil && len(fd.Doc.List) > 0 {
					doc = strings.TrimPrefix(fd.Doc.List[0].Text, "// ")
				}
				rf := &retFunc{id: obj.FullName(), name: fd.Name.Name, file: file,
					line: line, pkg: p, decl: fd, pkgName: p.Name,
					sig: obj.Type().String(), doc: doc, exported: obj.Exported(),
					takesCtx: typedHasCtxParam(p.TypesInfo, fd)}
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					if c, ok := x.(*ast.CallExpr); ok && isContextDeadline(p.TypesInfo, c) {
						rf.derivesDl = true
					}
					return true
				})
				funcs[rf.id] = rf

				// a function returning type T is a plausible construction site for T
				if sig, ok := obj.Type().(*types.Signature); ok && sig.Results() != nil {
					for i := 0; i < sig.Results().Len(); i++ {
						t := strings.TrimPrefix(sig.Results().At(i).Type().String(), "*")
						ctorsByType[t] = append(ctorsByType[t], rf)
					}
				}
			}
			ast.Inspect(f, func(x ast.Node) bool {
				if as, ok := x.(*ast.AssignStmt); ok {
					for i, rhs := range as.Rhs {
						call, isCall := rhs.(*ast.CallExpr)
						if !isCall || i >= len(as.Lhs) {
							continue
						}
						t := p.TypesInfo.TypeOf(call)
						if t == nil {
							continue
						}
						key := strings.TrimPrefix(t.String(), "*")
						file, line := rel(p, as)
						// Whole statement, so the options literal and its
						// timeout fields come with it.
						sn := Snippet{File: file, Line: line, Symbol: key,
							Source: src.text(p, as, as)}
						assignsByType[key] = append(assignsByType[key], sn)
						switch l := as.Lhs[i].(type) {
						case *ast.SelectorExpr:
							assignsByName[l.Sel.Name] = append(assignsByName[l.Sel.Name], sn)
						case *ast.Ident:
							assignsByName[l.Name] = append(assignsByName[l.Name], sn)
						}
					}
					return true
				}
				cl, ok := x.(*ast.CompositeLit)
				if !ok {
					return true
				}
				t := p.TypesInfo.TypeOf(cl)
				if t == nil {
					return true
				}
				key := strings.TrimPrefix(t.String(), "*")
				file, line := rel(p, cl)
				litsByType[key] = append(litsByType[key],
					Snippet{File: file, Line: line, Symbol: key, Source: src.text(p, cl, cl)})
				var fields []string
				for _, el := range cl.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok {
							fields = append(fields, id.Name)
						}
					}
				}
				if len(fields) > 0 {
					configFacts = append(configFacts, ConfigFact{Type: key, Fields: fields,
						File: file, Line: line, Source: src.text(p, cl, cl)})
				}
				return true
			})
		}
	}

	callees := map[string][]*retFunc{}

	// pass 2: caller edges by resolved identity
	for _, p := range pkgs {
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
				me := funcs[obj.FullName()]
				if me == nil {
					continue
				}
				inCallPos := map[ast.Node]bool{}
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					c, ok := x.(*ast.CallExpr)
					if !ok {
						return true
					}
					var callee *types.Func
					switch fun := c.Fun.(type) {
					case *ast.Ident:
						callee, _ = p.TypesInfo.Uses[fun].(*types.Func)
						inCallPos[fun] = true
					case *ast.SelectorExpr:
						callee, _ = p.TypesInfo.Uses[fun.Sel].(*types.Func)
						inCallPos[fun.Sel] = true
					}
					if callee != nil {
						if target, known := funcs[callee.FullName()]; known {
							callers[callee.FullName()] = append(callers[callee.FullName()], me)
							callees[me.id] = append(callees[me.id], target)
						}
					}
					return true
				})
				// A func named but NOT called is handed somewhere -- a router, a
				// struct field, a goroutine. That is mechanical evidence it may be
				// invoked indirectly, which is exactly what the panel needs to
				// judge whether "no in-repo callers" means "unreachable root".
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					id, ok := x.(*ast.Ident)
					if !ok || inCallPos[id] {
						return true
					}
					if fn, ok := p.TypesInfo.Uses[id].(*types.Func); ok {
						if rf := funcs[fn.FullName()]; rf != nil {
							rf.refAsVal++
						}
					}
					return true
				})
			}
		}
	}

	// ancestors walks upward by proximity only. No content inspection.
	// ancestors walks upward by proximity only, and REPORTS the functions it
	// stopped at rather than classifying them. No content inspection, no name
	// matching -- the roots go to the panel with their structural facts.
	ancestors := func(start *retFunc) ([]*retFunc, int, []RootFact, bool) {
		seen := map[string]bool{start.id: true}
		frontier := []*retFunc{start}
		var ordered []*retFunc
		var roots []RootFact
		rootSeen := map[string]bool{}
		depth := 0
		for ; depth < maxChainDepth && len(frontier) > 0; depth++ {
			var next []*retFunc
			for _, cur := range frontier {
				cs := callers[cur.id]
				if len(cs) == 0 {
					if !rootSeen[cur.id] {
						rootSeen[cur.id] = true
						roots = append(roots, cur.root())
					}
					continue
				}
				for _, c := range cs {
					if seen[c.id] {
						continue
					}
					seen[c.id] = true
					ordered = append(ordered, c)
					next = append(next, c)
				}
			}
			frontier = next
		}
		return ordered, depth, roots, len(frontier) > 0
	}

	lastRepoConfig = RepoConfig{Kind: "repo_config", Snapshot: name, Constructions: configFacts}

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
				obj, ok := info.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				me := funcs[obj.FullName()]
				if me == nil {
					continue
				}
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					c, ok := x.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := c.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					callee, _ := info.Uses[sel.Sel].(*types.Func)
					if callee == nil {
						return true
					}
					// A background-job registration surface (G3) or a classic
					// I/O call (G1); anything else is not a site.
					jobType := jobFrameworkType(callee)
					if jobType == "" && !ioMethods[callee.Name()] {
						return true
					}
					if jobType == "" && len(c.Args) == 0 && (callee.Name() == "Query" ||
						callee.Name() == "QueryRow" || callee.Name() == "Exec") {
						return true
					}
					file, line := rel(p, c)
					rs := RetrievedSite{
						Snapshot: name, File: file, Line: line,
						Symbol: fd.Name.Name, Method: callee.Name(),
						Receiver:  exprString(sel.X),
						CallSite:  src.text(p, c, c),
						Enclosing: src.text(p, fd, fd),
						ConstArgs: constArgs(info, c),
					}
					if t := info.TypeOf(sel.X); t != nil {
						rs.ClientType = strings.TrimPrefix(t.String(), "*")
						rs.Prov.ClientTypeKnown = true
					}
					if jobType != "" {
						rs.SiteKind = "background_job"
						// A package-function registration (time.NewTicker,
						// river.AddWorker) has no typed receiver value; carry
						// the canonical framework identity instead.
						if rs.ClientType == "" || rs.ClientType == "invalid type" {
							rs.ClientType = jobType
							rs.Prov.ClientTypeKnown = true
						}
					}

					anc, depth, roots, hitDepth := ancestors(me)
					rs.Prov = Provenance{
						CallersTotal: len(anc), AncestryDepth: depth,
						ChainRoots: roots, HitDepthCap: hitDepth,
						ClientTypeKnown: rs.Prov.ClientTypeKnown,
					}
					// Count the WHOLE traced ancestry, not just the emitted
					// slice: how many callers were shown is a budget artefact,
					// how many establish a deadline is the evidence.
					rs.Prov.AncestorsTraced = len(anc)
					for _, a := range anc {
						if a.derivesDl {
							rs.Prov.AncestorsWithDeadline++
						}
					}
					rs.Prov.EnclosingTakesCtx = me.takesCtx
					// Dataflow over DIRECT callers only. Tracing a ctx through
					// many frames needs interprocedural summaries; one hop is
					// where the evidence actually is and is sound to compute.
					for _, c := range callers[me.id] {
						rs.Prov.DirectCallers++
						if passesBoundedCtx(c.pkg.TypesInfo, c.decl, me.id, funcs) {
							rs.Prov.DirectPassingBounded++
						}
					}
					for _, a := range anc {
						if len(rs.Callers) >= maxCallersEmitted {
							rs.Prov.HitCallerBudget = true
							break
						}
						rs.Callers = append(rs.Callers, Snippet{
							File: a.file, Line: a.line, Symbol: a.name,
							Source: src.text(a.pkg, a.decl, a.decl),
							DerivesDeadline: a.derivesDl,
							PassesBoundedCtx: passesBoundedCtx(a.pkg.TypesInfo, a.decl, me.id, funcs)})
					}
					rs.Prov.CallersIncluded = len(rs.Callers)

					seenCallee := map[string]bool{me.id: true}
					down := callees[me.id]
					rs.Prov.CalleesTotal = len(down)
					for _, d := range down {
						if len(rs.Callees) >= maxCalleesEmitted {
							break
						}
						if seenCallee[d.id] {
							continue
						}
						seenCallee[d.id] = true
						rs.Callees = append(rs.Callees, Snippet{
							File: d.file, Line: d.line, Symbol: d.name,
							Source: src.text(d.pkg, d.decl, d.decl),
							DerivesDeadline: d.derivesDl})
					}
					rs.Prov.CalleesIncluded = len(rs.Callees)

					if rs.ClientType != "" {
						// Assignments first: they carry the options literal a
						// third-party constructor was called with, which is
						// where a dependency's timeouts are actually set.
						for _, s := range assignsByType[rs.ClientType] {
							if len(rs.Construction) >= maxCtorsEmitted {
								break
							}
							rs.Construction = append(rs.Construction, s)
						}
						for _, s := range litsByType[rs.ClientType] {
							if len(rs.Construction) >= maxCtorsEmitted {
								break
							}
							rs.Construction = append(rs.Construction, s)
						}
						for _, cf := range ctorsByType[rs.ClientType] {
							if len(rs.Construction) >= maxCtorsEmitted {
								break
							}
							rs.Construction = append(rs.Construction, Snippet{
								File: cf.file, Line: cf.line, Symbol: cf.name,
								Source: src.text(cf.pkg, cf.decl, cf.decl)})
						}
					}
					// Last resort: match on the receiver's field name. Weaker
					// than a type match and marked as such by leaving
					// ClientTypeKnown false, but it reaches `c.client` when the
					// type could not be resolved at all.
					if len(rs.Construction) == 0 {
						seg := rs.Receiver
						if i := strings.LastIndex(seg, "."); i >= 0 {
							seg = seg[i+1:]
						}
						for _, s := range assignsByName[seg] {
							if len(rs.Construction) >= maxCtorsEmitted {
								break
							}
							rs.Construction = append(rs.Construction, s)
						}
					}
					out = append(out, rs)
					return true
				})
			}
		}
	}
	return out
}

// RepoConfig is repo-scoped, not site-scoped, and that is the point. An
// http.Server's WriteTimeout bounds a handler but appears nowhere in that
// handler's caller chain, so upward retrieval can never reach it. Emitted once
// per repository, it lets propagation carry the bound FORWARD to every site the
// server governs, instead of trying to drag it backward into a packet.
type RepoConfig struct {
	Kind          string        `json:"kind"`
	Snapshot      string        `json:"snapshot_id"`
	Constructions []ConfigFact  `json:"constructions"`
}

type ConfigFact struct {
	Type   string   `json:"type"`
	Fields []string `json:"fields"`
	File   string   `json:"file"`
	Line   int      `json:"line"`
	Source string   `json:"source"`
}

// filterToFiles keeps only sites from the named files (exact path match,
// relative to the repo root). The incremental scan path re-retrieves just
// the files whose content hash changed; a prefix match here would quietly
// re-scan neighbours like db_extra.go alongside db.go.
func filterToFiles(sites []RetrievedSite, files []string) []RetrievedSite {
	if len(files) == 0 {
		return sites
	}
	want := make(map[string]bool, len(files))
	for _, f := range files {
		want[filepath.Clean(f)] = true
	}
	out := make([]RetrievedSite, 0, len(sites))
	for _, s := range sites {
		if want[filepath.Clean(s.File)] {
			out = append(out, s)
		}
	}
	return out
}

// siteKey mirrors rvl_index::site_key on the Rust side. Both must agree:
// the index and the retriever disagreeing about site identity is how a site
// silently disappears between passes.
func siteKey(s RetrievedSite) string {
	return fmt.Sprintf("%s:%d:%s:%s", s.File, s.Line, s.ClientType, s.Method)
}

// encodeRetrieved stamps the schema and site key on every record and writes
// the stream. One choke point: a record that reaches a consumer unstamped is
// a record no index can key.
func encodeRetrieved(w io.Writer, sites []RetrievedSite) {
	enc := json.NewEncoder(w)
	for _, s := range sites {
		s.Schema = PacketSchema
		s.SiteKey = siteKey(s)
		_ = enc.Encode(s)
	}
}

func emitRetrieved(sites []RetrievedSite) {
	encodeRetrieved(os.Stdout, sites)
}

func emitRepoConfig(rc RepoConfig) {
	_ = json.NewEncoder(os.Stdout).Encode(rc)
}
