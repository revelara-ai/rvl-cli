// goindex resolves the OFF-SITE evidence that decides whether a Go I/O call is
// bounded, and emits it as JSON for the labelling and feature pipelines.
//
// Why this exists
//
// Categorising 1119 panel abstentions by what the labeller said it was missing:
//
//	61.9%  ctx origin unknown
//	57.5%  client constructed elsewhere
//	49.0%  caller sets the deadline (ctx threaded in)
//	 4.6%  request/server deadline not visible
//	 2.4%  unclear whether this is I/O at all
//
// So for roughly 60% of Go call sites the deciding evidence is simply not in the
// enclosing function. Both the LLM teacher and the feature extractor were being
// asked to judge boundedness from a window that structurally cannot contain the
// answer, and both landed near chance (0.614 and 0.641 AUROC). This widens the
// window rather than tuning either of them.
//
// Why go/ast and not regex
//
// The factory claim is that adding a language costs one mechanical extractor, no
// reliability judgement. This is the test of that claim: a caller graph and
// composite-literal scan are ordinary compiler-frontend work, and Go ships the
// frontend. Nothing here decides whether a site is compliant -- it only reports
// what exists and where. The judgement stays in the panel and the model.
//
// Resolution is NAME-based, not type-based. Full go/types resolution needs every
// dependency present and compiling, which is false for a module-cache corpus.
// So a method is keyed by name and a receiver by its last selector segment. That
// is approximate: two types with a Do method collapse together. The output marks
// how many distinct candidates a lookup matched so downstream can discount
// ambiguous resolutions rather than trust them silently.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Site is one I/O call site plus the off-site evidence bearing on it.
type Site struct {
	File     string `json:"file_path"`
	Line     int    `json:"line_number"`
	Func     string `json:"symbol"`
	Receiver string `json:"receiver"`
	Method   string `json:"func"`

	// Local evidence (what the old single-function window could already see).
	CtxParam     bool `json:"ctx_param"`      // enclosing func takes a context
	CtxLocalDl   bool `json:"ctx_local_dl"`   // WithTimeout/WithDeadline in this func
	CtxBackground bool `json:"ctx_background"` // context.Background/TODO at the call

	// Caller evidence: resolves "the deadline is set by whoever calls me".
	CallerCount   int  `json:"caller_count"`
	CallerBounded int  `json:"caller_bounded"` // callers deriving a deadline first
	CallerCtxOnly int  `json:"caller_ctx_only"`// callers that just re-thread a ctx
	CallerUnknown bool `json:"caller_unknown"` // no caller found in this repo

	// Transitive ancestry. One level up resolved almost nothing -- only 2.3% of
	// sites had an immediate caller deriving a deadline -- because in Go the
	// deadline, when it exists, is established near the entrypoint and threaded
	// down many frames. The important consequence is that a COMPLETE search
	// finding no deadline is not missing evidence, it is positive evidence of an
	// unbounded call, and that flips a large block of abstentions into decidable
	// verdicts.
	AncestorBounded  bool `json:"ancestor_bounded"`   // a deadline anywhere up-chain
	AncestorDepth    int  `json:"ancestor_depth"`     // frames searched before deciding
	ReachedEntry     bool `json:"reached_entry"`      // main/handler/goroutine root reached
	ChainComplete    bool `json:"chain_complete"`     // every path terminated in-repo
	ChainTruncated   bool `json:"chain_truncated"`    // hit depth cap or external caller

	// Client evidence: resolves "the timeout is on the client, built elsewhere".
	ClientType       string `json:"client_type"`
	ClientTimeouts   []string `json:"client_timeouts"`   // field names set at construction
	ClientPhaseOnly  bool   `json:"client_phase_only"`   // only Dial/TLSHandshake bounds
	ClientCandidates int    `json:"client_candidates"`   // >1 means ambiguous resolution
}

// Timeout-ish field names, split by what they actually bound. The distinction is
// load-bearing and the panel already found it: retryablehttp transports that set
// only DialTimeout and TLSHandshakeTimeout bound the CONNECTION phase and leave
// the response read unbounded, which is a violation the regex rule scored as a
// pass. Reporting the field names lets the model learn that difference instead of
// having it hard-coded here.
var phaseOnlyFields = map[string]bool{
	"DialTimeout": true, "TLSHandshakeTimeout": true, "KeepAlive": true,
	"ExpectContinueTimeout": true, "IdleConnTimeout": true,
}

var wholeCallFields = map[string]bool{
	"Timeout": true, "ResponseHeaderTimeout": true, "ReadTimeout": true,
	"WriteTimeout": true, "RequestTimeout": true, "ReadHeaderTimeout": true,
	"DialTimeout_": false,
}

// I/O methods worth indexing. Kept aligned with scripts/12_go_corpus.py.
var ioMethods = map[string]bool{
	"Query": true, "QueryRow": true, "Exec": true,
	"QueryContext": true, "QueryRowContext": true, "ExecContext": true,
	"Get": true, "Post": true, "Do": true, "Head": true, "Send": true,
}

type funcInfo struct {
	decl       *ast.FuncDecl
	file       string
	hasCtx     bool
	derivesDl  bool
	callees    map[string]bool
}

type indexer struct {
	fset    *token.FileSet
	funcs   map[string][]*funcInfo // func or method name -> declarations
	callers map[string][]*funcInfo // callee name -> functions calling it
	fields  map[string][]string    // struct field name -> declared type strings
	ctors   map[string][]string    // type name -> timeout field names set anywhere
	root    string
}

func newIndexer(root string) *indexer {
	return &indexer{
		fset: token.NewFileSet(), root: root,
		funcs:   map[string][]*funcInfo{},
		callers: map[string][]*funcInfo{},
		fields:  map[string][]string{},
		ctors:   map[string][]string{},
	}
}

func skipDir(name string) bool {
	switch name {
	case ".git", ".claude", "vendor", "node_modules", "testdata", "third_party", "examples", "example":
		return true
	}
	return false
}

func typeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeString(t.X)
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + typeString(t.Elt)
	}
	return ""
}

// callName reduces a call expression to the name we index by: the method name
// for a selector call, the identifier for a plain call.
func callName(c *ast.CallExpr) (recv, name string) {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return "", f.Name
	case *ast.SelectorExpr:
		return exprString(f.X), f.Sel.Name
	}
	return "", ""
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.CallExpr:
		_, n := callName(t)
		return n + "()"
	case *ast.IndexExpr:
		return exprString(t.X)
	}
	return ""
}

func derivesDeadline(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		c, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		if r, m := callName(c); r == "context" && (m == "WithTimeout" || m == "WithDeadline") {
			found = true
			return false
		}
		return true
	})
	return found
}

func usesBackground(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		c, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		if r, m := callName(c); r == "context" && (m == "Background" || m == "TODO") {
			found = true
			return false
		}
		return true
	})
	return found
}

func hasCtxParam(fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		if strings.Contains(typeString(p.Type), "Context") {
			return true
		}
	}
	return false
}

func funcKey(fd *ast.FuncDecl) string { return fd.Name.Name }

// maxChainDepth caps the upward walk. Deep enough to reach a handler or main in
// ordinary Go layering, shallow enough that a pathological graph cannot stall
// the index. Hitting it sets ChainTruncated, so a capped search is never
// reported as a complete one.
var maxChainDepth = 12

// entrypointish reports whether a function is a plausible root of a request or
// process: nothing calls it from application code, so the search can honestly
// terminate there rather than admitting it ran out of graph.
func entrypointish(name string) bool {
	switch name {
	case "main", "init", "ServeHTTP", "Run", "Start", "Execute":
		return true
	}
	return strings.HasSuffix(name, "Handler") || strings.HasPrefix(name, "Handle") ||
		strings.HasSuffix(name, "Middleware")
}

// ancestry walks callers upward from fn, breadth-first, cycle-safe.
//
// Returns whether any ancestor derives a deadline, how deep the search went,
// whether it terminated at plausible entrypoints, and whether it was truncated.
// The distinction between "complete and found nothing" and "truncated" is the
// whole point: only the former licenses an unbounded verdict.
func (ix *indexer) ancestry(fn *funcInfo) (bounded bool, depth int, reachedEntry bool, truncated bool) {
	seen := map[*funcInfo]bool{fn: true}
	frontier := []*funcInfo{fn}

	for depth = 0; depth < maxChainDepth && len(frontier) > 0; depth++ {
		var next []*funcInfo
		for _, cur := range frontier {
			callers := ix.callers[cur.decl.Name.Name]
			if len(callers) == 0 {
				// Nothing in-repo calls this. Either a genuine root, or a caller
				// that lives outside the indexed source.
				if entrypointish(cur.decl.Name.Name) {
					reachedEntry = true
				} else if cur != fn {
					truncated = true
				}
				continue
			}
			for _, c := range callers {
				if seen[c] {
					continue
				}
				seen[c] = true
				if c.derivesDl {
					return true, depth + 1, reachedEntry, truncated
				}
				if entrypointish(c.decl.Name.Name) {
					reachedEntry = true
					continue // a root bounds the search; do not walk past it
				}
				next = append(next, c)
			}
		}
		frontier = next
	}
	if len(frontier) > 0 {
		truncated = true // ran out of depth with work still queued
	}
	return false, depth, reachedEntry, truncated
}

// pass1 records every function, the call graph, struct field types, and the
// timeout fields set at any composite literal construction.
func (ix *indexer) pass1() error {
	return filepath.Walk(ix.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(ix.fset, path, nil, 0)
		if perr != nil {
			return nil // unparseable file: skip, do not fail the run
		}
		rel, _ := filepath.Rel(ix.root, path)
		rel = filepath.ToSlash(rel)

		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Body == nil {
					continue
				}
				fi := &funcInfo{decl: decl, file: rel, hasCtx: hasCtxParam(decl),
					derivesDl: derivesDeadline(decl.Body), callees: map[string]bool{}}
				ast.Inspect(decl.Body, func(x ast.Node) bool {
					if c, ok := x.(*ast.CallExpr); ok {
						if _, n := callName(c); n != "" {
							fi.callees[n] = true
						}
					}
					return true
				})
				k := funcKey(decl)
				ix.funcs[k] = append(ix.funcs[k], fi)
				for callee := range fi.callees {
					ix.callers[callee] = append(ix.callers[callee], fi)
				}
			case *ast.GenDecl:
				ix.scanTypes(decl)
			}
		}
		// Composite literals anywhere: Client{Timeout: ...}, Options{ReadTimeout: ...}
		ast.Inspect(f, func(x ast.Node) bool {
			cl, ok := x.(*ast.CompositeLit)
			if !ok || cl.Type == nil {
				return true
			}
			tname := typeString(cl.Type)
			if tname == "" {
				return true
			}
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if phaseOnlyFields[key.Name] || wholeCallFields[key.Name] {
					ix.ctors[tname] = appendUnique(ix.ctors[tname], key.Name)
				}
			}
			return true
		})
		return nil
	})
}

func (ix *indexer) scanTypes(decl *ast.GenDecl) {
	for _, spec := range decl.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			continue
		}
		for _, fld := range st.Fields.List {
			t := typeString(fld.Type)
			for _, nm := range fld.Names {
				ix.fields[nm.Name] = appendUnique(ix.fields[nm.Name], t)
			}
		}
	}
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// resolveClient maps a receiver expression to a declared type and the timeout
// fields seen at that type's construction sites. Name-based, so it reports how
// many candidate types matched.
func (ix *indexer) resolveClient(recv string) (string, []string, int) {
	seg := recv
	if i := strings.LastIndex(recv, "."); i >= 0 {
		seg = recv[i+1:]
	}
	cands := ix.fields[seg]
	if len(cands) == 0 {
		// receiver may itself be a package-level var of a known ctor type
		if to, ok := ix.ctors[seg]; ok {
			return seg, to, 1
		}
		return "", nil, 0
	}
	var timeouts []string
	chosen := cands[0]
	for _, t := range cands {
		short := t
		if i := strings.LastIndex(t, "."); i >= 0 {
			short = t[i+1:]
		}
		for _, key := range []string{t, short} {
			if to, ok := ix.ctors[key]; ok {
				chosen = t
				for _, f := range to {
					timeouts = appendUnique(timeouts, f)
				}
			}
		}
	}
	return chosen, timeouts, len(cands)
}

// pass2 walks I/O call sites and attaches the resolved off-site evidence.
func (ix *indexer) pass2() []Site {
	var out []Site
	for _, infos := range ix.funcs {
		for _, fi := range infos {
			ast.Inspect(fi.decl.Body, func(x ast.Node) bool {
				c, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				recv, method := callName(c)
				if recv == "" || !ioMethods[method] {
					return true
				}
				// Zero-arg Query/Exec is url.Query(), not a database call.
				if len(c.Args) == 0 && (method == "Query" || method == "QueryRow" || method == "Exec") {
					return true
				}
				pos := ix.fset.Position(c.Pos())

				s := Site{
					File: fi.file, Line: pos.Line, Func: fi.decl.Name.Name,
					Receiver: recv, Method: method,
					CtxParam: fi.hasCtx, CtxLocalDl: fi.derivesDl,
					CtxBackground: usesBackground(c),
				}

				for _, caller := range ix.callers[fi.decl.Name.Name] {
					s.CallerCount++
					if caller.derivesDl {
						s.CallerBounded++
					} else if caller.hasCtx {
						s.CallerCtxOnly++
					}
				}
				s.CallerUnknown = s.CallerCount == 0

				s.AncestorBounded, s.AncestorDepth, s.ReachedEntry, s.ChainTruncated =
					ix.ancestry(fi)
				// Complete means: the walk ended by exhausting real callers or
				// arriving at roots, never by running out of depth or leaving the
				// indexed source. Only then does "no deadline found" mean "no
				// deadline exists".
				s.ChainComplete = !s.ChainTruncated

				s.ClientType, s.ClientTimeouts, s.ClientCandidates = ix.resolveClient(recv)
				whole := false
				for _, f := range s.ClientTimeouts {
					if wholeCallFields[f] {
						whole = true
					}
				}
				s.ClientPhaseOnly = len(s.ClientTimeouts) > 0 && !whole

				out = append(out, s)
				return true
			})
		}
	}
	return out
}

func main() {
	root := flag.String("root", ".", "repository root to index")
	name := flag.String("name", "", "snapshot id (defaults to base name of root)")
	typed := flag.Bool("typed", false, "type-accurate resolution via go/packages (repo must build)")
	retrieve := flag.Bool("retrieve", false, "emit retrieved SOURCE (callers, construction) instead of verdict-ish facts")
	files := flag.String("files", "", "comma-separated repo-relative files; emit packets only for these (incremental reload path)")
	schemaOnly := flag.Bool("packet-schema", false, "print the emitted packet schema version and exit")
	flag.IntVar(&maxCallersEmitted, "max-callers", 4, "callers to include per site (sweep axis)")
	flag.IntVar(&maxCtorsEmitted, "max-ctors", 2, "construction sites to include (sweep axis)")
	flag.IntVar(&maxCalleesEmitted, "max-callees", 4, "in-repo callees to include (sweep axis)")
	flag.IntVar(&maxSnippetBytes, "max-snippet", 2400, "byte cap per snippet (sweep axis)")
	flag.IntVar(&maxChainDepth, "max-depth", 12, "upward ancestry depth (sweep axis)")
	flag.Parse()

	// Lets a consumer negotiate before paying for a load.
	if *schemaOnly {
		fmt.Println(PacketSchema)
		return
	}

	if *retrieve {
		abs2, _ := filepath.Abs(*root)
		snap := *name
		if snap == "" {
			snap = filepath.Base(abs2)
		}
		sites, modules := runRetrieveAll(abs2, snap)
		// ABSTAIN, never a silent zero (po-av01j.131). No module means goindex
		// had nothing to load, which is a different claim from "loaded the code
		// and found no client calls". Returning an empty stream with exit 0 for
		// both made a monorepo scan report Go as scanned and clean when Go was
		// never looked at. Exit 3 is the helper ABSTAIN code rvlscan reads
		// (po-av01j.102); rustindex already does this for an unloadable cargo
		// workspace and this is the same charter: no heuristic tier, abstain
		// rather than guess.
		if modules == 0 {
			fmt.Fprintf(os.Stderr,
				"goindex: no go.mod under %s, so there is no module to load; goindex abstains "+
					"rather than reporting an empty scan as a clean one. If this is a monorepo, "+
					"each service's go.mod is discovered automatically -- none was found here.\n",
				abs2)
			os.Exit(3)
		}
		if *files != "" {
			sites = filterToFiles(sites, strings.Split(*files, ","))
		}
		emitRetrieved(sites)
		emitRepoConfig(lastRepoConfig)
		fmt.Fprintf(os.Stderr, "%s: %d retrieved sites\n", snap, len(sites))
		return
	}

	abs, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad root:", err)
		os.Exit(1)
	}
	snapshot := *name
	if snapshot == "" {
		snapshot = filepath.Base(abs)
	}

	var sites []Site
	var nfuncs, nctors int
	if *typed {
		sites = runTyped(abs, snapshot)
	} else {
		ix := newIndexer(abs)
		if err := ix.pass1(); err != nil {
			fmt.Fprintln(os.Stderr, "index failed:", err)
			os.Exit(1)
		}
		sites = ix.pass2()
		nfuncs, nctors = len(ix.funcs), len(ix.ctors)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, s := range sites {
		_ = enc.Encode(struct {
			Snapshot string `json:"snapshot_id"`
			Site
		}{snapshot, s})
	}
	fmt.Fprintf(os.Stderr, "%s: %d sites (funcs=%d ctors=%d)\n",
		snapshot, len(sites), nfuncs, nctors)
}
