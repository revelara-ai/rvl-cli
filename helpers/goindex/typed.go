// Type-accurate resolution via go/packages.
//
// The name-based index in main.go could not test the wider-packet hypothesis:
// 23.4% of the reference repo's func decls share a name and `Valid` alone appears 174 times,
// so the caller graph was mostly spurious edges and the upward walk wandered
// across unrelated subsystems. The evidence it produced failed its own sanity
// check (ancestor_bounded predicted violates at 50%, i.e. chance).
//
// Here every function is keyed by (*types.Func).FullName(), which carries the
// package path and receiver type, so `Valid` on 174 types is 174 distinct keys.
// Callee identity comes from types.Info.Uses rather than an identifier match,
// and the receiver's type comes from types.Info.TypeOf rather than its spelling.
//
// The cost is that the package must type-check, so this only runs on repos that
// build. That is the trade: fewer repos, but a caller graph that means something.
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

type typedFunc struct {
	id        string
	name      string
	file      string
	decl      *ast.FuncDecl
	hasCtx    bool
	derivesDl bool
}

type typedIndex struct {
	root    string
	fset    *token.FileSet
	funcs   map[string]*typedFunc
	callers map[string][]*typedFunc // callee id -> callers
	ctors   map[string][]string     // fully-qualified type -> timeout fields set
}

// isContextFunc reports a call to context.WithTimeout / WithDeadline resolved
// through the type checker, so a local helper named WithTimeout cannot spoof it.
func isContextDeadline(info *types.Info, c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "context" {
		return false
	}
	return fn.Name() == "WithTimeout" || fn.Name() == "WithDeadline"
}

func isContextRoot(info *types.Info, c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "context" {
		return false
	}
	return fn.Name() == "Background" || fn.Name() == "TODO"
}

func typedHasCtxParam(info *types.Info, fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		t := info.TypeOf(p.Type)
		if t != nil && strings.HasSuffix(t.String(), "context.Context") {
			return true
		}
	}
	return false
}

func loadTyped(root string) (*typedIndex, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports |
			packages.NeedDeps,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	ix := &typedIndex{root: root, funcs: map[string]*typedFunc{},
		callers: map[string][]*typedFunc{}, ctors: map[string][]string{}}

	var typed, broken int
	for _, p := range pkgs {
		if p.TypesInfo == nil || p.Fset == nil {
			broken++
			continue
		}
		typed++
		ix.fset = p.Fset
		info := p.TypesInfo
		for _, f := range p.Syntax {
			pos := p.Fset.Position(f.Pos())
			rel, _ := filepath.Rel(root, pos.Filename)
			rel = filepath.ToSlash(rel)
			if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "vendor/") {
				continue
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				obj, ok := info.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				tf := &typedFunc{id: obj.FullName(), name: fd.Name.Name, file: rel, decl: fd,
					hasCtx: typedHasCtxParam(info, fd)}
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					c, ok := x.(*ast.CallExpr)
					if !ok {
						return true
					}
					if isContextDeadline(info, c) {
						tf.derivesDl = true
					}
					return true
				})
				ix.funcs[tf.id] = tf
			}
			// composite literals: exact type, so http.Client{Timeout:} is not
			// confused with some local Client type of the same short name.
			ast.Inspect(f, func(x ast.Node) bool {
				cl, ok := x.(*ast.CompositeLit)
				if !ok {
					return true
				}
				t := info.TypeOf(cl)
				if t == nil {
					return true
				}
				key := strings.TrimPrefix(t.String(), "*")
				for _, el := range cl.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					id, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					if phaseOnlyFields[id.Name] || wholeCallFields[id.Name] {
						ix.ctors[key] = appendUnique(ix.ctors[key], id.Name)
					}
				}
				return true
			})
		}
	}

	// second pass: caller edges keyed by resolved callee identity
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
				me := ix.funcs[obj.FullName()]
				if me == nil {
					continue
				}
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					c, ok := x.(*ast.CallExpr)
					if !ok {
						return true
					}
					var callee *types.Func
					switch fun := c.Fun.(type) {
					case *ast.Ident:
						callee, _ = info.Uses[fun].(*types.Func)
					case *ast.SelectorExpr:
						callee, _ = info.Uses[fun.Sel].(*types.Func)
					}
					if callee != nil {
						id := callee.FullName()
						if _, known := ix.funcs[id]; known {
							ix.callers[id] = append(ix.callers[id], me)
						}
					}
					return true
				})
			}
		}
	}
	fmt.Fprintf(os.Stderr, "  typed packages: %d ok, %d unusable; %d funcs, %d ctor types\n",
		typed, broken, len(ix.funcs), len(ix.ctors))
	return ix, nil
}

func (ix *typedIndex) ancestry(fn *typedFunc) (bounded bool, depth int, entry bool, truncated bool) {
	seen := map[string]bool{fn.id: true}
	frontier := []*typedFunc{fn}
	for depth = 0; depth < maxChainDepth && len(frontier) > 0; depth++ {
		var next []*typedFunc
		for _, cur := range frontier {
			cs := ix.callers[cur.id]
			if len(cs) == 0 {
				if entrypointish(cur.name) {
					entry = true
				} else if cur != fn {
					truncated = true
				}
				continue
			}
			for _, c := range cs {
				if seen[c.id] {
					continue
				}
				seen[c.id] = true
				if c.derivesDl {
					return true, depth + 1, entry, truncated
				}
				if entrypointish(c.name) {
					entry = true
					continue
				}
				next = append(next, c)
			}
		}
		frontier = next
	}
	if len(frontier) > 0 {
		truncated = true
	}
	return false, depth, entry, truncated
}


// typedSites walks I/O call sites with resolved receiver types.
func runTyped(root, name string) []Site {
	ix, err := loadTyped(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "typed load failed:", err)
		return nil
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir: root, Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil
	}
	var out []Site
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
				me := ix.funcs[obj.FullName()]
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
					if callee == nil || !ioMethods[callee.Name()] {
						return true
					}
					if len(c.Args) == 0 && (callee.Name() == "Query" ||
						callee.Name() == "QueryRow" || callee.Name() == "Exec") {
						return true
					}
					pos := p.Fset.Position(c.Pos())
					rel, _ := filepath.Rel(root, pos.Filename)

					s := Site{File: filepath.ToSlash(rel), Line: pos.Line,
						Func: fd.Name.Name, Method: callee.Name(),
						CtxParam: me.hasCtx, CtxLocalDl: me.derivesDl}

					// receiver: exact type, not its spelling
					s.Receiver = exprString(sel.X)
					if t := info.TypeOf(sel.X); t != nil {
						s.ClientType = strings.TrimPrefix(t.String(), "*")
						if to, ok := ix.ctors[s.ClientType]; ok {
							s.ClientTimeouts = to
						}
						s.ClientCandidates = 1 // exact
					}
					whole := false
					for _, fl := range s.ClientTimeouts {
						if wholeCallFields[fl] {
							whole = true
						}
					}
					s.ClientPhaseOnly = len(s.ClientTimeouts) > 0 && !whole

					ast.Inspect(c, func(y ast.Node) bool {
						if cc, ok := y.(*ast.CallExpr); ok && isContextRoot(info, cc) {
							s.CtxBackground = true
						}
						return true
					})

					for _, caller := range ix.callers[me.id] {
						s.CallerCount++
						if caller.derivesDl {
							s.CallerBounded++
						} else if caller.hasCtx {
							s.CallerCtxOnly++
						}
					}
					s.CallerUnknown = s.CallerCount == 0
					s.AncestorBounded, s.AncestorDepth, s.ReachedEntry, s.ChainTruncated =
						ix.ancestry(me)
					s.ChainComplete = !s.ChainTruncated

					out = append(out, s)
					return true
				})
			}
		}
	}
	return out
}
