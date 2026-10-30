// Constructions that are call sites: the crypto, TLS and database
// constructions whose arguments ARE the security setting.
//
// A broken cipher (des.NewCipher), a hash used for integrity (md5.Sum), a TLS
// config that skips verification and a database opened with a credential in
// its DSN violate at the line that builds them. The call that later uses the
// value (Client.Do, db.Query) shows none of it, so these constructions are
// retrieved as call sites of their own. Like ioMethods these tables select
// what to surface, never what it means: whether md5 here guards integrity or
// keys a cache is a judgment made downstream.
package main

import (
	"go/ast"
	"go/types"
	"sort"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

// constructionCall is one row of construction_calls: a package function whose
// call is a call site, with the package as its client type
// (crypto/des.NewCipher).
type constructionCall struct {
	Package string `json:"package"`
	Func    string `json:"func"`
}

// constructionField is one row of construction_fields: a struct field whose
// setting is a call site, in a composite literal (tls.Config{MinVersion: v})
// or an assignment (cfg.InsecureSkipVerify = v). The client type is the
// struct's type and the method is the field.
type constructionField struct {
	Type  string `json:"type"`
	Field string `json:"field"`
}

// isConstructionCall reports whether callee is in construction_calls.
func isConstructionCall(callee *types.Func) bool {
	if !packageFunc(callee) {
		return false
	}
	for _, c := range extractor.ConstructionCalls {
		if callee.Pkg().Path() == c.Package && callee.Name() == c.Func {
			return true
		}
	}
	return false
}

func isConstructionField(typeName, field string) bool {
	for _, f := range extractor.ConstructionFields {
		if f.Type == typeName && f.Field == field {
			return true
		}
	}
	return false
}

// structName is the name of t, or of what t points to: crypto/tls.Config.
func structName(t types.Type) string {
	if t == nil {
		return ""
	}
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	return t.String()
}

// guard is the condition under which the code at n runs: that of the
// innermost if statement whose branch holds n, as written, negated in its else
// branch. "" when no if holds it; the walk stops at a function, since a
// closure built under an if can run anywhere. params are the parameters of
// that function the condition reads by bare name (`insecure`, not the `o` of
// `o.Insecure`), so a caller's opt-out can be told from a local's value.
func guard(p *packages.Package, src *srcIndex, f *ast.File, n ast.Node) (cond string, params []string) {
	path, _ := astutil.PathEnclosingInterval(f, n.Pos(), n.End())
	var test ast.Expr
	for i, up := range path {
		switch up := up.(type) {
		case *ast.FuncLit:
			return cond, guardParams(p, test, up.Type)
		case *ast.FuncDecl:
			return cond, guardParams(p, test, up.Type)
		case *ast.IfStmt:
			if i == 0 || test != nil {
				continue
			}
			text := src.text(p, up.Cond, up.Cond)
			switch path[i-1] {
			case up.Body:
				cond, test = text, up.Cond
			case up.Else:
				cond, test = "!("+text+")", up.Cond
			}
		}
	}
	return cond, nil
}

// guardParams are the parameters of fn that test reads by bare name, sorted.
func guardParams(p *packages.Package, test ast.Expr, fn *ast.FuncType) []string {
	if test == nil || fn.Params == nil {
		return nil
	}
	own := map[types.Object]bool{}
	for _, field := range fn.Params.List {
		for _, name := range field.Names {
			own[p.TypesInfo.Defs[name]] = true
		}
	}
	rooted := map[ast.Expr]bool{}
	seen := map[string]bool{}
	var out []string
	ast.Inspect(test, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			rooted[n.X] = true
		case *ast.Ident:
			if obj := p.TypesInfo.Uses[n]; obj != nil && own[obj] && !rooted[n] && !seen[n.Name] {
				seen[n.Name] = true
				out = append(out, n.Name)
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

// collectConstructionFields returns one call site per construction_fields
// setting in scanned code, package-level declarations included: a TLS config
// is often a package variable.
func collectConstructionFields(pkgs []*packages.Package, src *srcIndex, root, snapshot string) []RetrievedSite {
	var out []RetrievedSite
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		info := p.TypesInfo
		for _, f := range p.Syntax {
			if !scannedFile(p, root, f) {
				continue
			}
			rel := relPath(root, p.Fset.Position(f.Pos()).Filename)
			for _, d := range f.Decls {
				fd, _ := d.(*ast.FuncDecl)
				site := func(at ast.Node, typeName, field, receiver string, snippet ast.Node, value ast.Expr) {
					s := RetrievedSite{
						Snapshot: snapshot, File: rel,
						Line:       p.Fset.Position(at.Pos()).Line,
						Method:     field,
						Receiver:   receiver,
						ClientType: typeName,
						CallSite:   src.text(p, snippet, snippet),
						Callers:    []Snippet{},
						Callees:    []Snippet{},
						ConstArgs:  []ConstArg{valueObservation(p, src, field, 0, value)},
						Prov:       Provenance{ClientTypeKnown: true},
					}
					s.Guard, s.GuardParams = guard(p, src, f, at)
					if fd != nil {
						s.Symbol = fd.Name.Name
						s.Enclosing = src.text(p, fd, fd)
					}
					out = append(out, s)
				}
				ast.Inspect(d, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.CompositeLit:
						typeName := structName(info.TypeOf(n))
						for _, e := range n.Elts {
							kv, ok := e.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							if key, ok := kv.Key.(*ast.Ident); ok && isConstructionField(typeName, key.Name) {
								site(kv, typeName, key.Name, "", n, kv.Value)
							}
						}
					case *ast.AssignStmt:
						if len(n.Lhs) != len(n.Rhs) {
							return true
						}
						for i, lhs := range n.Lhs {
							sel, ok := lhs.(*ast.SelectorExpr)
							if !ok {
								continue
							}
							typeName := structName(info.TypeOf(sel.X))
							if isConstructionField(typeName, sel.Sel.Name) {
								site(n, typeName, sel.Sel.Name, exprString(sel.X), n, n.Rhs[i])
							}
						}
					}
					return true
				})
			}
		}
	}
	return out
}
