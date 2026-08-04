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
// packet per log line. A polaris-sized repo must not produce tens of
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
func emissionFramework(pkgPath string) (string, bool) {
	switch {
	case pkgPath == "log/slog" || strings.HasPrefix(pkgPath, "log/slog/"):
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

// functionEmissions aggregates one function's emission calls, plus the
// recover_block swallow fact: a function that calls recover() and emits
// NOTHING recognized is an error path with no capture — the combined
// mechanical fact RC-027's capture-vs-swallow question needs. A function
// that recovers AND emits is instrumented, not a swallow.
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

	if recoverCount > 0 && !sawEmission {
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
