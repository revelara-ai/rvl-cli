// The candidate-extractor tables, loaded from corpus data (po-av01j.219).
//
// ioMethods and the emission framework list used to be code constants. They
// are judgment about what is worth looking at, they change rarely, and nothing
// measured their completeness -- so "94% resolved" on nats-server was a
// statement about these tables, not about the repo. They now live in
// extractor_corpus.json beside a known_unretrieved list, and the retrieval
// census counts what the tables leave out. reader_calls is the third
// retrieval table: package functions that read from a reader (io.ReadAll).
// construction_calls and construction_fields select the crypto, TLS and
// database constructions retrieved as call sites (construction.go).
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"go/types"
	"strings"
)

//go:embed extractor_corpus.json
var extractorCorpusJSON []byte

type frameworkEntry struct {
	Match    string `json:"match"` // "exact" or "prefix"
	Path     string `json:"path"`
	Category string `json:"category"`
}

type unretrievedEntry struct {
	Package string `json:"package"`
	Func    string `json:"func"`
	Why     string `json:"why"`
}

// readerCall names a package-level function that reads from the reader given
// as its first argument.
type readerCall struct {
	Package string `json:"package"`
	Func    string `json:"func"`
}

type extractorCorpus struct {
	IOMethods          []string            `json:"io_methods"`
	ReaderCalls        []readerCall        `json:"reader_calls"`
	EmissionFrameworks []frameworkEntry    `json:"emission_frameworks"`
	KnownUnretrieved   []unretrievedEntry  `json:"known_unretrieved"`
	BoundConstructors  []boundConstructor  `json:"bound_constructors"`
	ConstructionCalls  []constructionCall  `json:"construction_calls"`
	ConstructionFields []constructionField `json:"construction_fields"`
}

// parseExtractorCorpus is strict: a malformed table would change what is
// retrieved with nothing on the wire to say so, so it is an error, never a
// partial load.
func parseExtractorCorpus(raw []byte) (extractorCorpus, error) {
	var c extractorCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("extractor corpus: %w", err)
	}
	if len(c.IOMethods) == 0 || len(c.EmissionFrameworks) == 0 {
		return c, fmt.Errorf("extractor corpus: io_methods and emission_frameworks must be non-empty")
	}
	methods := map[string]bool{}
	for _, m := range c.IOMethods {
		methods[m] = true
	}
	for _, f := range c.EmissionFrameworks {
		if (f.Match != "exact" && f.Match != "prefix") || f.Path == "" || f.Category == "" {
			return c, fmt.Errorf("extractor corpus: bad emission framework entry %+v", f)
		}
	}
	readers := map[readerCall]bool{}
	for _, r := range c.ReaderCalls {
		if r.Package == "" || r.Func == "" {
			return c, fmt.Errorf("extractor corpus: bad reader_calls entry %+v", r)
		}
		readers[r] = true
	}
	constructions := map[constructionCall]bool{}
	for _, k := range c.ConstructionCalls {
		if k.Package == "" || k.Func == "" {
			return c, fmt.Errorf("extractor corpus: bad construction_calls entry %+v", k)
		}
		constructions[k] = true
	}
	for _, k := range c.ConstructionFields {
		if k.Type == "" || k.Field == "" {
			return c, fmt.Errorf("extractor corpus: bad construction_fields entry %+v", k)
		}
	}
	for _, u := range c.KnownUnretrieved {
		if u.Package == "" || u.Func == "" {
			return c, fmt.Errorf("extractor corpus: bad known_unretrieved entry %+v", u)
		}
		if readers[readerCall{u.Package, u.Func}] || constructions[constructionCall{u.Package, u.Func}] {
			return c, fmt.Errorf("extractor corpus: %s.%s is retrieved and in known_unretrieved",
				u.Package, u.Func)
		}
		// A surface cannot be both retrieved and counted as missed.
		if methods[u.Func] {
			return c, fmt.Errorf("extractor corpus: %s.%s is in io_methods and known_unretrieved",
				u.Package, u.Func)
		}
	}
	for _, b := range c.BoundConstructors {
		if !boundClasses[b.Class] || b.Package == "" || b.Func == "" {
			return c, fmt.Errorf("extractor corpus: bad bound_constructors entry %+v", b)
		}
	}
	return c, nil
}

func mustParseExtractorCorpus(raw []byte) extractorCorpus {
	c, err := parseExtractorCorpus(raw)
	if err != nil {
		panic(err)
	}
	return c
}

var extractor = mustParseExtractorCorpus(extractorCorpusJSON)

// ioMethods is the G1 candidate table: I/O methods worth indexing, by name.
var ioMethods = func() map[string]bool {
	m := make(map[string]bool, len(extractor.IOMethods))
	for _, name := range extractor.IOMethods {
		m[name] = true
	}
	return m
}()

// emissionFramework classifies a callee's PACKAGE into an emission category.
// First match wins, in corpus order.
func emissionFramework(pkgPath string) (string, bool) {
	for _, f := range extractor.EmissionFrameworks {
		if (f.Match == "exact" && pkgPath == f.Path) ||
			(f.Match == "prefix" && strings.HasPrefix(pkgPath, f.Path)) {
			return f.Category, true
		}
	}
	return "", false
}

// packageFunc reports whether callee is a package-level function, not a method.
func packageFunc(callee *types.Func) bool {
	if callee.Pkg() == nil {
		return false
	}
	sig, ok := callee.Type().(*types.Signature)
	return ok && sig.Recv() == nil
}

// isReaderCall reports whether callee is in the corpus's reader_calls table.
func isReaderCall(callee *types.Func) bool {
	if !packageFunc(callee) {
		return false
	}
	for _, r := range extractor.ReaderCalls {
		if callee.Pkg().Path() == r.Package && callee.Name() == r.Func {
			return true
		}
	}
	return false
}

// knownUnretrieved names a package-level function the corpus lists as I/O the
// tables do not retrieve, keyed "<import path>.<func>".
func knownUnretrieved(callee *types.Func) (string, bool) {
	if !packageFunc(callee) {
		return "", false
	}
	for _, u := range extractor.KnownUnretrieved {
		if callee.Pkg().Path() == u.Package && callee.Name() == u.Func {
			return u.Package + "." + u.Func, true
		}
	}
	return "", false
}

// RetrievalCensus is the retrieval denominator (po-av01j.219). Coverage says
// how many RETRIEVED sites resolved; this says how many call sites the
// extractor retrieved out of the ones that exist.
//
// CallsResolved is deliberately crude: every selector call in non-test code
// whose callee the type checker resolves to a function or method. Most are not
// I/O. It bounds the gap from above, and turns "the tables never looked" into
// a number. Unretrieved is the sharp half: calls the corpus knows ARE I/O that
// the tables did not retrieve.
type RetrievalCensus struct {
	Lang          string         `json:"lang"`
	CallsResolved int            `json:"calls_resolved"`
	Candidates    int            `json:"candidates"`
	Unretrieved   map[string]int `json:"unretrieved"`
}

func newRetrievalCensus() RetrievalCensus {
	return RetrievalCensus{Lang: Lang, Unretrieved: map[string]int{}}
}

func (c *RetrievalCensus) add(o RetrievalCensus) {
	c.CallsResolved += o.CallsResolved
	c.Candidates += o.Candidates
	for k, v := range o.Unretrieved {
		c.Unretrieved[k] += v
	}
}
