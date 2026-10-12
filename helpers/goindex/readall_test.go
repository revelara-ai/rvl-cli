package main

import (
	"strings"
	"testing"
)

// io.ReadAll is a package function: the call names no client, and what bounds
// it is the reader it is given. The site therefore carries where that reader
// comes from, so a spec can tell a network read from a file read.

func readAllSites(t *testing.T) map[string]RetrievedSite {
	t.Helper()
	sites, scan := runRetrieveAll("testdata/fixture", "fixture")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	got := map[string]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind == "" && s.Method == "ReadAll" {
			if _, dup := got[s.Symbol]; dup {
				t.Fatalf("two ReadAll call sites in %s", s.Symbol)
			}
			got[s.Symbol] = s
		}
	}
	return got
}

func TestReadAllOfAResponseBodyIsACallSiteWithTheReadersOrigin(t *testing.T) {
	s, ok := readAllSites(t)["ReadBodyUnbounded"]
	if !ok {
		t.Fatal("io.ReadAll(resp.Body) must be emitted as a call site")
	}
	if s.ClientType != "io" || !s.Prov.ClientTypeKnown {
		t.Fatalf("client_type = %q (known %v), want the package path io", s.ClientType, s.Prov.ClientTypeKnown)
	}
	if s.Receiver != "resp.Body" {
		t.Fatalf("receiver = %q, want the reader expression resp.Body", s.Receiver)
	}
	if s.FrameworkType != "net/http.Response.Body" {
		t.Fatalf("framework_type = %q, want the reader's origin net/http.Response.Body", s.FrameworkType)
	}
	if s.ConstructionScope != "receiver" || len(s.Construction) != 1 ||
		!strings.Contains(s.Construction[0].Source, "nethttp.Get(url)") {
		t.Fatalf("client_construction must be the call that produced the response, got scope %q %+v",
			s.ConstructionScope, s.Construction)
	}
	if !strings.HasSuffix(siteKey(s), ":io:ReadAll") {
		t.Fatalf("site key = %q", siteKey(s))
	}
}

func TestReadAllOriginIsFollowedThroughALocalAndAWrappingReader(t *testing.T) {
	s, ok := readAllSites(t)["ReadBodyWrapped"]
	if !ok {
		t.Fatal("io.ReadAll(io.LimitReader(body, n)) must be emitted")
	}
	if s.FrameworkType != "net/http.Response.Body" {
		t.Fatalf("framework_type = %q, want net/http.Response.Body through body := resp.Body and io.LimitReader",
			s.FrameworkType)
	}
	if s.Receiver != "io.LimitReader(body, 1 << 20)" {
		t.Fatalf("receiver = %q, want the reader expression", s.Receiver)
	}
}

func TestReadAllOriginsAreDistinctPerReader(t *testing.T) {
	got := readAllSites(t)
	for symbol, want := range map[string][2]string{
		"ReadRequestBody": {"io/ioutil", "net/http.Request.Body"},
		"ReadFile":        {"io", "os.File"},
		// An interface parameter: the origin is not known, and the site is
		// still emitted under the package path alone.
		"ReadAny": {"io", ""},
	} {
		s, ok := got[symbol]
		if !ok {
			t.Fatalf("%s: ReadAll site not emitted", symbol)
		}
		if s.ClientType != want[0] || s.FrameworkType != want[1] {
			t.Fatalf("%s: client_type %q framework_type %q, want %q and %q",
				symbol, s.ClientType, s.FrameworkType, want[0], want[1])
		}
	}
	if len(got) != 5 {
		t.Fatalf("want the five ReadAll calls of the fixture, got %d", len(got))
	}
}

func TestReadAllOriginGoesThroughAWrapperOfAConcreteType(t *testing.T) {
	// r := bufio.NewReader(resp.Body) has the concrete type bufio.Reader, and
	// the bytes still come from the response body.
	sites, _ := runRetrieveAll("testdata/boundsfixture", "bounds")
	want := map[string]string{
		"ReadUnbounded":     "net/http.Response.Body",
		"ReadBuffered":      "net/http.Response.Body",
		"ReadLimitedInline": "net/http.Response.Body",
		"ReadLimitedLocal":  "net/http.Response.Body",
		"ReadMaxBytes":      "net/http.Request.Body",
	}
	n := 0
	for _, s := range sites {
		if s.SiteKind != "" || s.Method != "ReadAll" {
			continue
		}
		n++
		if s.FrameworkType != want[s.Symbol] {
			t.Fatalf("%s: framework_type %q, want %q", s.Symbol, s.FrameworkType, want[s.Symbol])
		}
	}
	if n != len(want) {
		t.Fatalf("want %d ReadAll call sites, got %d", len(want), n)
	}
}

func TestAMethodNamedReadAllIsNotAReaderCall(t *testing.T) {
	// reader_calls is package-qualified: only the listed functions match,
	// never a method that shares the name.
	for _, r := range extractor.ReaderCalls {
		if r.Package == "" || r.Func == "" {
			t.Fatalf("bad reader_calls entry %+v", r)
		}
	}
	if ioMethods["ReadAll"] {
		t.Fatal("ReadAll must not be in io_methods, which matches a method name on any type")
	}
}
