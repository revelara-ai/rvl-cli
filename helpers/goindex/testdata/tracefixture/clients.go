// Package tracefixture holds one bounded net/http.Client and several unbounded
// ones in the same package. Each call site must be judged by the client that
// reaches its receiver, never by the bounded one declared elsewhere.
package tracefixture

import (
	"net/http"
	"net/http/httptest"
	"time"
)

func zeroLocal(url string) (*http.Response, error) {
	c := &http.Client{}
	return c.Get(url)
}

func boundedLocal(url string) (*http.Response, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	return c.Get(url)
}

func defaultClient(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

func zeroValueVar(url string) (*http.Response, error) {
	var c http.Client
	return c.Get(url)
}

func mutatedAfter(url string) (*http.Response, error) {
	c := &http.Client{}
	c.Timeout = 3 * time.Second
	return c.Get(url)
}

func aliased(url string) (*http.Response, error) {
	c := &http.Client{}
	d := c
	return d.Get(url)
}

func fromParam(c *http.Client, url string) (*http.Response, error) {
	return c.Get(url)
}

func newBounded() (*http.Client, error) {
	return &http.Client{Timeout: 9 * time.Second}, nil
}

func fromCtor(url string) (*http.Response, error) {
	c, err := newBounded()
	if err != nil {
		return nil, err
	}
	return c.Get(url)
}

// A struct field set once, in a keyed literal.
type API struct{ hc *http.Client }

func NewAPI() *API { return &API{hc: &http.Client{Timeout: 7 * time.Second}} }

func (a *API) fetch(url string) (*http.Response, error) { return a.hc.Get(url) }

// A struct field set by assignment, with no timeout.
type Loose struct{ hc *http.Client }

func (l *Loose) init() { l.hc = &http.Client{} }

func (l *Loose) fetch(url string) (*http.Response, error) { return l.hc.Get(url) }

// A client parameter: every call of the function is visible, and each passes
// a client built with a Timeout.
func fromBoundedParam(c *http.Client, url string) (*http.Response, error) {
	return c.Get(url)
}

func callsBoundedParam(url string) {
	fromBoundedParam(&http.Client{Timeout: 4 * time.Second}, url)
	c := &http.Client{Timeout: 6 * time.Second}
	fromBoundedParam(c, url)
}

// The function travels as a value and is called through a function-typed
// parameter, one hop on from where it was handed over.
type searcher struct{ hc *http.Client }

func newSearcher() *searcher {
	s := &searcher{}
	s.hc = &http.Client{Timeout: 8 * time.Second}
	return s
}

type searchFn func(*http.Client, string) (*http.Response, error)

func (s *searcher) run(url string, search searchFn) (*http.Response, error) {
	return s.forward(url, search)
}

func (s *searcher) forward(url string, search searchFn) (*http.Response, error) {
	return search(s.hc, url)
}

func (s *searcher) viaFuncValue(c *http.Client, url string) (*http.Response, error) {
	return c.Get(url)
}

func (s *searcher) start(url string) { s.run(url, s.viaFuncValue) }

// The function is stored, so it can be called from anywhere: its parameter
// stays untraced however bounded the one visible call is.
func storedFunc(c *http.Client, url string) (*http.Response, error) {
	return c.Get(url)
}

var stored = storedFunc

func callsStored(url string) { storedFunc(&http.Client{Timeout: time.Second}, url) }

// An exported method can satisfy an interface declared anywhere.
type Fetcher struct{}

func (Fetcher) ExportedMethod(c *http.Client, url string) (*http.Response, error) {
	return c.Get(url)
}

func callsExported(url string) {
	Fetcher{}.ExportedMethod(&http.Client{Timeout: time.Second}, url)
}

// The client is the result of a call this repository cannot read: through a
// function value, or into a package that returns another package's type.
type factory struct{ HTTPClient func() *http.Client }

func fromFuncValue(f factory, url string) (*http.Response, error) {
	c := f.HTTPClient()
	return c.Get(url)
}

func fromDependency(srv *httptest.Server, url string) (*http.Response, error) {
	c := srv.Client()
	return c.Get(url)
}
