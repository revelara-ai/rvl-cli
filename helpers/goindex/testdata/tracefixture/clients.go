// Package tracefixture holds one bounded net/http.Client and several unbounded
// ones in the same package. Each call site must be judged by the client that
// reaches its receiver, never by the bounded one declared elsewhere.
package tracefixture

import (
	"net/http"
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
