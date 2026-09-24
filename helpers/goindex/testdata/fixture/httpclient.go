package fixture

import (
	nethttp "net/http"
)

// Package-level net/http calls: the receiver is the imported package, not a
// value, so the site's client type is the package path. The import is aliased
// on purpose: the identity is the path, never the spelling at the call site.
func FetchPackageLevel(url string) (*nethttp.Response, error) {
	return nethttp.Get(url)
}

// A method call on a client value keeps its type identity.
func FetchWithClient(url string) (*nethttp.Response, error) {
	c := &nethttp.Client{}
	return c.Get(url)
}
