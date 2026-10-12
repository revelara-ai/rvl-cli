package fixture

import (
	"io"
	"io/ioutil"
	nethttp "net/http"
	"os"
)

// io.ReadAll is a package function, so the call names no client. What bounds
// it is the reader it is given: a response body blocks on the network until
// the request's context or the client's timeout ends it, and a file does not.
// Each function below reads from a different origin.

// The reader is a field of a net/http.Response.
func ReadBodyUnbounded(url string) ([]byte, error) {
	resp, err := nethttp.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// The body is copied to a local and wrapped before the read. The origin is
// still the response body.
func ReadBodyWrapped(c *nethttp.Client, url string) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body := resp.Body
	return io.ReadAll(io.LimitReader(body, 1<<20))
}

// A server reads the body of the request it was given.
func ReadRequestBody(r *nethttp.Request) ([]byte, error) {
	return ioutil.ReadAll(r.Body)
}

// The reader is a value of a concrete type.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// The reader is an interface value handed in by a caller, so the origin is
// not known here.
func ReadAny(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
