package fixture

import (
	"io"
	nethttp "net/http"
)

// io.ReadAll(resp.Body) is the call po-av01j.149 found invisible: it is I/O,
// it exists, and the extractor tables do not retrieve it. The retrieval census
// must count it as existing-but-not-retrieved rather than leave it out of
// every number.
func ReadBodyUnbounded(url string) ([]byte, error) {
	resp, err := nethttp.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
