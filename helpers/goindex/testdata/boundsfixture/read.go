package boundsfixture

import (
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
)

const maxBody = 1 << 20

// The whole body, no limit.
func ReadUnbounded(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}

// A wrapper that is not a limit.
func ReadBuffered(resp *http.Response) ([]byte, error) {
	r := bufio.NewReader(resp.Body)
	return ioutil.ReadAll(r)
}

// The limit is written inline.
func ReadLimitedInline(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// The limit is on a local the read goes through.
func ReadLimitedLocal(resp *http.Response) ([]byte, error) {
	body := io.LimitReader(resp.Body, maxBody)
	return io.ReadAll(body)
}

// The limit is assigned back to the field the read goes through.
func ReadMaxBytes(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	return io.ReadAll(r.Body)
}

// An unbuffered channel is a rendezvous, not an unbounded queue: the sender
// blocks until a receiver is ready. It must not be emitted.
func Rendezvous() chan int {
	return make(chan int)
}
