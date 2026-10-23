package main

import (
	"fmt"
	"net/http"
	"os"
)

// fetch sends req on a client with no Timeout: the Go site the smoke scan
// must decide.
func fetch(req *http.Request) (*http.Response, error) {
	c := &http.Client{}
	return c.Do(req)
}

func main() {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	resp, err := fetch(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(resp.Status)
}
