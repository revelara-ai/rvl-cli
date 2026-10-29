package store

import (
	"context"
	"net/http"
)

type Client struct {
	hc   *http.Client
	base string
}

func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.hc.Do(req.WithContext(ctx))
}

func newRequest(ctx context.Context, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
}

func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	req, err := newRequest(ctx, c.base+path)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, req)
	return resp, err
}

func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.hc.Get(c.base + "/ping")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
