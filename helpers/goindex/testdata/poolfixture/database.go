package main

import "database/sql"

// The shape of crowdsec's pkg/database/database.go: sql.Open in a function
// that returns the pool beside an error, the error returned on its own path.

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn) // seed: db
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	return db, nil
}

type Client struct {
	DB *sql.DB // reached: DB
}

func NewClient(dsn string) (*Client, error) {
	pool, openErr := openDB(dsn) // reached: pool; not: openErr
	if openErr != nil {
		return nil, openErr
	}
	return &Client{DB: pool}, nil
}

func (c *Client) Flush() {
	c.DB.Exec("DELETE FROM alerts")
}

func main() {
	c, err := NewClient("file::memory:") // not: c, err
	if err != nil {
		return
	}
	go c.Flush()
	serve(nil)
}
