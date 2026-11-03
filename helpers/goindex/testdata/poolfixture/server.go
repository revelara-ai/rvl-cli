package main

import (
	"database/sql"
	"database/sql/driver"
	"net/http"
)

// The shape of nakama's server/db.go: the pool is opened inside a helper,
// returned, returned again by the exported wrapper, and only then handed to
// the code that serves requests.

func dbConnect(c driver.Connector, create bool) *sql.DB {
	if create {
		probe := sql.OpenDB(c)
		probe.Close()
	}
	db := sql.OpenDB(c) // seed: db
	db.SetMaxOpenConns(10)
	return db
}

func DbConnect(c driver.Connector) *sql.DB {
	return dbConnect(c, false)
}

type ApiServer struct {
	db *sql.DB // reached: db
}

func (s *ApiServer) GetAccount(w http.ResponseWriter, r *http.Request) {
	s.db.QueryRowContext(r.Context(), "SELECT 1")
}

func serve(c driver.Connector) {
	db := DbConnect(c) // reached: db
	s := &ApiServer{db: db}
	http.HandleFunc("/account", s.GetAccount)
}
