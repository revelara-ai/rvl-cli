package boundsfixture

import (
	"database/sql"
	"time"
)

type Config struct{ MaxOpen int }

type Store struct{ db *sql.DB }

var global *sql.DB

// No setter in scope, and the value never leaves the function.
func OpenUnbounded(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}

// Literal and constant-expression bounds: values the retriever can read.
func OpenLiteral(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db.Ping()
}

// A bound set through a non-constant: a name, not a value.
func OpenNamed(dsn string, cfg Config) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(cfg.MaxOpen)
	return db.Ping()
}

// The value is returned without a local name.
func OpenReturned(dsn string) (*sql.DB, error) {
	return sql.Open("postgres", dsn)
}

// The value is named, then leaves inside a struct.
func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// The value is assigned to a field and bounded through the same expression.
func (s *Store) Reopen(dsn string) (err error) {
	s.db, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	s.db.SetMaxIdleConns(2)
	return nil
}

// The value is assigned to a package variable.
func OpenGlobal(dsn string) (err error) {
	global, err = sql.Open("postgres", dsn)
	return err
}
