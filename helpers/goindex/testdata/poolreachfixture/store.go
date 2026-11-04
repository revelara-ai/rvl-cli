package main

import (
	"context"
	"database/sql"
)

// The pool is opened in a constructor and returned beside an error, then
// wrapped in the repository's own type.

func openPool(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn) // pool
	if err != nil {
		return nil, err
	}
	return db, nil
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Count(ctx context.Context) {
	s.db.QueryRowContext(ctx, "SELECT count(*) FROM t") // site: count
}

func (s *Store) Compact() { // job: job_framework, by gocron.NewTask in main
	s.db.ExecContext(context.Background(), "VACUUM")
}

// inTx calls fn with a transaction, the shape of ExecuteInTx: the call
// site is in the literal, on the literal's parameter.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	return fn(tx)
}

func (s *Store) Rename(ctx context.Context) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE t SET n = 1") // site: tx
		return err
	})
}

// Exported's parameter can be passed by callers outside the repository.
func (s *Store) Exported(ctx context.Context, db *sql.DB) {
	db.ExecContext(ctx, "SELECT 1") // site: open
}

// spare is only ever nil: no pool reaches it.
var spare *sql.DB

func useSpare(ctx context.Context) {
	spare = nil
	spare.ExecContext(ctx, "SELECT 1") // site: nil
}
