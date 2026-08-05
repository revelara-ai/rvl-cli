package fixture

import (
	"context"
	"database/sql"
)

type Store struct{ db *sql.DB }

// pruneLimit exercises named-constant argument resolution (schema v2): the
// call below passes it where a literal would otherwise sit.
const pruneLimit = 50

func (s *Store) Load(ctx context.Context, id string) error {
	_, err := s.db.QueryContext(ctx, "SELECT 1 WHERE id=$1", id)
	return err
}

func (s *Store) Prune(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM items LIMIT $1", pruneLimit)
	return err
}

func Caller(s *Store) error {
	if err := s.Load(context.Background(), "x"); err != nil {
		return err
	}
	return s.Prune(context.Background())
}
