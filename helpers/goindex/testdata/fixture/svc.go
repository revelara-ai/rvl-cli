package fixture

import (
	"context"
	"database/sql"
)

type Store struct{ db *sql.DB }

func (s *Store) Load(ctx context.Context, id string) error {
	_, err := s.db.QueryContext(ctx, "SELECT 1 WHERE id=$1", id)
	return err
}

func Caller(s *Store) error {
	return s.Load(context.Background(), "x")
}
