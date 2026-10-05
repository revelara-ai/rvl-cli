// Package cache is an offline stub of github.com/patrickmn/go-cache: the
// identities the fixture needs, and no behaviour.
package cache

import "time"

const (
	NoExpiration      time.Duration = -1
	DefaultExpiration time.Duration = 0
)

type Cache struct{}

func New(defaultExpiration, cleanupInterval time.Duration) *Cache { return &Cache{} }
