package boundsfixture

import (
	"time"

	cache "github.com/patrickmn/go-cache"
)

// A named constant that means "never expire": resolved, so it is a value.
func CacheForever() *cache.Cache {
	return cache.New(cache.NoExpiration, 0)
}

// A real TTL, as a folded constant expression.
func CacheWithTTL() *cache.Cache {
	return cache.New(5*time.Minute, 10*time.Minute)
}

// A TTL from a variable: a name.
func CacheNamedTTL(ttl time.Duration) *cache.Cache {
	return cache.New(ttl, time.Minute)
}
