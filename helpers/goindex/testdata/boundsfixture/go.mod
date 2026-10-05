module boundsfixture

go 1.21

// Offline stub (see stubgocache/): gives the fixture the real go-cache package
// identity for type-driven construction detection without any network dep.
require github.com/patrickmn/go-cache v2.1.0+incompatible

replace github.com/patrickmn/go-cache => ./stubgocache
