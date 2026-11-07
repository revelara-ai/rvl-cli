module protectivefixture

go 1.21

// Offline stub (see stubrate/): gives the limiter its real package identity
// without any network dep.
require golang.org/x/time v0.0.0

replace golang.org/x/time => ./stubrate
