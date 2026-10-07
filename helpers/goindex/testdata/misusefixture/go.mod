module misusefixture

go 1.22

// Offline stub (see stubprom/): gives the fixture the real Prometheus client
// package identity for type-driven metric-registration detection without any
// network dep.
require github.com/prometheus/client_golang v1.20.0

replace github.com/prometheus/client_golang => ./stubprom
