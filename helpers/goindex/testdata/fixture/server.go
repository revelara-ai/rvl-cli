package fixture

import "net/http"

// routes exercises the G2 server-entry inventory (po-av01j.3): ServeMux
// method registrations carrying literal paths, and a package-level
// http.Handle. Stdlib-only so the fixture keeps building offline.
func routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {})
	http.Handle("/metrics", mux)
	return mux
}
