package main

import "testing"

// G2 (po-av01j.3): server-entry registrations are inventoried as sites
// stamped site_kind "server_entry", with the framework identity as
// client_type and the literal route path riding const_args. They must never
// leak into the G1 client-call lane, and G1 sites must never carry the kind.
func TestServerEntrySitesAreInventoriedFromTheFixture(t *testing.T) {
	sites := runRetrieve("testdata/fixture", "fixture")
	if len(sites) == 0 {
		t.Fatal("fixture retrieval produced no sites (does the fixture build?)")
	}
	var entries, g1 []RetrievedSite
	for _, s := range sites {
		if s.SiteKind == siteKindServerEntry {
			entries = append(entries, s)
		} else {
			// The fixture also exercises the G3/G4 lanes; only unknown kinds fail.
			if s.SiteKind != "" && s.SiteKind != "background_job" && s.SiteKind != "emission_point" {
				t.Fatalf("unexpected site_kind %q on %s:%d", s.SiteKind, s.File, s.Line)
			}
			if s.SiteKind == "" {
				g1 = append(g1, s)
			}
		}
	}
	// Two ServeMux.HandleFunc registrations + one package-level http.Handle.
	if len(entries) != 3 {
		t.Fatalf("want 3 server-entry sites, got %d: %+v", len(entries), entries)
	}
	// The G1 lane still sees the fixture's DB calls, and nothing else changed.
	if len(g1) == 0 {
		t.Fatal("G1 sites must still be emitted alongside server entries")
	}

	byPath := map[string]RetrievedSite{}
	for _, e := range entries {
		if e.ClientType != "net/http.ServeMux" && e.ClientType != "net/http" {
			t.Fatalf("server-entry client_type must be the framework identity, got %q", e.ClientType)
		}
		for _, a := range e.ConstArgs {
			byPath[a.Value] = e
		}
	}
	// Literal route paths ride the existing const_args machinery.
	if _, ok := byPath[`"/healthz"`]; !ok {
		t.Fatalf("the /healthz registration must carry its path as a const arg: %v", byPath)
	}
	if got := byPath[`"/healthz"`]; got.Method != "HandleFunc" {
		t.Fatalf("method must be the registration function, got %q", got.Method)
	}
	// The package-level http.Handle registration resolves without a receiver type.
	var pkgLevel bool
	for _, e := range entries {
		if e.ClientType == "net/http" && e.Method == "Handle" {
			pkgLevel = true
		}
	}
	if !pkgLevel {
		t.Fatalf("package-level http.Handle must be inventoried: %+v", entries)
	}
}

// The framework table is typed and conservative: known router types match
// their registration verbs, versioned module paths normalize to one row, and
// anything unknown abstains (no emission) rather than guessing.
func TestServerEntryFrameworkTableMatchesTypedRouters(t *testing.T) {
	cases := []struct {
		typeStr, method string
		want            bool
	}{
		{"github.com/gin-gonic/gin.Engine", "GET", true},
		{"github.com/gin-gonic/gin.RouterGroup", "Use", true},
		{"github.com/labstack/echo/v4.Echo", "GET", true}, // /v4 normalizes away
		{"github.com/go-chi/chi/v5.Mux", "Get", true},
		{"github.com/go-chi/chi/v5.Router", "Use", true},
		{"github.com/gorilla/mux.Router", "HandleFunc", true},
		{"net/http.ServeMux", "HandleFunc", true},
		// Unknown types and non-registration methods abstain.
		{"github.com/some/router.Router", "GET", false},
		{"github.com/gin-gonic/gin.Engine", "Run", false},
		{"net/http.Client", "Get", false},
	}
	for _, c := range cases {
		methods, known := serverEntryFrameworks[normalizeVersionedType(c.typeStr)]
		got := known && methods[c.method]
		if got != c.want {
			t.Errorf("%s.%s: got %v, want %v", c.typeStr, c.method, got, c.want)
		}
	}
}
