package main

import (
	"sort"
	"strings"
	"testing"
)

// The unsized-construction inventory: one packet per construction of an
// object that takes a bound (a pool, a cache, a whole-body read), listing the
// setters and options OBSERVED in the constructing function. Which of them is
// a bound is spec knowledge, so nothing here asserts a verdict.

func unsizedBySymbol(t *testing.T) map[string]RetrievedSite {
	t.Helper()
	sites, scan := runRetrieveAll("testdata/boundsfixture", "bounds")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	out := map[string]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind != siteKindUnsized {
			continue
		}
		if _, dup := out[s.Symbol]; dup {
			t.Fatalf("two unsized packets for %s: one per construction", s.Symbol)
		}
		out[s.Symbol] = s
	}
	if len(out) == 0 {
		t.Fatal("no unsized-construction packets (does the fixture build?)")
	}
	return out
}

// observed renders the non-aggregate const_args as "name=value/how".
func observed(s RetrievedSite) []string {
	var out []string
	for _, a := range s.ConstArgs {
		if a.How != "aggregate" {
			out = append(out, a.Name+"="+a.Value+"/"+a.How)
		}
	}
	sort.Strings(out)
	return out
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestPoolConstructionCarriesTheSettersSeenInScope(t *testing.T) {
	sites := unsizedBySymbol(t)

	u := sites["OpenUnbounded"]
	if u.ClientType != "database/sql.DB" || u.Method != "Open" {
		t.Fatalf("identity = %s.%s, want database/sql.DB.Open", u.ClientType, u.Method)
	}
	if got := constArgByName(u.ConstArgs, "bound_class"); got != "pool" {
		t.Fatalf("bound_class = %q, want pool", got)
	}
	if constArgByName(u.ConstArgs, "bound_escapes") != "" {
		t.Fatalf("a value used only as a receiver does not escape: %+v", u.ConstArgs)
	}
	for _, o := range observed(u) {
		if strings.HasPrefix(o, "Set") {
			t.Fatalf("OpenUnbounded sets nothing, got %v", observed(u))
		}
	}

	lit := observed(sites["OpenLiteral"])
	if !has(lit, "SetMaxOpenConns=25/literal") {
		t.Fatalf("a literal bound is a value: %v", lit)
	}
	if !has(lit, "SetConnMaxLifetime=300000000000/named_constant") {
		t.Fatalf("a folded constant expression is a value: %v", lit)
	}
}

func TestNonConstantBoundIsANameNotAValue(t *testing.T) {
	named := observed(unsizedBySymbol(t)["OpenNamed"])
	if !has(named, "SetMaxOpenConns=cfg.MaxOpen/name") {
		t.Fatalf("a non-constant bound is reported as a name and never resolved: %v", named)
	}
}

func TestEscapingValueCarriesTypeLevelSetters(t *testing.T) {
	sites := unsizedBySymbol(t)
	for _, sym := range []string{"OpenReturned", "NewStore", "OpenGlobal", "Reopen"} {
		s, ok := sites[sym]
		if !ok {
			t.Fatalf("no packet for %s", sym)
		}
		if constArgByName(s.ConstArgs, "bound_escapes") == "" {
			t.Fatalf("%s: the value leaves the function and must say so: %+v", sym, s.ConstArgs)
		}
		// A setter the fixture calls on *sql.DB somewhere is evidence to
		// abstain on, labeled so it can never read as an in-scope bound.
		if !has(observed(s), "SetMaxOpenConns=/type") {
			t.Fatalf("%s: want the type-level setter observation, got %v", sym, observed(s))
		}
	}
	// A setter on the same expression the value was assigned to is in scope.
	if got := observed(sites["Reopen"]); !has(got, "SetMaxIdleConns=2/literal") {
		t.Fatalf("Reopen bounds s.db in scope: %v", got)
	}
	// A value that stays in scope gets no type-level observations.
	for _, o := range observed(sites["OpenUnbounded"]) {
		if strings.HasSuffix(o, "/type") {
			t.Fatalf("type-level observations are for escaping values only: %v", o)
		}
	}
}

func TestCacheConstructionCarriesItsPositionalArguments(t *testing.T) {
	sites := unsizedBySymbol(t)
	forever := sites["CacheForever"]
	if forever.ClientType != "github.com/patrickmn/go-cache.Cache" ||
		constArgByName(forever.ConstArgs, "bound_class") != "cache" {
		t.Fatalf("cache identity/class wrong: %+v", forever)
	}
	if got := observed(forever); !has(got, "arg0=-1/named_constant") {
		t.Fatalf("NoExpiration resolves to its value: %v", got)
	}
	if got := observed(sites["CacheWithTTL"]); !has(got, "arg0=300000000000/named_constant") {
		t.Fatalf("a constant TTL is a value: %v", got)
	}
	if got := observed(sites["CacheNamedTTL"]); !has(got, "arg0=ttl/name") {
		t.Fatalf("a variable TTL is a name: %v", got)
	}
}

func TestReadCarriesTheCallsItsArgumentPassesThrough(t *testing.T) {
	sites := unsizedBySymbol(t)
	u := sites["ReadUnbounded"]
	if u.ClientType != "io.ReadAll" || constArgByName(u.ConstArgs, "bound_class") != "read" {
		t.Fatalf("read identity/class wrong: %+v", u)
	}
	if got := observed(u); len(got) != 0 {
		t.Fatalf("a bare body passes through nothing: %v", got)
	}
	if got := observed(sites["ReadBuffered"]); len(got) != 1 || got[0] != "bufio.NewReader=/call" {
		t.Fatalf("a wrapper is reported whatever it is; the spec decides: %v", got)
	}
	if sites["ReadBuffered"].ClientType != "io/ioutil.ReadAll" {
		t.Fatalf("the deprecated spelling keeps its own identity: %s", sites["ReadBuffered"].ClientType)
	}
	for sym, want := range map[string]string{
		"ReadLimitedInline": "io.LimitReader=/call",
		"ReadLimitedLocal":  "io.LimitReader=/call",
		"ReadMaxBytes":      "net/http.MaxBytesReader=/call",
	} {
		if got := observed(sites[sym]); !has(got, want) {
			t.Fatalf("%s: want %s, got %v", sym, want, got)
		}
	}
}

func TestUnbufferedChannelIsNotAnUnsizedConstruction(t *testing.T) {
	if s, ok := unsizedBySymbol(t)["Rendezvous"]; ok {
		t.Fatalf("make(chan T) is a rendezvous, not an unbounded queue: %+v", s)
	}
}

func TestUnsizedPacketsCarryASiteKeyAndStayOutOfTheCensus(t *testing.T) {
	sites, scan := runRetrieveAll("testdata/boundsfixture", "bounds")
	if scan.Census.Candidates != 0 {
		t.Fatalf("the fixture has no G1 call site; unsized packets are not candidates: %d",
			scan.Census.Candidates)
	}
	var sb strings.Builder
	encodeRetrieved(&sb, sites)
	if !strings.Contains(sb.String(), `"site_kind":"unsized_construction"`) ||
		!strings.Contains(sb.String(), `:database/sql.DB:Open","lang"`) {
		t.Fatalf("unsized packets must ride the stream through the choke point: %s", sb.String())
	}
}

func TestBoundConstructorTableIsValidated(t *testing.T) {
	bad := `{"io_methods":["Get"],"emission_frameworks":[{"match":"exact","path":"log","category":"log"}],
	  "bound_constructors":[{"class":"pool","package":"database/sql","func":""}]}`
	if _, err := parseExtractorCorpus([]byte(bad)); err == nil {
		t.Fatal("a bound_constructors entry with no func must be rejected")
	}
}
