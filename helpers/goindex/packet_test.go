package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A packet stream must be self-describing and uniquely keyed: those two
// properties are what every downstream consumer (index, eval join, factory)
// depends on, and neither is recoverable after the fact.
func TestEmittedPacketsCarrySchemaAndUniqueSiteKey(t *testing.T) {
	sites := []RetrievedSite{
		{File: "svc/x.go", Line: 306, ClientType: "drive.Service", Method: "Do"},
		{File: "svc/x.go", Line: 306, ClientType: "http.Client", Method: "Do"},
	}
	var sb strings.Builder
	encodeRetrieved(&sb, sites)

	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(sb.String()), "\n") {
		var got RetrievedSite
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("emitted line is not valid JSON: %v", err)
		}
		if got.Schema != PacketSchema {
			t.Fatalf("packet_schema = %d, want %d", got.Schema, PacketSchema)
		}
		if got.SiteKey == "" {
			t.Fatal("site_key must be stamped on every packet")
		}
		keys = append(keys, got.SiteKey)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 packets, got %d", len(keys))
	}
	if keys[0] == keys[1] {
		t.Fatalf("two sites at one file:line must not share a key: %q", keys[0])
	}
}

// Schema v2 (po-av01j.19): constant-valued arguments at the call site are
// evidence — the libcurl/POSIX discrimination lives in enum constants, and the
// TS pool-timeout precision fix needed this same shape — and every site
// carries the macro flag (mechanical for C/C++, always false for Go).
func TestRetrievedSitesCarryConstArgsAndMacroFlag(t *testing.T) {
	if PacketSchema != 2 {
		t.Fatalf("const_args/macro_expansion are the v2 contract; PacketSchema = %d", PacketSchema)
	}
	sites := runRetrieve("testdata/fixture", "fixture")
	if len(sites) == 0 {
		t.Fatal("fixture retrieval produced no sites (does the fixture build?)")
	}
	byMethod := map[string]RetrievedSite{}
	for _, s := range sites {
		byMethod[s.Method] = s
		if s.MacroExpansion {
			t.Fatalf("Go has no macros; macro_expansion must be false on %s", s.File)
		}
	}

	// A string literal argument resolves as a literal const arg.
	q, ok := byMethod["QueryContext"]
	if !ok {
		t.Fatalf("expected a QueryContext site, have %v", byMethod)
	}
	lit := findConstArg(q.ConstArgs, 1)
	if lit == nil || lit.How != "literal" || lit.Value != `"SELECT 1 WHERE id=$1"` {
		t.Fatalf("QueryContext arg 1 must resolve as a literal const arg, got %+v", q.ConstArgs)
	}

	// A named package-level constant resolves through the type checker.
	p, ok := byMethod["ExecContext"]
	if !ok {
		t.Fatalf("expected an ExecContext site, have %v", byMethod)
	}
	named := findConstArg(p.ConstArgs, 2)
	if named == nil || named.How != "named_constant" || named.Value != "50" {
		t.Fatalf("ExecContext arg 2 must resolve as named_constant 50, got %+v", p.ConstArgs)
	}

	// Non-constant arguments (ctx, a variable id) must NOT be reported.
	if findConstArg(q.ConstArgs, 0) != nil || findConstArg(q.ConstArgs, 2) != nil {
		t.Fatalf("non-constant args must not become const args: %+v", q.ConstArgs)
	}
}

// G3 (po-av01j.4): background-job registrations ride the SAME packet stream,
// marked by site_kind. Detection is TYPE-driven — the callee must resolve into
// the scheduler/queue framework's package — so a same-named local method is
// never guessed at, and ordinary client calls stay classic (empty site_kind).
func TestBackgroundJobRegistrationsAreEmittedWithSiteKind(t *testing.T) {
	sites := runRetrieve("testdata/fixture", "fixture")
	if len(sites) == 0 {
		t.Fatal("fixture retrieval produced no sites (does the fixture build?)")
	}
	byMethod := map[string][]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind == "background_job" {
			byMethod[s.Method] = append(byMethod[s.Method], s)
		} else if s.SiteKind != "" && s.SiteKind != siteKindServerEntry && s.SiteKind != "emission_point" {
			// The fixture also exercises the G2/G4 lanes; only unknown kinds fail.
			t.Fatalf("unexpected site_kind %q on %s:%d", s.SiteKind, s.File, s.Line)
		}
	}

	// The two cron registrations, carrying the scheduler's resolved identity.
	adds := byMethod["AddFunc"]
	if len(adds) != 2 {
		t.Fatalf("want 2 cron AddFunc background_job sites, got %+v", byMethod)
	}
	symbols := map[string]bool{}
	for _, j := range adds {
		if j.ClientType != "github.com/robfig/cron/v3.Cron" {
			t.Fatalf("cron registration must carry the scheduler identity, got %q", j.ClientType)
		}
		symbols[j.Symbol] = true
	}
	if !symbols["scheduleHourly"] || !symbols["scheduleDaily"] {
		t.Fatalf("job site symbols must be the registering functions, got %v", symbols)
	}

	// The ticker worker loop: a package-level callee, canonical identity.
	ticks := byMethod["NewTicker"]
	if len(ticks) != 1 || ticks[0].ClientType != "time.Ticker" {
		t.Fatalf("want one ticker worker-loop site with client_type time.Ticker, got %+v", ticks)
	}

	// Classic G1 sites are untouched by the extension.
	for _, s := range sites {
		if s.Method == "QueryContext" && s.SiteKind != "" {
			t.Fatalf("classic call sites must keep an empty site_kind, got %q", s.SiteKind)
		}
	}
	// cron.Start is registration-adjacent but NOT a registration surface:
	// abstain-by-omission, never guess.
	if len(byMethod["Start"]) != 0 {
		t.Fatalf("Start is not a registration; got %+v", byMethod["Start"])
	}
}

func findConstArg(args []ConstArg, index int) *ConstArg {
	for i := range args {
		if args[i].Index == index {
			return &args[i]
		}
	}
	return nil
}

// The incremental path (po-3t3oj.14) asks for packets from a subset of files.
// Filtering must be exact-path, never prefix or substring, or a shallow
// reload silently pulls in unrelated sites.
func TestFilterToFilesIsExactPath(t *testing.T) {
	sites := []RetrievedSite{
		{File: "svc/db.go", Line: 1},
		{File: "svc/db_extra.go", Line: 2},
		{File: "other/db.go", Line: 3},
	}
	got := filterToFiles(sites, []string{"svc/db.go"})
	if len(got) != 1 || got[0].File != "svc/db.go" {
		t.Fatalf("want exactly svc/db.go, got %+v", got)
	}
	// no filter = everything
	if len(filterToFiles(sites, nil)) != 3 {
		t.Fatal("an empty file list must not filter anything out")
	}
}
