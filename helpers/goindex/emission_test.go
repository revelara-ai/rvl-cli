package main

import (
	"strings"
	"testing"
)

// G4 (po-av01j.5): the retriever inventories emission points — log
// statements, span/trace instrumentation, error-handling sites — as
// AGGREGATE packets: one per (enclosing function, framework, category),
// never one per log line. The category and count ride const_args.

func emissionSites(t *testing.T) []RetrievedSite {
	t.Helper()
	sites := runRetrieve("testdata/fixture", "fixture")
	if len(sites) == 0 {
		t.Fatal("fixture retrieval produced no sites (does the fixture build?)")
	}
	var out []RetrievedSite
	for _, s := range sites {
		if s.SiteKind == "emission_point" {
			out = append(out, s)
		}
	}
	return out
}

func constArgByName(args []ConstArg, name string) string {
	for _, a := range args {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

func TestLogStatementsAggregatePerFunctionFrameworkCategory(t *testing.T) {
	emissions := emissionSites(t)
	if len(emissions) == 0 {
		t.Fatal("no emission packets from the fixture")
	}

	// Emitter() calls slog.Logger methods three times: ONE aggregate with
	// count 3, not three packets. This is the volume-control contract — a
	// large backend repo must not produce tens of thousands of emission sites.
	var loggerAggs []RetrievedSite
	for _, s := range emissions {
		if s.Symbol == "Emitter" && s.ClientType == "log/slog.Logger" {
			loggerAggs = append(loggerAggs, s)
		}
	}
	if len(loggerAggs) != 1 {
		t.Fatalf("want ONE log/slog.Logger aggregate for Emitter, got %d: %+v",
			len(loggerAggs), loggerAggs)
	}
	agg := loggerAggs[0]
	if got := constArgByName(agg.ConstArgs, "emission_category"); got != "log" {
		t.Fatalf("emission_category = %q, want log", got)
	}
	if got := constArgByName(agg.ConstArgs, "emission_count"); got != "3" {
		t.Fatalf("emission_count = %q, want 3 (three logger calls in Emitter)", got)
	}
	// Site keys are stamped at the emit choke point, like every packet.
	var sb strings.Builder
	encodeRetrieved(&sb, []RetrievedSite{agg})
	if !strings.Contains(sb.String(), `"site_key":"`+agg.File+`:`) {
		t.Fatalf("emission packets must carry a site_key through the choke point: %s", sb.String())
	}

	// Package-level slog calls carry the package identity, separately.
	var pkgAggs []RetrievedSite
	for _, s := range emissions {
		if s.Symbol == "Emitter" && s.ClientType == "log/slog" {
			pkgAggs = append(pkgAggs, s)
		}
	}
	if len(pkgAggs) != 1 || constArgByName(pkgAggs[0].ConstArgs, "emission_count") != "2" {
		t.Fatalf("want one log/slog package aggregate with count 2, got %+v", pkgAggs)
	}
}

func TestRecoverWithNoEmissionIsASwallowAggregate(t *testing.T) {
	emissions := emissionSites(t)
	var swallows []RetrievedSite
	for _, s := range emissions {
		if s.ClientType == "recover_block" {
			swallows = append(swallows, s)
		}
	}
	if len(swallows) != 1 {
		t.Fatalf("want exactly one recover_block aggregate (Swallow), got %+v", swallows)
	}
	sw := swallows[0]
	if sw.Symbol != "Swallow" {
		t.Fatalf("swallow attributed to %q, want Swallow", sw.Symbol)
	}
	if got := constArgByName(sw.ConstArgs, "emission_category"); got != "error_capture" {
		t.Fatalf("emission_category = %q, want error_capture", got)
	}
	// Emitter() has no recover; Recovered() recovers AND logs, so it is not a
	// swallow. Only Swallow() qualifies — the combined mechanical fact
	// (recover present, no recognized emission in the function).
	for _, s := range swallows {
		if s.Symbol == "Recovered" {
			t.Fatal("a function that recovers AND logs is not a swallow")
		}
	}
}

func TestG1CallSitesAreUnchangedByTheEmissionPass(t *testing.T) {
	sites := runRetrieve("testdata/fixture", "fixture")
	byMethod := map[string]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind == "" {
			byMethod[s.Method] = s
		}
	}
	if _, ok := byMethod["QueryContext"]; !ok {
		t.Fatalf("G1 QueryContext site missing after the emission pass: %v", byMethod)
	}
	// Emission methods must never appear as G1 call sites.
	for m := range byMethod {
		if m == "Error" || m == "Warn" || m == "InfoContext" {
			t.Fatalf("a logger call leaked into the G1 site list as %q", m)
		}
	}
}
