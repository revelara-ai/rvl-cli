package main

import (
	"strings"
	"testing"
)

// The misuse inventory for Go is one class, discarded_error: an error-typed
// call result assigned to the blank identifier. One aggregate per (function,
// callee), with the count in const_args. Whether a discard is legitimate is
// spec knowledge, so nothing here asserts a verdict.

func misuseByKey(t *testing.T) map[string]RetrievedSite {
	t.Helper()
	sites, scan := runRetrieveAll("testdata/misusefixture", "misuse")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	out := map[string]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind != siteKindMisuse {
			continue
		}
		key := s.Symbol + " " + s.ClientType
		if _, dup := out[key]; dup {
			t.Fatalf("two misuse packets for %s: one per function and callee", key)
		}
		out[key] = s
	}
	if len(out) == 0 {
		t.Fatal("no misuse packets (does the fixture build?)")
	}
	return out
}

func TestDiscardedErrorsAggregatePerFunctionAndCallee(t *testing.T) {
	sites := misuseByKey(t)

	rm, ok := sites["CleanUp os.Remove"]
	if !ok {
		t.Fatalf("no packet for the discarded os.Remove: %v", keysOf(sites))
	}
	if got := constArgByName(rm.ConstArgs, "misuse_class"); got != "discarded_error" {
		t.Fatalf("misuse_class = %q, want discarded_error", got)
	}
	if got := constArgByName(rm.ConstArgs, "misuse_count"); got != "2" {
		t.Fatalf("misuse_count = %q, want 2: two discards, one packet", got)
	}
	if rm.Method != "Remove" || rm.Line != 17 || !strings.Contains(rm.CallSite, "os.Remove(path)") {
		t.Fatalf("the packet sits on the first discard: %+v", rm)
	}
	if !rm.Prov.ClientTypeKnown {
		t.Fatalf("a type-resolved callee is a known identity: %+v", rm.Prov)
	}

	// A method is keyed by its receiver type, with no pointer star.
	if _, ok := sites["CleanUp os.File.Close"]; !ok {
		t.Fatalf("no packet for the discarded (*os.File).Close: %v", keysOf(sites))
	}
}

func TestDiscardOfTheErrorHalfOfATupleIsEmitted(t *testing.T) {
	sites := misuseByKey(t)
	if _, ok := sites["Parse strconv.Atoi"]; !ok {
		t.Fatalf("n, _ := strconv.Atoi(raw) discards an error: %v", keysOf(sites))
	}
	pair, ok := sites["Pair os.Remove"]
	if !ok || constArgByName(pair.ConstArgs, "misuse_count") != "2" {
		t.Fatalf("a parallel assignment discards each error: %+v", pair)
	}
}

func TestOnlyErrorTypedDiscardsAreEmitted(t *testing.T) {
	for key := range misuseByKey(t) {
		if strings.HasPrefix(key, "Decode ") || strings.HasPrefix(key, "Lookup ") {
			t.Fatalf("a kept error, a discarded bool and a discarded int are not discarded errors: %s", key)
		}
	}
}

func TestDiscardInAClosureBelongsToTheDeclaredFunction(t *testing.T) {
	sites := misuseByKey(t)
	if _, ok := sites["Flush misusefixture.store.flush"]; !ok {
		t.Fatalf("the deferred closure's discard is Flush's: %v", keysOf(sites))
	}
}

func TestDiscardThroughAFunctionValueHasNoResolvedIdentity(t *testing.T) {
	d, ok := misuseByKey(t)["Dynamic "+misuseDynamicCallee]
	if !ok {
		t.Fatalf("a call through a function value still discards an error: %v", keysOf(misuseByKey(t)))
	}
	if d.Prov.ClientTypeKnown {
		t.Fatalf("a function value is not a resolved callee: %+v", d.Prov)
	}
}

func TestMisusePacketsCarryASiteKeyAndStayOutOfTheCensus(t *testing.T) {
	sites, scan := runRetrieveAll("testdata/misusefixture", "misuse")
	if scan.Census.Candidates != 0 {
		t.Fatalf("the fixture has no G1 call site; misuse packets are not candidates: %d",
			scan.Census.Candidates)
	}
	var sb strings.Builder
	encodeRetrieved(&sb, sites)
	if !strings.Contains(sb.String(), `"site_kind":"misuse_shape"`) ||
		!strings.Contains(sb.String(), `:os.Remove:Remove","lang"`) {
		t.Fatalf("misuse packets must ride the stream through the choke point: %s", sb.String())
	}
}

func keysOf(m map[string]RetrievedSite) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
