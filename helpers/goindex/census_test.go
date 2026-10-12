package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// po-av01j.219: coverage is resolution over RETRIEVED surfaces, and the
// extractor tables decide what is retrieved. The census puts the retrieval
// denominator beside the resolution one, so a gap in the tables is a number
// instead of an absence.

func TestCensusNoLongerCountsReadAllAsNotRetrieved(t *testing.T) {
	// io.ReadAll used to be the known-unretrieved surface. It is a call site
	// now, so it is a candidate and no longer a gap.
	_, scan := runRetrieveAll("testdata/fixture", "fixture")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	c := scan.Census
	if c.Lang != Lang {
		t.Fatalf("census lang = %q, want %q", c.Lang, Lang)
	}
	if len(c.Unretrieved) != 0 {
		t.Fatalf("no surface of the fixture is known and not retrieved, got %v", c.Unretrieved)
	}
}

func TestCensusCountsAKnownUnretrievedSurface(t *testing.T) {
	// The mechanism stays: a surface the corpus lists as known I/O that the
	// tables do not retrieve is counted, not emitted.
	saved := extractor
	defer func() { extractor = saved }()
	extractor.KnownUnretrieved = []unretrievedEntry{{Package: "os", Func: "Open", Why: "test"}}
	sites, scan := runRetrieveAll("testdata/fixture", "fixture")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	if got := scan.Census.Unretrieved["os.Open"]; got != 1 {
		t.Fatalf("want ONE os.Open counted as existing-but-not-retrieved, got %d (%v)",
			got, scan.Census.Unretrieved)
	}
	for _, s := range sites {
		if s.SiteKind == "" && s.Method == "Open" {
			t.Fatalf("a known-unretrieved surface must not be emitted: %+v", s)
		}
	}
}

func TestExtractorCorpusRefusesASurfaceThatIsBothRetrievedAndCountedAsMissed(t *testing.T) {
	raw := []byte(`{"io_methods":["Do"],"emission_frameworks":[{"match":"exact","path":"log","category":"log"}],
		"reader_calls":[{"package":"io","func":"ReadAll"}],
		"known_unretrieved":[{"package":"io","func":"ReadAll","why":"x"}]}`)
	if _, err := parseExtractorCorpus(raw); err == nil {
		t.Fatal("io.ReadAll in reader_calls and known_unretrieved must be an error")
	}
}

func TestCensusCandidatesAreTheEmittedCallSitesAndNeverExceedCallsResolved(t *testing.T) {
	sites, scan := runRetrieveAll("testdata/fixture", "fixture")
	calls := 0
	for _, s := range sites {
		if s.SiteKind != siteKindEmission && s.SiteKind != siteKindMisuse && s.SiteKind != siteKindUnsized {
			calls++
		}
	}
	c := scan.Census
	if c.Candidates != calls {
		t.Fatalf("candidates = %d, want the %d call-site packets emitted (emission and misuse aggregates and unsized constructions excluded)",
			c.Candidates, calls)
	}
	if c.Candidates == 0 || c.CallsResolved <= c.Candidates {
		t.Fatalf("calls that exist (%d) must strictly exceed candidates retrieved (%d) on a fixture "+
			"with calls the tables skip", c.CallsResolved, c.Candidates)
	}
}

func TestCensusIsWholeRepoEvenUnderAFileFilter(t *testing.T) {
	// --files filters the emitted sites, never the denominator: goindex loads
	// every module regardless, so the census stays a statement about the repo.
	_, scan := runRetrieveAll("testdata/fixture", "fixture")
	rc := repoConfigFor(scan, "fixture")
	if len(rc.Retrieval) != 1 || rc.Retrieval[0].CallsResolved != scan.Census.CallsResolved {
		t.Fatalf("repo_config must carry the whole-repo census, got %+v", rc.Retrieval)
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(rc)
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	r, ok := back["retrieval"].([]any)
	if !ok || len(r) != 1 {
		t.Fatalf("repo_config JSON must carry a retrieval array, got %s", buf.String())
	}
	entry := r[0].(map[string]any)
	for _, k := range []string{"lang", "calls_resolved", "candidates", "unretrieved"} {
		if _, ok := entry[k]; !ok {
			t.Fatalf("retrieval entry lacks %q: %s", k, buf.String())
		}
	}
}

func TestExtractorCorpusCarriesTheTablesThatUsedToBeCode(t *testing.T) {
	// The tables moved from code constants into corpus data unchanged: the
	// move must not add or drop a method, or it silently changes what is
	// retrieved.
	want := []string{"Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext",
		"ExecContext", "Get", "Post", "Do", "Head", "Send"}
	if len(ioMethods) != len(want) {
		t.Fatalf("io_methods = %v, want exactly %v", ioMethods, want)
	}
	for _, m := range want {
		if !ioMethods[m] {
			t.Fatalf("io_methods lost %q", m)
		}
	}
	if len(extractor.EmissionFrameworks) == 0 {
		t.Fatal("the emission framework list must come from the corpus")
	}
	if len(extractor.ReaderCalls) == 0 {
		t.Fatal("the reader-call list must come from the corpus")
	}
}
