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

func TestCensusCountsReadAllAsExistingButNotRetrieved(t *testing.T) {
	sites, scan := runRetrieveAll("testdata/fixture", "fixture")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	for _, s := range sites {
		if s.SiteKind == "" && s.Method == "ReadAll" {
			t.Fatalf("io.ReadAll is not in the io_methods table and must not be emitted as a call site: %+v", s)
		}
	}
	c := scan.Census
	if c.Lang != Lang {
		t.Fatalf("census lang = %q, want %q", c.Lang, Lang)
	}
	if got := c.Unretrieved["io.ReadAll"]; got != 1 {
		t.Fatalf("want ONE io.ReadAll counted as existing-but-not-retrieved, got %d (%v)",
			got, c.Unretrieved)
	}
}

func TestCensusCandidatesAreTheEmittedCallSitesAndNeverExceedCallsResolved(t *testing.T) {
	sites, scan := runRetrieveAll("testdata/fixture", "fixture")
	calls := 0
	for _, s := range sites {
		if s.SiteKind != siteKindEmission && s.SiteKind != siteKindUnsized {
			calls++
		}
	}
	c := scan.Census
	if c.Candidates != calls {
		t.Fatalf("candidates = %d, want the %d call-site packets emitted (emission aggregates and unsized constructions excluded)",
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
	if ioMethods["ReadAll"] {
		t.Fatal("ReadAll is a known-unretrieved surface, not a retrieved one")
	}
	if len(extractor.EmissionFrameworks) == 0 {
		t.Fatal("the emission framework list must come from the corpus")
	}
	if len(extractor.KnownUnretrieved) == 0 {
		t.Fatal("the corpus must name the known-unretrieved I/O surfaces it measures completeness by")
	}
}
