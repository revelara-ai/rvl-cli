package main

import (
	"strings"
	"testing"
)

// A call is judged by the client that reaches its receiver. Attaching every
// construction of the type let one bounded client vouch for every unbounded
// one in the repository.
func TestConstructionIsTracedToTheReceiver(t *testing.T) {
	bySymbol := map[string]RetrievedSite{}
	for _, s := range runRetrieve("testdata/tracefixture", "tracefixture") {
		if s.Method == "Get" || s.Method == "Do" {
			bySymbol[s.Symbol] = s
		}
	}
	sets := func(s RetrievedSite) bool {
		for _, c := range s.Construction {
			if strings.Contains(c.Source, "Timeout") {
				return true
			}
		}
		return false
	}
	cases := []struct {
		symbol    string
		scope     string
		bounded   bool
		wantCtors int // -1: any number
	}{
		{"zeroLocal", "receiver", false, 1},
		{"boundedLocal", "receiver", true, 1},
		{"defaultClient", "receiver", false, 0},
		{"zeroValueVar", "receiver", false, 1},
		{"mutatedAfter", "receiver", true, -1},
		{"aliased", "receiver", false, 1},
		{"fromCtor", "receiver", true, 1},
		{"fetch", "", false, -1}, // two methods named fetch; checked below by receiver
		{"fromParam", "type", false, -1},
	}
	for _, tc := range cases {
		if tc.symbol == "fetch" {
			continue
		}
		s, ok := bySymbol[tc.symbol]
		if !ok {
			t.Errorf("%s: no site retrieved", tc.symbol)
			continue
		}
		if s.ConstructionScope != tc.scope {
			t.Errorf("%s: construction scope %q, want %q", tc.symbol, s.ConstructionScope, tc.scope)
		}
		if tc.scope == "receiver" && sets(s) != tc.bounded {
			t.Errorf("%s: construction sets Timeout = %v, want %v; got %+v", tc.symbol, sets(s), tc.bounded, s.Construction)
		}
		if tc.wantCtors >= 0 && len(s.Construction) != tc.wantCtors {
			t.Errorf("%s: %d constructions, want %d: %+v", tc.symbol, len(s.Construction), tc.wantCtors, s.Construction)
		}
	}

	// The two fetch methods share a name; tell them apart by receiver field owner.
	var api, loose *RetrievedSite
	for _, s := range runRetrieve("testdata/tracefixture", "tracefixture") {
		s := s
		if s.Symbol != "fetch" {
			continue
		}
		switch {
		case strings.Contains(s.Enclosing, "a *API"):
			api = &s
		case strings.Contains(s.Enclosing, "l *Loose"):
			loose = &s
		}
	}
	if api == nil || loose == nil {
		t.Fatalf("want both struct-field fetch sites, got api=%v loose=%v", api != nil, loose != nil)
	}
	if api.ConstructionScope != "receiver" || !sets(*api) {
		t.Errorf("API.hc is set with a Timeout in a keyed literal: scope %q, constructions %+v", api.ConstructionScope, api.Construction)
	}
	if loose.ConstructionScope != "receiver" || sets(*loose) {
		t.Errorf("Loose.hc is assigned an unbounded client: scope %q, constructions %+v", loose.ConstructionScope, loose.Construction)
	}
}
