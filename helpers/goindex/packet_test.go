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
