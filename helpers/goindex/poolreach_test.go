package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every site on one pool carries the same fact: the entries that reach the
// pool, each named by the rule that classed it. The fixture marks the lines.
func TestPoolReachClassesTheEntryPointsThatReachEachPool(t *testing.T) {
	dir, err := filepath.Abs("testdata/poolreachfixture")
	if err != nil {
		t.Fatal(err)
	}
	// at is "file:line" of the line holding mark.
	at := func(file, mark string) string {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "// "+mark) {
				return file + ":" + strconv.Itoa(i+1)
			}
		}
		t.Fatalf("%s: no line marked %q", file, mark)
		return ""
	}
	maxPoolEntriesEmitted = 100
	defer func() { maxPoolEntriesEmitted = 3 }()
	sites := runRetrieve(dir, "poolreachfixture")
	fact := func(mark string) []PoolReach {
		file := "store.go"
		if mark == "client" {
			file = "entries.go"
		}
		want := at(file, "site: "+mark)
		for _, s := range sites {
			if s.File+":"+strconv.Itoa(s.Line) == want && s.SiteKind == "" {
				return s.PoolReach
			}
		}
		t.Fatalf("no site at %s", want)
		return nil
	}
	show := func(es []EntryRef) string {
		var out []string
		for _, e := range es {
			out = append(out, e.Via+" "+e.Symbol+" "+e.File+":"+strconv.Itoa(e.Line))
		}
		sort.Strings(out)
		return strings.Join(out, "\n")
	}
	entry := func(via, symbol, file, mark string) string {
		return via + " " + symbol + " " + at(file, mark)
	}
	sorted := func(s ...string) string {
		sort.Strings(s)
		return strings.Join(s, "\n")
	}
	handlers := sorted(
		entry("http_handler", "ServeHTTP", "entries.go", "handler: http_handler"),
		entry("route", "rename", "entries.go", "handler: route"),
		entry("grpc", "Purge", "entries.go", "handler: grpc"),
		entry("route_literal", "main", "entries.go", "handler: route_literal"),
	)
	// newPoller, which stores a ticker, and helper, a method of the gRPC
	// type its interface does not name, are not entries.
	jobs := sorted(
		entry("go,ticker", "flushLoop", "entries.go", "job: go,ticker flushLoop"),
		entry("go,ticker", "run", "entries.go", "job: go,ticker run"),
		entry("ticker", "tick", "entries.go", "job: ticker"),
		entry("go_literal", "main", "entries.go", "job: go_literal"),
		entry("job_framework", "Compact", "store.go", "job: job_framework"),
	)

	// The receiver, a transaction begun on it and passed to a literal, and a
	// parameter whose callers are not all visible, which the fact says.
	pool := at("store.go", "pool")
	for _, mark := range []string{"count", "tx", "open"} {
		got := fact(mark)
		if len(got) != 1 || got[0].File+":"+strconv.Itoa(got[0].Line) != pool || got[0].Symbol != "database/sql.DB" {
			t.Fatalf("site %s: pool %+v, want the sql.Open at %s", mark, got, pool)
		}
		p := got[0]
		if p.JoinOpen != (mark == "open") {
			t.Errorf("site %s: join_open %v", mark, p.JoinOpen)
		}
		if g := show(p.HandlerEntries); g != handlers || p.Handlers != 4 {
			t.Errorf("site %s: %d handlers\n%s\nwant\n%s", mark, p.Handlers, g, handlers)
		}
		if g := show(p.JobEntries); g != jobs || p.Jobs != 5 {
			t.Errorf("site %s: %d jobs\n%s\nwant\n%s", mark, p.Jobs, g, jobs)
		}
	}

	// A second pool is walked on its own.
	c := fact("client")
	if len(c) != 1 || c[0].Symbol != "net/http.Client" || c[0].Handlers != 0 ||
		show(c[0].JobEntries) != entry("go", "poll", "entries.go", "job: go poll") {
		t.Errorf("client site: %+v, want one job, poll started by go", c)
	}
	// nil is no construction.
	if got := fact("nil"); got != nil {
		t.Errorf("nil site: %+v, want no fact", got)
	}
}
