package main

import (
	"slices"
	"testing"
)

// A construction whose arguments are the security setting is a call site of
// its own: a later Client.Do or db.Query does not show the cipher, the TLS
// setting or the DSN.

func constructionSites(t *testing.T) map[string]RetrievedSite {
	t.Helper()
	sites, scan := runRetrieveAll("testdata/constructionfixture", "constructionfixture")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	got := map[string]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind != "" {
			continue
		}
		key := s.Symbol + " " + s.ClientType + "." + s.Method
		if _, dup := got[key]; dup {
			t.Fatalf("two sites %s", key)
		}
		got[key] = s
	}
	return got
}

func TestCryptoAndDatabaseConstructorsAreCallSitesOfTheirPackage(t *testing.T) {
	got := constructionSites(t)
	for _, key := range []string{
		"Block crypto/des.NewCipher",
		"Digest crypto/md5.Sum",
		"Open database/sql.Open",
	} {
		s, ok := got[key]
		if !ok {
			t.Fatalf("no call site %q in %v", key, keys(got))
		}
		if !s.Prov.ClientTypeKnown || s.Enclosing == "" {
			t.Fatalf("%s: client type known %v, enclosing %q", key, s.Prov.ClientTypeKnown, s.Enclosing)
		}
	}
	dsn := got["Open database/sql.Open"].ConstArgs
	if len(dsn) != 2 || dsn[1].Value != `"postgres://app:hunter2@db/app"` || dsn[1].How != "literal" {
		t.Fatalf("the DSN must ride const_args, got %+v", dsn)
	}
}

func TestTLSConfigFieldSettingsAreCallSites(t *testing.T) {
	got := constructionSites(t)
	skip, ok := got[" crypto/tls.Config.InsecureSkipVerify"]
	if !ok {
		t.Fatalf("the package-level literal's InsecureSkipVerify is not a site: %v", keys(got))
	}
	if skip.Line != 14 || skip.CallSite == "" ||
		len(skip.ConstArgs) != 1 || skip.ConstArgs[0].Name != "InsecureSkipVerify" || skip.ConstArgs[0].Value != "true" {
		t.Fatalf("literal site = %+v", skip)
	}
	min, ok := got[" crypto/tls.Config.MinVersion"]
	if !ok || min.ConstArgs[0].Value != "769" || min.ConstArgs[0].How != "named_constant" {
		t.Fatalf("MinVersion must carry the folded tls.VersionTLS10, got %+v", min)
	}
	set, ok := got["Verify crypto/tls.Config.InsecureSkipVerify"]
	if !ok {
		t.Fatalf("the assignment is not a site: %v", keys(got))
	}
	if set.Receiver != "cfg" || set.ConstArgs[0].How != "name" || set.ConstArgs[0].Value != "skip" {
		t.Fatalf("assignment site = %+v", set)
	}
	if _, ok := got["Verify crypto/tls.Config.ServerName"]; ok {
		t.Fatal("a field outside construction_fields must not be a site")
	}
}

// A setting made under an if carries the condition, and the parameters it
// reads by bare name, so a user's opt-out can be told from the code's
// default. The walk stops at a closure.
func TestATLSFieldSiteCarriesTheIfThatGuardsIt(t *testing.T) {
	got := constructionSites(t)
	for symbol, want := range map[string]struct {
		guard  string
		params []string
	}{
		"Reverified":       {},
		"InsecureLoopback": {},
		"OptedOut":         {guard: "t.Insecure == true"},
		"NotVerified":      {guard: "!o.SSLVerify"},
		"Skipped":          {guard: "o.SkipVerify"},
		"Verified":         {guard: "!(o.SSLVerify)"},
		"DeferredInsecure": {},
		"Verify":           {},
		"DialInsecure":     {guard: `addr != "" && insecure`, params: []string{"addr", "insecure"}},
		"InsecureFromEnv":  {guard: "skip"},
	} {
		s, ok := got[symbol+" crypto/tls.Config.InsecureSkipVerify"]
		if !ok {
			t.Fatalf("%s: no InsecureSkipVerify site in %v", symbol, keys(got))
		}
		if s.Guard != want.guard || !slices.Equal(s.GuardParams, want.params) {
			t.Errorf("%s: guard %q %q, want %q %q", symbol, s.Guard, s.GuardParams, want.guard, want.params)
		}
	}
}

func TestConstructionTablesAreValidated(t *testing.T) {
	for _, table := range []string{
		`"construction_calls":[{"package":"crypto/md5","func":""}]`,
		`"construction_fields":[{"type":"crypto/tls.Config","field":""}]`,
		`"construction_calls":[{"package":"crypto/md5","func":"Sum"}],
		 "known_unretrieved":[{"package":"crypto/md5","func":"Sum","why":"x"}]`,
	} {
		bad := `{"io_methods":["Get"],"emission_frameworks":[{"match":"exact","path":"log","category":"log"}],` + table + `}`
		if _, err := parseExtractorCorpus([]byte(bad)); err == nil {
			t.Fatalf("corpus must be rejected: %s", table)
		}
	}
}

func keys(m map[string]RetrievedSite) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
