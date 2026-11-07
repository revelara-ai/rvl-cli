package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The fixture marks each line that holds a protective site with "// site:".
func protectiveMarks(t *testing.T, dir string) map[string]bool {
	t.Helper()
	want := map[string]bool{}
	for _, file := range []string{"main.go", "main_test.go"} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "// site:") {
				want[file+":"+strconv.Itoa(i+1)] = true
			}
		}
	}
	return want
}

func TestProtectiveSitesAreTheLimiterCallsOfTheTable(t *testing.T) {
	dir, err := filepath.Abs("testdata/protectivefixture")
	if err != nil {
		t.Fatal(err)
	}
	sites, scan := runRetrieveAll(dir, "protectivefixture")
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	got := map[string]RetrievedSite{}
	for _, s := range sites {
		if s.SiteKind == siteKindProtective {
			got[s.File+":"+strconv.Itoa(s.Line)] = s
		}
	}
	want := protectiveMarks(t, dir)
	for at := range want {
		if _, ok := got[at]; !ok {
			t.Errorf("no protective site at %s", at)
		}
	}
	// The local Allow and the limiter's Limit are not in the table.
	for at, s := range got {
		if !want[at] {
			t.Errorf("unexpected protective site at %s: %s.%s", at, s.ClientType, s.Method)
		}
	}
	if scan.Census.ProtectiveSites != len(want) {
		t.Errorf("census protective_sites = %d, want %d", scan.Census.ProtectiveSites, len(want))
	}

	// The handler's site: the class, the mechanism, and the handler with
	// its refusal branch as the enclosing function.
	var handler RetrievedSite
	for _, s := range got {
		if s.File == "main.go" && s.Symbol == "handle" {
			handler = s
		}
	}
	if handler.ClientType != "golang.org/x/time/rate.Limiter" || handler.Method != "Allow" {
		t.Fatalf("handler site: %+v", handler)
	}
	mech := ""
	for _, a := range handler.ConstArgs {
		if a.Name == "protective_mechanism" && a.How == "aggregate" {
			mech = a.Value
		}
	}
	if mech != "rate_limit" {
		t.Errorf("handler site mechanism %q, want rate_limit", mech)
	}
	if !strings.HasPrefix(handler.Enclosing, "func handle(") ||
		!strings.Contains(handler.Enclosing, "http.StatusTooManyRequests") {
		t.Errorf("enclosing function must be the handler with its refusal:\n%s", handler.Enclosing)
	}
	if siteKey(handler) != handler.File+":"+strconv.Itoa(handler.Line)+":golang.org/x/time/rate.Limiter:Allow" {
		t.Errorf("site key %q", siteKey(handler))
	}

	// The call through an embedding struct is the limiter's method.
	var test, wait RetrievedSite
	for _, s := range got {
		switch s.Symbol {
		case "drain":
			wait = s
		case "TestLimiterRefusesWithNoBurst":
			test = s
		}
	}
	if wait.Method != "Wait" || wait.ClientType != "golang.org/x/time/rate.Limiter" {
		t.Errorf("embedded limiter site: %+v", wait)
	}
	// The test file is read, and its site is in the test file.
	if test.File != "main_test.go" || test.Method != "Allow" {
		t.Errorf("test site: %+v", test)
	}
}

func TestProtectiveSitesNeedNoTestLoadWithoutALimiter(t *testing.T) {
	// The fixture module imports no listed package, so no package's tests
	// are loaded a second time.
	pkgs := loadFixture(t, "testdata/fixture")
	if p := protectiveTestPatterns("testdata/fixture", pkgs); len(p) != 0 {
		t.Fatalf("test patterns %v, want none", p)
	}
	pkgs = loadFixture(t, "testdata/protectivefixture")
	if p := protectiveTestPatterns("testdata/protectivefixture", pkgs); len(p) != 1 || p[0] != "./." {
		t.Fatalf("test patterns %v, want the root package", p)
	}
}

func TestExtractorCorpusRefusesAProtectiveCallWithNoMechanism(t *testing.T) {
	raw := []byte(`{"io_methods":["Do"],"emission_frameworks":[{"match":"exact","path":"log","category":"log"}],
		"protective_calls":[{"package":"golang.org/x/time/rate","type":"Limiter","method":"Allow"}]}`)
	if _, err := parseExtractorCorpus(raw); err == nil {
		t.Fatal("a protective_calls entry without a mechanism must be an error")
	}
}
