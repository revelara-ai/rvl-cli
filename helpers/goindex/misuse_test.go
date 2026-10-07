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
	calls := 0
	for _, s := range sites {
		if s.SiteKind == "" {
			calls++
		}
	}
	// The database/sql calls of shapes.go are the fixture's G1 call sites.
	if scan.Census.Candidates != calls {
		t.Fatalf("candidates = %d, want the %d call sites: misuse packets are not candidates",
			scan.Census.Candidates, calls)
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

// Wave 3 shapes: retry delay, SQL text built in a query call, print-style
// output and a latency metric that is not a histogram. Each class is named
// for the shape, and each test pins the neighbour that must not be emitted.

func shapesOf(t *testing.T, symbol string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, s := range misuseByKey(t) {
		if s.Symbol == symbol {
			out[constArgByName(s.ConstArgs, "misuse_class")+" "+s.ClientType] = constArgByName(s.ConstArgs, "misuse_count")
		}
	}
	return out
}

func wantShapes(t *testing.T, symbol string, want map[string]string) {
	t.Helper()
	got := shapesOf(t, symbol)
	if len(got) != len(want) {
		t.Fatalf("%s: shapes = %v, want %v", symbol, got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("%s: shapes = %v, want %v", symbol, got, want)
		}
	}
}

func TestRetryShapeIsReadFromTheDelayExpressionOnTheFailurePath(t *testing.T) {
	wantShapes(t, "RetryConstant", map[string]string{"retry_shape constant_delay": "1"})
	wantShapes(t, "RetryForever", map[string]string{
		"retry_shape constant_delay":     "1",
		"retry_shape unbounded_attempts": "1",
	})
	wantShapes(t, "RetryExponential", map[string]string{"retry_shape no_jitter": "1"})
	// The delay reaches the wait through a local and a select.
	wantShapes(t, "RetryShifted", map[string]string{"retry_shape no_jitter": "1"})
	// A counter in the body limits the attempts.
	wantShapes(t, "RetryCounted", map[string]string{"retry_shape constant_delay": "1"})

	s := misuseByKey(t)["RetryConstant constant_delay"]
	if s.Method != "Sleep" || !strings.Contains(s.CallSite, "time.Sleep(2 * time.Second)") || !s.Prov.ClientTypeKnown {
		t.Fatalf("the packet sits on the wait: %+v", s)
	}
}

func TestRetryShapeAbstainsWhereTheShapeIsNotARetryOrIsNotVisible(t *testing.T) {
	wantShapes(t, "RetryJittered", map[string]string{})
	// A delay from a function has no shape in this expression.
	wantShapes(t, "RetryOpaque", map[string]string{})
	// A constant delay in a loop over items is not a retry.
	wantShapes(t, "PingAll", map[string]string{})
	// A sleep between rounds of work is not on the failure path.
	wantShapes(t, "Poll", map[string]string{})
}

func TestSQLTextBuiltInTheQueryCallIsEmittedAndOtherFormsAreNot(t *testing.T) {
	wantShapes(t, "FindUser", map[string]string{"sql_concat_in_call database/sql.DB.Query": "1"})
	wantShapes(t, "DeleteUser", map[string]string{"sql_concat_in_call database/sql.Tx.ExecContext": "1"})
	// A parameter, a join of constants and text from another statement.
	wantShapes(t, "SafeQueries", map[string]string{})
}

func TestPrintStyleOutputIsEmittedAndStdlibLogIsNot(t *testing.T) {
	wantShapes(t, "Report", map[string]string{
		"print_logging fmt.Println":            "1",
		"print_logging fmt.Printf":             "1",
		"print_logging fmt.Fprintf(os.Stderr)": "1",
		"print_logging println":                "1",
	})
	wantShapes(t, "Render", map[string]string{})
	// The emission lane counts log.Print* as a log emission that can satisfy
	// RC-027. This lane must not report the same line as a violation.
	sites, _ := runRetrieveAll("testdata/fixture", "fixture")
	for _, s := range sites {
		if s.SiteKind == siteKindMisuse && strings.HasPrefix(s.ClientType, "log.") {
			t.Fatalf("a stdlib log call is not print-style output: %+v", s)
		}
	}
}

func TestALatencyMetricRegisteredAsAGaugeOrCounterIsEmitted(t *testing.T) {
	const prom = "latency_scalar_metric github.com/prometheus/client_golang/prometheus."
	// Package-level registrations have no enclosing function.
	wantShapes(t, "", map[string]string{prom + "NewGauge": "1", prom + "NewCounterVec": "1"})
	wantShapes(t, "registerLate", map[string]string{prom + "NewGauge": "1"})
}
