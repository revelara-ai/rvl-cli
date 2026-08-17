package main

import (
	"os"
	"path/filepath"
	"testing"
)

// po-av01j.142: a recover() that hands the failure back to the caller is NOT a
// swallow. Measured on hashicorp/consul, every site the old rule reported was
// this shape -- idiomatic "don't panic across an API boundary" code, told to
// add logging it does not need.

func recoverFixture(t *testing.T, body string) []RetrievedSite {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fx\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := "package fx\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, _ := runRetrieveAll(dir, "t")
	var sw []RetrievedSite
	for _, s := range got {
		if s.ClientType == "recover_block" {
			sw = append(sw, s)
		}
	}
	return sw
}

func TestRecoverAssigningNamedResultIsNotASwallow(t *testing.T) {
	// The exact shape from consul's structpatcher.go and controller.go.
	sw := recoverFixture(t, `
func Patch() (e error) {
	defer func() {
		if err := recover(); err != nil {
			e = fmt.Errorf("unexpected panic: %v", err)
		}
	}()
	return nil
}
`)
	if len(sw) != 0 {
		t.Fatalf("propagating recover reported as a swallow: %+v", sw)
	}
}

func TestRecoverThatRepanicsIsNotASwallow(t *testing.T) {
	sw := recoverFixture(t, `
func Repanic() {
	defer func() {
		if err := recover(); err != nil {
			panic(err)
		}
	}()
}
`)
	if len(sw) != 0 {
		t.Fatalf("re-panicking recover reported as a swallow: %+v", sw)
	}
}

// THE CASE THAT MUST STILL FIRE. Discarding the panic with no emission and no
// propagation is the real defect, and the fix must not suppress it.
func TestRecoverThatDiscardsIsStillASwallow(t *testing.T) {
	sw := recoverFixture(t, `
func Discard() {
	defer func() {
		if err := recover(); err != nil {
			_ = err
		}
	}()
}
`)
	if len(sw) != 1 {
		t.Fatalf("a discarding recover must remain a swallow, got %+v", sw)
	}
}

// Scoping check: a function whose NORMAL path assigns the named result but
// whose deferred block discards the panic is still a swallow. Looking at the
// whole function body instead of the recovering block would clear it wrongly.
func TestNormalPathAssignmentDoesNotClearADiscardingRecover(t *testing.T) {
	sw := recoverFixture(t, `
func Mixed() (err error) {
	defer func() {
		if r := recover(); r != nil {
			_ = r
		}
	}()
	err = fmt.Errorf("normal path")
	return err
}
`)
	if len(sw) != 1 {
		t.Fatalf("a discarding recover must survive a normal-path assignment, got %+v", sw)
	}
}

// The shape that survived the FIRST version of this fix, from consul's
// agent/grpc-middleware/rate.go: the recovering block assigns `retErr`, a named
// result of the RETURNED CLOSURE, not of the outer function. Judging it against
// the outer scope finds nothing, which is why the walk is per-scope.
func TestRecoverAssigningAnInnerClosuresNamedResultIsNotASwallow(t *testing.T) {
	sw := recoverFixture(t, `
type handler func(int) (int, error)

func Middleware() handler {
	return func(i int) (_ int, retErr error) {
		defer func() {
			if r := recover(); r != nil {
				retErr = fmt.Errorf("panic: %v", r)
			}
		}()
		return i, nil
	}
}
`)
	if len(sw) != 0 {
		t.Fatalf("closure-scoped propagation reported as a swallow: %+v", sw)
	}
}

// ...and a discarding recover inside an inner closure must STILL fire.
func TestDiscardingRecoverInsideAnInnerClosureIsStillASwallow(t *testing.T) {
	sw := recoverFixture(t, `
type handler2 func(int) (int, error)

func Middleware2() handler2 {
	return func(i int) (_ int, retErr error) {
		defer func() {
			if r := recover(); r != nil {
				_ = r
			}
		}()
		return i, nil
	}
}
`)
	if len(sw) != 1 {
		t.Fatalf("a discarding recover in a closure must remain a swallow, got %+v", sw)
	}
}

// po-av01j.142, third shape. A recover that LOGS through a framework the
// extractor did not know was reported as emitting nothing. Consul logs every
// recovered panic through hashicorp/go-hclog; the standard `log` package was
// missing too, which is the most common logging call in Go. A missing
// framework can only ever invent a swallow, never hide one.
func TestRecoverThatLogsViaTheStandardLogPackageIsNotASwallow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fx\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `package fx

import "log"

func Handler() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered: %v", r)
		}
	}()
}
`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, _ := runRetrieveAll(dir, "t")
	for _, s := range got {
		if s.ClientType == "recover_block" {
			t.Fatalf("a recover that logs via the stdlib is not a swallow: %+v", s)
		}
	}
}

func TestStandardLogIsRecognisedButLogSubpackagesAreNotDoubleCounted(t *testing.T) {
	if _, ok := emissionFramework("log"); !ok {
		t.Error("the standard log package must be recognised")
	}
	cat, ok := emissionFramework("log/slog")
	if !ok || cat != "log" {
		t.Error("log/slog must still resolve through its own arm")
	}
	for _, p := range []string{"github.com/hashicorp/go-hclog", "k8s.io/klog/v2", "github.com/golang/glog"} {
		if _, ok := emissionFramework(p); !ok {
			t.Errorf("%s must be recognised", p)
		}
	}
	// Not a logger: must stay unrecognised, or every call becomes an emission.
	if _, ok := emissionFramework("github.com/some/logistics"); ok {
		t.Error("a package merely starting with 'log' must not match")
	}
}
