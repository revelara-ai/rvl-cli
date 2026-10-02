package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// `http.Client{Timeout: 0}` names the Timeout field and sets no timeout: zero
// is Go's "wait forever". A fact that carried only the field name let that
// literal vouch for a whole-call bound (po-xtoe4).
func TestConfigFactRecordsFieldsSetToAConstantZero(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module zerofixture\n\ngo 1.21\n")
	write("clients.go", `package zerofixture

import (
	"net/http"
	"time"
)

const none time.Duration = 0

type opts struct{ Timeout time.Duration }

func build(d time.Duration) []any {
	return []any{
		opts{Timeout: 0},
		opts{Timeout: 0 * time.Second},
		opts{Timeout: none},
		opts{Timeout: 5 * time.Second},
		opts{Timeout: d},
		&http.Client{Timeout: 0, Transport: nil},
	}
}
`)
	lastRepoConfig = RepoConfig{}
	t.Cleanup(func() { lastRepoConfig = RepoConfig{} })
	if _, scan := runRetrieveAll(root, "zerofixture"); scan.Err != nil {
		t.Fatal(scan.Err)
	}

	var got [][]string
	for _, c := range lastRepoConfig.Constructions {
		if c.Type == "zerofixture.opts" || c.Type == "net/http.Client" {
			got = append(got, c.ZeroFields)
		}
	}
	want := [][]string{
		{"Timeout"}, // 0
		{"Timeout"}, // a folded constant expression
		{"Timeout"}, // a named zero constant
		nil,         // a real duration
		nil,         // not a constant: unknown, never asserted zero
		{"Timeout"}, // nil is not a constant zero; only Timeout is
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zero_fields = %v, want %v", got, want)
	}
}
