package main

import (
	"regexp"
	"testing"
	"testing/fstest"
)

// The handshake (po-8ozxg): rvl compares a goindex it found against the one
// bundled with it by this value alone, so it must exist, be stable for one set
// of sources, and move when any of them does.
func TestContentVersionIsAShortHexDigestOfTheSources(t *testing.T) {
	got := contentVersion()
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(got) {
		t.Fatalf("contentVersion() = %q, want 12 lowercase hex digits", got)
	}
	if again := contentVersion(); again != got {
		t.Fatalf("contentVersion() is not stable: %q then %q", got, again)
	}
}

func TestContentVersionMovesWithAnySourceByte(t *testing.T) {
	base := fstest.MapFS{
		"a.go": {Data: []byte("package main\n")},
		"b.go": {Data: []byte("package main\n")},
	}
	edited := fstest.MapFS{
		"a.go": {Data: []byte("package main\n")},
		"b.go": {Data: []byte("package main\n// edit\n")},
	}
	// The same bytes split across file boundaries differently: a digest of
	// the bare concatenation would not see this.
	moved := fstest.MapFS{
		"a.go":  {Data: []byte("package main\n")},
		"bb.go": {Data: []byte("package main\n")},
	}
	if versionOf(base) != versionOf(base) {
		t.Fatal("the same sources must give the same version")
	}
	if versionOf(base) == versionOf(edited) {
		t.Fatal("an edited source must change the version")
	}
	if versionOf(base) == versionOf(moved) {
		t.Fatal("a renamed source must change the version")
	}
}

func TestHandshakeKeepsTheSchemaOnLineOne(t *testing.T) {
	want := "2\ncontent-version " + contentVersion() + "\n"
	if got := handshake(); got != want {
		t.Fatalf("handshake() = %q, want %q", got, want)
	}
}
