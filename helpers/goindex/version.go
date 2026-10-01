package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
)

// sources is this helper's own source tree, carried in the binary so the
// binary can say which build it is. A Go binary has no file to hash the way
// pyindex.py does, and the toolchain's VCS stamp is absent from a build made
// outside a checkout (a release tarball, `go build` in a vendored copy).
//
//go:embed *.go go.mod go.sum
var sources embed.FS

// versionOf is the first 12 hex digits of a sha256 over every file in fsys, in
// name order. Each name and each body is terminated, so moving bytes from one
// file to the next cannot produce the same digest.
func versionOf(fsys fs.FS) string {
	h := sha256.New()
	entries, _ := fs.ReadDir(fsys, ".")
	for _, e := range entries {
		body, _ := fs.ReadFile(fsys, e.Name())
		h.Write([]byte(e.Name()))
		h.Write([]byte{0})
		h.Write(body)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// contentVersion is the second line of the -packet-schema reply: which
// goindex this is. PacketSchema says what SHAPE the stream has. It does not
// move when the helper learns a new client surface, so a week-old goindex and
// today's answer the same "2" and scan differently. rvl compares this value
// between the goindex it found and the one bundled with it, and warns when
// they are different builds.
func contentVersion() string {
	return versionOf(sources)
}

// handshake is the whole -packet-schema reply. Line 1 stays the bare schema
// integer, so a consumer that reads only the first line keeps working.
func handshake() string {
	return fmt.Sprintf("%d\ncontent-version %s\n", PacketSchema, contentVersion())
}
