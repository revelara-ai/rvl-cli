package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
)

// buildTestTarball creates a signed tarball for testing.
func buildTestTarball(t *testing.T, priv ed25519.PrivateKey, files map[string][]byte) []byte {
	t.Helper()

	// Build manifest
	fileHashes := make(map[string]string, len(files))
	for path, content := range files {
		hash := sha256.Sum256(content)
		fileHashes[path] = "sha256:" + hex.EncodeToString(hash[:])
	}

	// Build canonical signing input
	type entry struct {
		path string
		hash string
	}
	entries := make([]entry, 0, len(fileHashes))
	for path, hash := range fileHashes {
		entries = append(entries, entry{path, hash})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})
	var sb strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&sb, "%s:%s\n", e.path, e.hash)
	}
	canonicalInput := []byte(sb.String())

	// Sign
	sig := ed25519.Sign(priv, canonicalInput)

	manifest := IntegrityManifest{
		Version:   "1.0.0",
		SignedAt:  "2026-04-20T00:00:00Z",
		Algorithm: "EdDSA",
		KeyID:     "test-key",
		Files:     fileHashes,
		Signature: hex.EncodeToString(sig),
		Provenance: Provenance{
			CommitSHA: "test-sha",
			Builder:   "test",
		},
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	// Build tarball
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add files
	for path, content := range files {
		header := &tar.Header{
			Name: path,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write header %s: %v", path, err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatalf("write content %s: %v", path, err)
		}
	}

	// Add manifest
	header := &tar.Header{
		Name: "integrity.manifest.json",
		Mode: 0644,
		Size: int64(len(manifestJSON)),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("write manifest header: %v", err)
	}
	if _, err := tarWriter.Write(manifestJSON); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	tarWriter.Close()
	gzWriter.Close()
	return buf.Bytes()
}

func TestVerifyTarball_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	files := map[string][]byte{
		"commands/scan.md":      []byte("# Scan\nScan for risks."),
		"agents/golang-pro.md":  []byte("# Go Pro\nExpert Go agent."),
		".claude-plugin/plugin.json": []byte(`{"name":"rvl","version":"1.0.0"}`),
	}

	tarball := buildTestTarball(t, priv, files)

	manifest, err := VerifyTarball(tarball, pub)
	if err != nil {
		t.Fatalf("VerifyTarball: %v", err)
	}

	if manifest.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", manifest.Version)
	}
	if len(manifest.Files) != 3 {
		t.Errorf("files count = %d, want 3", len(manifest.Files))
	}
}

func TestVerifyTarball_TamperedFile(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Tamper with the file content in the tarball by rebuilding with different content
	// but keeping the same manifest. We'll just use the wrong key to simulate.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	tamperedFiles := map[string][]byte{
		"commands/scan.md": []byte("# Scan\nTampered content!"),
	}
	tamperedTarball := buildTestTarball(t, wrongPriv, tamperedFiles)

	// Verify with original key should fail (wrong signature)
	_, err := VerifyTarball(tamperedTarball, pub)
	if err == nil {
		t.Fatal("expected verification failure for tarball signed with wrong key")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyTarball_MissingManifest(t *testing.T) {
	// Build a tarball with no manifest
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	content := []byte("# Scan")
	header := &tar.Header{
		Name: "commands/scan.md",
		Mode: 0644,
		Size: int64(len(content)),
	}
	tarWriter.WriteHeader(header)
	tarWriter.Write(content)
	tarWriter.Close()
	gzWriter.Close()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := VerifyTarball(buf.Bytes(), pub)
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	if !strings.Contains(err.Error(), "missing integrity.manifest.json") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyTarball_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	files := map[string][]byte{
		"commands/scan.md": []byte("# Scan"),
	}

	tarball := buildTestTarball(t, priv, files)

	_, err := VerifyTarball(tarball, wrongPub)
	if err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func TestVerifyTarball_UntrackedFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Build manifest for just one file
	files := map[string][]byte{
		"commands/scan.md": []byte("# Scan"),
	}
	tarball := buildTestTarball(t, priv, files)

	// Inject an extra file into the tarball that isn't in the manifest
	// We need to rebuild the tarball manually
	gzReader, _ := gzip.NewReader(bytes.NewReader(tarball))
	defer gzReader.Close()
	tarReader := tar.NewReader(gzReader)

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Copy existing files
	for {
		hdr, err := tarReader.Next()
		if err != nil {
			break
		}
		content, _ := io.ReadAll(tarReader)
		hdr.Size = int64(len(content))
		tarWriter.WriteHeader(hdr)
		tarWriter.Write(content)
	}

	// Add untracked file
	extra := []byte("malicious content")
	tarWriter.WriteHeader(&tar.Header{
		Name: "commands/evil.md",
		Mode: 0644,
		Size: int64(len(extra)),
	})
	tarWriter.Write(extra)
	tarWriter.Close()
	gzWriter.Close()

	_, err := VerifyTarball(buf.Bytes(), pub)
	if err == nil {
		t.Fatal("expected error for untracked file")
	}
	if !strings.Contains(err.Error(), "not tracked in manifest") {
		t.Errorf("unexpected error: %v", err)
	}
}
