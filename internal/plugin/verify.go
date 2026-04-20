package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// IntegrityManifest is the integrity.manifest.json included in every plugin tarball.
type IntegrityManifest struct {
	Version    string            `json:"version"`
	SignedAt   string            `json:"signed_at"`
	Algorithm  string            `json:"algorithm"`
	KeyID      string            `json:"key_id"`
	Files      map[string]string `json:"files"`
	Signature  string            `json:"signature"`
	Provenance Provenance        `json:"provenance"`
}

// Provenance contains build metadata for audit trail.
type Provenance struct {
	CommitSHA string `json:"commit_sha"`
	BuildJob  string `json:"build_job,omitempty"`
	Builder   string `json:"builder,omitempty"`
}

// VerifyTarball verifies the integrity of a plugin tarball.
// It extracts the integrity.manifest.json, verifies the Ed25519 signature
// against the provided public key, and verifies every file's SHA-256 hash.
func VerifyTarball(tarballData []byte, publicKey ed25519.PublicKey) (*IntegrityManifest, error) {
	// Extract all files from the tarball into memory
	files, err := extractTarballToMemory(tarballData)
	if err != nil {
		return nil, fmt.Errorf("read tarball: %w", err)
	}

	// Find and parse the integrity manifest
	manifestData, ok := files["integrity.manifest.json"]
	if !ok {
		return nil, fmt.Errorf("tarball missing integrity.manifest.json — plugin may be unsigned")
	}

	var manifest IntegrityManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parse integrity manifest: %w", err)
	}

	// Verify the Ed25519 signature
	if manifest.Algorithm != "EdDSA" {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", manifest.Algorithm)
	}

	canonicalInput := buildCanonicalInput(manifest.Files)
	sigBytes, err := hex.DecodeString(manifest.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(publicKey, canonicalInput, sigBytes) {
		return nil, fmt.Errorf("signature verification failed — plugin may have been tampered with")
	}

	// Verify every file's SHA-256 hash
	for path, expectedHash := range manifest.Files {
		content, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("manifest lists %q but file not found in tarball", path)
		}
		hash := sha256.Sum256(content)
		actualHash := "sha256:" + hex.EncodeToString(hash[:])
		if actualHash != expectedHash {
			return nil, fmt.Errorf("hash mismatch for %q: expected %s, got %s", path, expectedHash, actualHash)
		}
	}

	// Check for files in tarball not tracked by manifest (excluding manifest itself)
	for path := range files {
		if path == "integrity.manifest.json" {
			continue
		}
		if _, ok := manifest.Files[path]; !ok {
			return nil, fmt.Errorf("file %q in tarball but not tracked in manifest", path)
		}
	}

	return &manifest, nil
}

// buildCanonicalInput reconstructs the canonical signing input from the files map.
// Format: sorted "path:hash\n" lines.
func buildCanonicalInput(files map[string]string) []byte {
	type entry struct {
		path string
		hash string
	}
	entries := make([]entry, 0, len(files))
	for path, hash := range files {
		entries = append(entries, entry{path, hash})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})

	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.path)
		sb.WriteString(":")
		sb.WriteString(e.hash)
		sb.WriteString("\n")
	}
	return []byte(sb.String())
}

// extractTarballToMemory reads a gzipped tarball into a map of path → content.
func extractTarballToMemory(tarballData []byte) (map[string][]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(tarballData))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	files := make(map[string][]byte)
	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", header.Name, err)
		}
		files[header.Name] = content
	}

	return files, nil
}
