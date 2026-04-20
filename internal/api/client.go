package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/config"
)

// LoadAndResolveConfig loads config and resolves org name to UUID.
func LoadAndResolveConfig() *config.Config {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if cfg == nil || cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: Not configured. Run 'rely login' first.")
		os.Exit(1)
	}
	if err := ResolveOrganizationID(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// ResolveOrganizationID resolves an org name to its UUID by listing the user's orgs.
func ResolveOrganizationID(cfg *config.Config) error {
	if cfg.OrgName == "" {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/organizations", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("fetch organizations failed (status %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	var orgsResp struct {
		Organizations []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"organizations"`
	}
	if err := json.Unmarshal(body, &orgsResp); err != nil {
		return fmt.Errorf("parse organizations: %w", err)
	}

	for _, org := range orgsResp.Organizations {
		if strings.EqualFold(org.Name, cfg.OrgName) {
			cfg.ResolvedOrgID = org.ID
			return nil
		}
	}

	// List available org names to help the user
	names := make([]string, len(orgsResp.Organizations))
	for i, org := range orgsResp.Organizations {
		names[i] = org.Name
	}
	return fmt.Errorf("organization %q not found; available: %s", cfg.OrgName, strings.Join(names, ", "))
}

// ValidateCredentials checks if credentials are valid
func ValidateCredentials(cfg *config.Config) error {
	// Try to call a simple endpoint to validate
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/risks/stats", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("authentication failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server error (status %d)", resp.StatusCode)
	}

	return nil
}

// MakeAPIRequest makes an authenticated API request
func MakeAPIRequest(cfg *config.Config, method, url string, body []byte) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed - run 'rely login' to reconfigure")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// FetchServerPluginVersion queries the API for the latest plugin semver.
// Returns the semver base (e.g., "0.2.0") without build metadata.
// Returns empty string if the server is unreachable or returns an error.
func FetchServerPluginVersion(cfg *config.Config) string {
	if cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/plugin", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		Version string `json:"version"`
		SemVer  string `json:"semver"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	// Prefer the dedicated semver field (new servers), fall back to
	// stripping build metadata from the full version (old servers).
	if result.SemVer != "" {
		return result.SemVer
	}
	if idx := strings.Index(result.Version, "+"); idx != -1 {
		return result.Version[:idx]
	}
	return result.Version
}

// FetchSigningKey fetches the Ed25519 public key used to sign plugin tarballs.
// Returns nil if the server doesn't support signing or is unreachable.
func FetchSigningKey(cfg *config.Config) ed25519.PublicKey {
	if cfg == nil || cfg.APIURL == "" {
		return nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/plugin/signing-key", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var result struct {
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	if result.Algorithm != "EdDSA" || result.PublicKey == "" {
		return nil
	}

	keyBytes, err := hex.DecodeString(result.PublicKey)
	if err != nil {
		return nil
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil
	}

	return ed25519.PublicKey(keyBytes)
}
