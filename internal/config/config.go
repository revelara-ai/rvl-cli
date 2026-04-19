package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	configDir  = ".revelara"
	configFile = "config.yaml"

	// DefaultAPIURL is the production Revelara API endpoint.
	DefaultAPIURL = "https://api.revelara.ai"
)

// Config holds the CLI configuration
type Config struct {
	APIURL  string `yaml:"api_url"`
	APIKey  string `yaml:"api_key"`
	OrgName string `yaml:"org_name"`

	// ResolvedOrgID is runtime-only: resolved org UUID (not persisted to YAML)
	ResolvedOrgID string `yaml:"-"`
}

// GetConfigPath returns the path to the config file
func GetConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, configDir, configFile)
}

// LoadConfig loads configuration from disk
func LoadConfig() (*Config, error) {
	path := GetConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No config yet
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	return &cfg, nil
}

// SaveConfig saves configuration to disk
func SaveConfig(cfg *Config) error {
	path := GetConfigPath()
	dir := filepath.Dir(path)

	// Create directory with restricted permissions
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Write with restricted permissions (owner read/write only)
	return os.WriteFile(path, data, 0600)
}
