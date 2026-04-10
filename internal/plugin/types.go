package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// PluginInfo tracks installed plugin metadata
type PluginInfo struct {
	Editor    string `json:"editor"`
	Version   string `json:"version"`
	Installed string `json:"installed"` // ISO8601 timestamp
	Location  string `json:"location"`
}

// PolarisSkillNames lists all Relynce skill directory names for cleanup.
// Includes both old (pre-0.7.0) and current names to clean up any version.
var PolarisSkillNames = []string{
	// Current skills (v0.7.0+)
	"ask", "evidence", "fix", "review", "risks", "scan", "status",
	// Legacy skills (pre-0.7.0) — kept for cleanup of old installations
	"detect-risks", "analyze-risks", "remediate-risks", "risk-check",
	"risk-guidance", "control-guidance", "submit-evidence", "reliability-review",
	"incident-patterns", "sre-context", "list-open", "ready",
	"ai-reliability-guidance", "capacity-planning-guidance", "cicd-guidance",
	"cost-governance-guidance", "deployment-excellence-guidance",
	"development-testing-guidance", "disaster-recovery-guidance",
	"incident-response-guidance", "observability-guidance",
	"post-incident-guidance", "reliability-culture-guidance",
	"resilience-guidance", "security-supply-chain-guidance",
	"slo-monitoring-guidance",
}

// SavePluginInfo persists plugin metadata to ~/.relynce/plugins.json
func SavePluginInfo(editor, version, location string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	metadataDir := filepath.Join(home, ".relynce")
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return err
	}

	metadataFile := filepath.Join(metadataDir, "plugins.json")

	// Load existing metadata
	var plugins []PluginInfo
	if data, err := os.ReadFile(metadataFile); err == nil {
		_ = json.Unmarshal(data, &plugins)
	}

	// Update or add this plugin
	found := false
	for i, p := range plugins {
		if p.Editor == editor {
			plugins[i].Version = version
			plugins[i].Installed = time.Now().Format(time.RFC3339)
			plugins[i].Location = location
			found = true
			break
		}
	}

	if !found {
		plugins = append(plugins, PluginInfo{
			Editor:    editor,
			Version:   version,
			Installed: time.Now().Format(time.RFC3339),
			Location:  location,
		})
	}

	// Save metadata
	data, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataFile, data, 0644)
}

// GetInstalledPlugins reads the plugin metadata file
func GetInstalledPlugins() ([]PluginInfo, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	metadataFile := filepath.Join(home, ".relynce", "plugins.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []PluginInfo{}, nil
		}
		return nil, err
	}

	var plugins []PluginInfo
	if err := json.Unmarshal(data, &plugins); err != nil {
		return nil, err
	}

	return plugins, nil
}

// RemovePluginFromMetadata removes a plugin entry from the metadata file
func RemovePluginFromMetadata(editor, metadataFile string) error {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return err
	}

	var plugins []PluginInfo
	if err := json.Unmarshal(data, &plugins); err != nil {
		return err
	}

	// Filter out the removed plugin
	var updated []PluginInfo
	for _, p := range plugins {
		if p.Editor != editor {
			updated = append(updated, p)
		}
	}

	data, err = json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataFile, data, 0644)
}
