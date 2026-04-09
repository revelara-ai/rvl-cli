package project

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProjectConfig represents the .relynce.yaml project configuration file
type ProjectConfig struct {
	Project     string             `yaml:"project"`
	Criticality string             `yaml:"criticality,omitempty"`
	Components  []ProjectComponent `yaml:"components"`
}

// CriticalityScore maps the human-friendly criticality label to a float64 (0.0-1.0)
// for use in risk scoring. Unknown or empty values default to 0.0 (no boost).
func (c *ProjectConfig) CriticalityScore() float64 {
	switch c.Criticality {
	case "hobby":
		return 0.0
	case "internal":
		return 0.25
	case "customer-facing":
		return 0.6
	case "critical":
		return 1.0
	default:
		return 0.0
	}
}

// ProjectComponent represents a component within a project
type ProjectComponent struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// LoadProjectConfigFrom reads .relynce.yaml from the specified directory's git root.
// If targetDir is empty, uses the current working directory (existing behavior).
func LoadProjectConfigFrom(targetDir string) *ProjectConfig {
	var gitRoot string
	if targetDir != "" {
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			return nil
		}
		cmd := exec.Command("git", "-C", absTarget, "rev-parse", "--show-toplevel")
		out, err := cmd.Output()
		if err != nil {
			// Not a git repo — try using the directory itself
			gitRoot = absTarget
		} else {
			gitRoot = strings.TrimSpace(string(out))
		}
	} else {
		cmd := exec.Command("git", "rev-parse", "--show-toplevel")
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		gitRoot = strings.TrimSpace(string(out))
	}

	relyncePath := filepath.Join(gitRoot, ".relynce.yaml")
	polarisPath := filepath.Join(gitRoot, ".polaris.yaml")
	data, err := os.ReadFile(relyncePath)
	if err != nil {
		// Fallback: try .polaris.yaml and auto-rename
		data, err = os.ReadFile(polarisPath)
		if err != nil {
			return nil
		}
		// Auto-rename .polaris.yaml → .relynce.yaml
		if renameErr := os.Rename(polarisPath, relyncePath); renameErr == nil {
			fmt.Fprintf(os.Stderr, "Renamed .polaris.yaml → .relynce.yaml\n")
		}
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

// LoadProjectConfig reads .relynce.yaml from the current directory's git root.
func LoadProjectConfig() *ProjectConfig {
	return LoadProjectConfigFrom("")
}

// WriteProjectConfig writes a ProjectConfig to disk as .relynce.yaml
func WriteProjectConfig(path string, cfg *ProjectConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := "# Relynce project configuration\n# Used by detect-risks and reliability-review skills for consistent service naming\n"
	return os.WriteFile(path, []byte(header+string(data)), 0644)
}
