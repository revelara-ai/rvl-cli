package project

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProjectConfig represents the .revelara.yaml project configuration file
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

// LoadProjectConfigFrom reads .revelara.yaml from the specified directory's git root.
// If targetDir is empty, uses the current working directory (existing behavior).
// Falls back to .relynce.yaml then .polaris.yaml, auto-renaming to .revelara.yaml.
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

	revelaraPath := filepath.Join(gitRoot, ".revelara.yaml")
	relyncePath := filepath.Join(gitRoot, ".relynce.yaml")
	polarisPath := filepath.Join(gitRoot, ".polaris.yaml")

	// 1. Try .revelara.yaml first
	data, err := os.ReadFile(revelaraPath)
	if err != nil {
		// 2. Fallback: try .relynce.yaml and auto-rename
		data, err = os.ReadFile(relyncePath)
		if err != nil {
			// 3. Fallback: try .polaris.yaml and auto-rename
			data, err = os.ReadFile(polarisPath)
			if err != nil {
				return nil
			}
			if renameErr := os.Rename(polarisPath, revelaraPath); renameErr == nil {
				fmt.Fprintf(os.Stderr, "Renamed .polaris.yaml to .revelara.yaml\n")
			}
		} else {
			if renameErr := os.Rename(relyncePath, revelaraPath); renameErr == nil {
				fmt.Fprintf(os.Stderr, "Renamed .relynce.yaml to .revelara.yaml\n")
			}
		}
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

// LoadProjectConfig reads .revelara.yaml from the current directory's git root.
func LoadProjectConfig() *ProjectConfig {
	return LoadProjectConfigFrom("")
}

// WriteProjectConfig writes a ProjectConfig to disk as .revelara.yaml
func WriteProjectConfig(path string, cfg *ProjectConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := "# Revelara project configuration\n# Used by detect-risks and reliability-review skills for consistent service naming\n"
	return os.WriteFile(path, []byte(header+string(data)), 0644)
}
