package plugin

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EditorDef describes how to install, remove, and configure the Relynce plugin
// for a given AI coding editor. Adding a new editor = adding one entry to Registry.
type EditorDef struct {
	Name        string
	DisplayName string
	Binary      string // CLI binary name for PATH detection
	Tier        int

	// InstallDir is the path relative to $HOME where the tarball is extracted.
	// Empty for editors with CustomInstall (e.g., Claude).
	InstallDir string

	// SkillsDir is the path relative to $HOME containing skill directories.
	// Used for cleanup during removal. Defaults to InstallDir if empty.
	SkillsDir string

	// AgentsDir is the path relative to $HOME containing agent files.
	// Empty means no agent files to manage.
	AgentsDir string

	// AgentGlob is the glob pattern for matching agent files during removal.
	// Defaults to "rely-*.md" if empty.
	AgentGlob string

	// ConfigDir is the path relative to $HOME used for detection.
	// If the directory exists, the editor is considered installed.
	// Empty means detection relies on binary check only.
	ConfigDir string

	// PostInstall is called after standard tarball extraction (e.g., EnableGeminiSubagents).
	PostInstall func() error

	// CustomInstall replaces the entire install flow (tarball extraction included).
	// When set, the standard download+extract flow is bypassed.
	CustomInstall func(version string, data []byte) error

	// CustomRemove replaces the standard removal flow.
	// When set, the standard skills/agents cleanup is bypassed.
	CustomRemove func(home string) error

	// Instructions are printed after successful installation (one per line).
	Instructions []string
}

// effectiveSkillsDir returns SkillsDir if set, otherwise InstallDir.
func (d EditorDef) effectiveSkillsDir() string {
	if d.SkillsDir != "" {
		return d.SkillsDir
	}
	return d.InstallDir
}

// effectiveAgentGlob returns AgentGlob if set, otherwise "rely-*.md".
func (d EditorDef) effectiveAgentGlob() string {
	if d.AgentGlob != "" {
		return d.AgentGlob
	}
	return "rely-*.md"
}

// Registry maps editor names to their definitions.
var Registry = map[string]EditorDef{
	"claude": {
		Name:          "claude",
		DisplayName:   "Claude Code",
		Binary:        "claude",
		Tier:          1,
		ConfigDir:     ".claude",
		CustomInstall: InstallClaudePlugin,
		CustomRemove:  removeClaudePlugin,
		Instructions: []string{
			"Commands are now available: /rely:scan, /rely:fix, /rely:ask, etc.",
			"Restart Claude Code to ensure all commands are loaded.",
		},
	},
	"codex": {
		Name:        "codex",
		DisplayName: "OpenAI Codex",
		Binary:      "codex",
		Tier:        2,
		InstallDir:  ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered by Codex CLI.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"gemini": {
		Name:        "gemini",
		DisplayName: "Google Gemini CLI",
		Binary:      "gemini",
		Tier:        2,
		InstallDir:  ".gemini",
		ConfigDir:   ".gemini",
		SkillsDir:   ".gemini/skills",
		AgentsDir:   ".gemini/agents",
		PostInstall: EnableGeminiSubagents,
		Instructions: []string{
			"Skills and agents are auto-discovered by Gemini CLI.",
			"Subagents enabled via experimental.enableAgents in ~/.gemini/settings.json",
			"",
			"Note: Subagents are experimental and run in YOLO mode (no per-tool confirmation).",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"cursor": {
		Name:        "cursor",
		DisplayName: "Cursor",
		Binary:      "cursor",
		Tier:        2,
		InstallDir:  ".cursor",
		ConfigDir:   ".cursor",
		SkillsDir:   ".cursor/skills",
		AgentsDir:   ".cursor/agents",
		Instructions: []string{
			"Skills and agents are auto-discovered by Cursor.",
			"Use /scan or ask naturally.",
		},
	},
	"windsurf": {
		Name:        "windsurf",
		DisplayName: "Windsurf",
		Binary:      "windsurf",
		Tier:        2,
		InstallDir:  ".codeium/windsurf/skills",
		ConfigDir:   ".codeium/windsurf",
		Instructions: []string{
			"Skills are auto-discovered by Windsurf.",
			"Use @scan or ask Cascade naturally.",
		},
	},
	"copilot": {
		Name:        "copilot",
		DisplayName: "GitHub Copilot",
		Binary:      "copilot",
		Tier:        2,
		InstallDir:  ".copilot",
		ConfigDir:   ".copilot",
		SkillsDir:   ".copilot/skills",
		AgentsDir:   ".copilot/agents",
		AgentGlob:   "rely-*.agent.md",
		Instructions: []string{
			"Skills and agents are auto-discovered by Copilot CLI.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"augment": {
		Name:        "augment",
		DisplayName: "Augment Code",
		Binary:      "auggie",
		Tier:        2,
		InstallDir:  ".augment",
		ConfigDir:   ".augment",
		SkillsDir:   ".augment/skills",
		AgentsDir:   ".augment/agents",
		Instructions: []string{
			"Skills and agents are auto-discovered by Augment CLI.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
}

// IsValidEditor returns true if the editor name exists in the Registry.
func IsValidEditor(name string) bool {
	_, ok := Registry[name]
	return ok
}

// EditorNames returns a comma-separated, sorted list of editor names.
func EditorNames() string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// isEditorDetected returns true if the editor is present on this machine.
// Detection passes if the CLI binary is on PATH or the config directory exists.
func isEditorDetected(def EditorDef) bool {
	if IsEditorAvailable(def.Binary) {
		return true
	}
	if def.ConfigDir != "" {
		home, err := os.UserHomeDir()
		if err == nil {
			if _, err := os.Stat(filepath.Join(home, def.ConfigDir)); err == nil {
				return true
			}
		}
	}
	return false
}

// DetectEditors returns the names of editors whose CLI binary is on the PATH.
func DetectEditors() []string {
	var found []string
	for name, def := range Registry {
		if IsEditorAvailable(def.Binary) {
			found = append(found, name)
		}
	}
	sort.Strings(found)
	return found
}

// DetectInstalled returns the names of editors detected on this machine.
// An editor is detected if its CLI binary is on PATH or its config directory exists.
func DetectInstalled() []string {
	var found []string
	for name, def := range Registry {
		if isEditorDetected(def) {
			found = append(found, name)
		}
	}
	sort.Strings(found)
	return found
}
