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

	// LocalDir is the path relative to the project root for --project installs.
	// Empty means --project is not supported for this editor.
	LocalDir string

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
		LocalDir:    ".agents/skills",
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
		LocalDir:    ".gemini",
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
		LocalDir:    ".cursor",
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
		LocalDir:    ".windsurf/skills",
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
		LocalDir:    ".copilot",
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
		LocalDir:    ".augment",
		SkillsDir:   ".augment/skills",
		AgentsDir:   ".augment/agents",
		Instructions: []string{
			"Skills and agents are auto-discovered by Augment CLI.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},

	// --- Tier 3: skills + agent-as-skill fallback ---
	"cline": {
		Name:        "cline",
		DisplayName: "Cline",
		Binary:      "cline",
		Tier:        3,
		InstallDir:  ".agents/skills",
		ConfigDir:   ".cline",
		LocalDir:    ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered from .agents/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"roo": {
		Name:        "roo",
		DisplayName: "Roo Code",
		Binary:      "roo",
		Tier:        3,
		InstallDir:  ".roo/skills",
		ConfigDir:   ".roo",
		LocalDir:    ".roo/skills",
		Instructions: []string{
			"Skills are auto-discovered from .roo/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"openhands": {
		Name:        "openhands",
		DisplayName: "OpenHands",
		Binary:      "openhands",
		Tier:        3,
		InstallDir:  ".openhands/skills",
		ConfigDir:   ".openhands",
		LocalDir:    ".openhands/skills",
		Instructions: []string{
			"Skills are auto-discovered from .openhands/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"goose": {
		Name:        "goose",
		DisplayName: "Goose",
		Binary:      "goose",
		Tier:        3,
		InstallDir:  ".config/goose/skills",
		ConfigDir:   ".config/goose",
		LocalDir:    ".goose/skills",
		Instructions: []string{
			"Skills are auto-discovered by Goose.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"warp": {
		Name:        "warp",
		DisplayName: "Warp",
		Binary:      "warp",
		Tier:        3,
		InstallDir:  ".agents/skills",
		ConfigDir:   ".warp",
		LocalDir:    ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered from .agents/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"continue": {
		Name:        "continue",
		DisplayName: "Continue",
		Binary:      "continue",
		Tier:        3,
		InstallDir:  ".continue/skills",
		ConfigDir:   ".continue",
		LocalDir:    ".continue/skills",
		Instructions: []string{
			"Skills are auto-discovered from .continue/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"amp": {
		Name:        "amp",
		DisplayName: "Amp",
		Binary:      "amp",
		Tier:        3,
		InstallDir:  ".config/amp/skills",
		ConfigDir:   ".config/amp",
		LocalDir:    ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered by Amp.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"kilo": {
		Name:        "kilo",
		DisplayName: "Kilo Code",
		Binary:      "kilo",
		Tier:        3,
		InstallDir:  ".kilocode/skills",
		ConfigDir:   ".kilocode",
		LocalDir:    ".kilocode/skills",
		Instructions: []string{
			"Skills are auto-discovered from .kilocode/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"opencode": {
		Name:        "opencode",
		DisplayName: "OpenCode",
		Binary:      "opencode",
		Tier:        3,
		InstallDir:  ".config/opencode/skills",
		ConfigDir:   ".config/opencode",
		LocalDir:    ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered by OpenCode.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"trae": {
		Name:        "trae",
		DisplayName: "Trae",
		Binary:      "trae",
		Tier:        3,
		InstallDir:  ".trae/skills",
		ConfigDir:   ".trae",
		LocalDir:    ".trae/skills",
		Instructions: []string{
			"Skills are auto-discovered from .trae/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"junie": {
		Name:        "junie",
		DisplayName: "Junie",
		Binary:      "junie",
		Tier:        3,
		InstallDir:  ".junie/skills",
		ConfigDir:   ".junie",
		LocalDir:    ".junie/skills",
		Instructions: []string{
			"Skills are auto-discovered from .junie/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"qwen-code": {
		Name:        "qwen-code",
		DisplayName: "Qwen Code",
		Binary:      "qwen",
		Tier:        3,
		InstallDir:  ".qwen/skills",
		ConfigDir:   ".qwen",
		LocalDir:    ".qwen/skills",
		Instructions: []string{
			"Skills are auto-discovered from .qwen/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"antigravity": {
		Name:        "antigravity",
		DisplayName: "Antigravity",
		Binary:      "antigravity",
		Tier:        3,
		InstallDir:  ".gemini/antigravity/skills",
		ConfigDir:   ".gemini/antigravity",
		LocalDir:    ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered from .agents/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"firebender": {
		Name:        "firebender",
		DisplayName: "Firebender",
		Binary:      "firebender",
		Tier:        3,
		InstallDir:  ".firebender/skills",
		ConfigDir:   ".firebender",
		LocalDir:    ".agents/skills",
		Instructions: []string{
			"Skills are auto-discovered from .agents/skills/.",
			"Try: \"scan this codebase for reliability risks\"",
		},
	},
	"kiro": {
		Name:        "kiro",
		DisplayName: "Kiro",
		Binary:      "kiro",
		Tier:        3,
		InstallDir:  ".kiro/skills",
		ConfigDir:   ".kiro",
		LocalDir:    ".kiro/skills",
		Instructions: []string{
			"Skills are auto-discovered from .kiro/skills/.",
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

// EditorInfo holds a name and display name pair for listing.
type EditorInfo struct {
	Name        string
	DisplayName string
}

// EditorsByTier returns editors grouped as custom (tier 1-2) and universal (tier 3).
// Each list is sorted alphabetically by name.
func EditorsByTier() (custom, universal []EditorInfo) {
	for name, def := range Registry {
		info := EditorInfo{Name: name, DisplayName: def.DisplayName}
		if def.Tier <= 2 {
			custom = append(custom, info)
		} else {
			universal = append(universal, info)
		}
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].Name < custom[j].Name })
	sort.Slice(universal, func(i, j int) bool { return universal[i].Name < universal[j].Name })
	return custom, universal
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
