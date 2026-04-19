package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryHasAllEditors(t *testing.T) {
	expected := []string{
		// Tier 1-2
		"claude", "codex", "gemini", "cursor", "windsurf", "copilot", "augment",
		// Tier 3
		"cline", "roo", "openhands", "goose", "warp", "continue", "amp",
		"kilo", "opencode", "trae", "junie", "qwen-code", "antigravity",
		"firebender", "kiro",
	}
	for _, editor := range expected {
		if _, ok := Registry[editor]; !ok {
			t.Errorf("editor %q missing from Registry", editor)
		}
	}
}

func TestRegistryRequiredFields(t *testing.T) {
	for name, def := range Registry {
		if def.Name == "" {
			t.Errorf("Registry[%q].Name is empty", name)
		}
		if def.Name != name {
			t.Errorf("Registry[%q].Name = %q, want %q", name, def.Name, name)
		}
		if def.DisplayName == "" {
			t.Errorf("Registry[%q].DisplayName is empty", name)
		}
		if def.Binary == "" {
			t.Errorf("Registry[%q].Binary is empty", name)
		}
		if def.Tier < 1 || def.Tier > 3 {
			t.Errorf("Registry[%q].Tier = %d, want 1-3", name, def.Tier)
		}
		if def.CustomInstall == nil && def.InstallDir == "" {
			t.Errorf("Registry[%q] has neither InstallDir nor CustomInstall", name)
		}
		if len(def.Instructions) == 0 {
			t.Errorf("Registry[%q].Instructions is empty", name)
		}
	}
}

func TestRegistryClaudeHasCustomFlows(t *testing.T) {
	def := Registry["claude"]
	if def.CustomInstall == nil {
		t.Error("claude should have CustomInstall")
	}
	if def.CustomRemove == nil {
		t.Error("claude should have CustomRemove")
	}
	if def.InstallDir != "" {
		t.Error("claude should not have InstallDir (uses CustomInstall)")
	}
}

func TestRegistryGeminiHasPostInstall(t *testing.T) {
	def := Registry["gemini"]
	if def.PostInstall == nil {
		t.Error("gemini should have PostInstall hook")
	}
}

func TestRegistryCopilotAgentGlob(t *testing.T) {
	def := Registry["copilot"]
	if def.AgentGlob != "rvl-*.agent.md" {
		t.Errorf("copilot AgentGlob = %q, want %q", def.AgentGlob, "rvl-*.agent.md")
	}
}

func TestEffectiveSkillsDir_DefaultsToInstallDir(t *testing.T) {
	// Codex has no SkillsDir, should default to InstallDir
	def := Registry["codex"]
	if def.SkillsDir != "" {
		t.Skip("codex has explicit SkillsDir")
	}
	got := def.effectiveSkillsDir()
	if got != def.InstallDir {
		t.Errorf("effectiveSkillsDir() = %q, want %q (InstallDir)", got, def.InstallDir)
	}
}

func TestEffectiveSkillsDir_ExplicitOverride(t *testing.T) {
	def := Registry["gemini"]
	got := def.effectiveSkillsDir()
	if got != ".gemini/skills" {
		t.Errorf("effectiveSkillsDir() = %q, want %q", got, ".gemini/skills")
	}
}

func TestEffectiveAgentGlob_Default(t *testing.T) {
	def := Registry["gemini"]
	got := def.effectiveAgentGlob()
	if got != "rvl-*.md" {
		t.Errorf("effectiveAgentGlob() = %q, want %q", got, "rvl-*.md")
	}
}

func TestEffectiveAgentGlob_Override(t *testing.T) {
	def := Registry["copilot"]
	got := def.effectiveAgentGlob()
	if got != "rvl-*.agent.md" {
		t.Errorf("effectiveAgentGlob() = %q, want %q", got, "rvl-*.agent.md")
	}
}

func TestIsValidEditor(t *testing.T) {
	for name := range Registry {
		if !IsValidEditor(name) {
			t.Errorf("IsValidEditor(%q) = false, want true", name)
		}
	}

	if IsValidEditor("vim") {
		t.Error("IsValidEditor(vim) = true, want false")
	}
	if IsValidEditor("") {
		t.Error("IsValidEditor('') = true, want false")
	}
}

func TestEditorNames(t *testing.T) {
	names := EditorNames()

	// Should contain all editors
	for name := range Registry {
		if !strings.Contains(names, name) {
			t.Errorf("EditorNames() missing %q", name)
		}
	}

	// Should be sorted (verify by checking a few known orderings)
	parts := strings.Split(names, ", ")
	for i := 1; i < len(parts); i++ {
		if parts[i] < parts[i-1] {
			t.Errorf("EditorNames() not sorted: %q comes after %q", parts[i], parts[i-1])
		}
	}
}

func TestRegistryInstallDirPaths(t *testing.T) {
	tests := map[string]string{
		"codex":    ".agents/skills",
		"gemini":   ".gemini",
		"cursor":   ".cursor",
		"windsurf": ".codeium/windsurf/skills",
		"copilot":  ".copilot",
		"augment":  ".augment",
	}
	for editor, wantDir := range tests {
		def := Registry[editor]
		if def.InstallDir != wantDir {
			t.Errorf("Registry[%q].InstallDir = %q, want %q", editor, def.InstallDir, wantDir)
		}
	}
}

func TestRegistryBinaryNames(t *testing.T) {
	tests := map[string]string{
		"claude":   "claude",
		"codex":    "codex",
		"gemini":   "gemini",
		"cursor":   "cursor",
		"windsurf": "windsurf",
		"copilot":  "copilot",
		"augment":  "auggie",
	}
	for editor, wantBinary := range tests {
		def := Registry[editor]
		if def.Binary != wantBinary {
			t.Errorf("Registry[%q].Binary = %q, want %q", editor, def.Binary, wantBinary)
		}
	}
}

func TestRegistryAgentsDir(t *testing.T) {
	// Editors with agents should have AgentsDir
	withAgents := map[string]string{
		"gemini":  ".gemini/agents",
		"cursor":  ".cursor/agents",
		"copilot": ".copilot/agents",
		"augment": ".augment/agents",
	}
	for editor, wantDir := range withAgents {
		def := Registry[editor]
		if def.AgentsDir != wantDir {
			t.Errorf("Registry[%q].AgentsDir = %q, want %q", editor, def.AgentsDir, wantDir)
		}
	}

	// Editors without agents should have empty AgentsDir
	withoutAgents := []string{"codex", "windsurf"}
	for _, editor := range withoutAgents {
		def := Registry[editor]
		if def.AgentsDir != "" {
			t.Errorf("Registry[%q].AgentsDir = %q, want empty", editor, def.AgentsDir)
		}
	}
}

func TestRegistryConfigDir(t *testing.T) {
	// Most editors should have ConfigDir for detection
	withConfigDir := []string{"claude", "gemini", "cursor", "windsurf", "copilot", "augment"}
	for _, editor := range withConfigDir {
		def := Registry[editor]
		if def.ConfigDir == "" {
			t.Errorf("Registry[%q].ConfigDir is empty", editor)
		}
	}
}

func TestIsEditorDetected_BinaryOnPath(t *testing.T) {
	// "go" is always on PATH in test environments
	def := EditorDef{Binary: "go"}
	if !isEditorDetected(def) {
		t.Error("isEditorDetected should return true when binary is on PATH")
	}
}

func TestIsEditorDetected_NoBinaryNoConfig(t *testing.T) {
	def := EditorDef{Binary: "nonexistent-binary-xyz-12345"}
	if isEditorDetected(def) {
		t.Error("isEditorDetected should return false when binary not on PATH and no ConfigDir")
	}
}

func TestIsEditorDetected_ConfigDirExists(t *testing.T) {
	// Create a temp dir to simulate a config directory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".test-editor")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Override HOME for the test
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	def := EditorDef{
		Binary:    "nonexistent-binary-xyz-12345",
		ConfigDir: ".test-editor",
	}
	if !isEditorDetected(def) {
		t.Error("isEditorDetected should return true when config dir exists")
	}
}

func TestIsEditorDetected_ConfigDirNotExists(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	def := EditorDef{
		Binary:    "nonexistent-binary-xyz-12345",
		ConfigDir: ".nonexistent-config-dir",
	}
	if isEditorDetected(def) {
		t.Error("isEditorDetected should return false when neither binary nor config dir exist")
	}
}

func TestDetectInstalled_ReturnsSorted(t *testing.T) {
	editors := DetectInstalled()
	for i := 1; i < len(editors); i++ {
		if editors[i] < editors[i-1] {
			t.Errorf("DetectInstalled() not sorted: %q comes after %q", editors[i], editors[i-1])
		}
	}
}

func TestRegistryLocalDirPaths(t *testing.T) {
	tests := map[string]string{
		"codex":    ".agents/skills",
		"gemini":   ".gemini",
		"cursor":   ".cursor",
		"windsurf": ".windsurf/skills",
		"copilot":  ".copilot",
		"augment":  ".augment",
	}
	for editor, wantDir := range tests {
		def := Registry[editor]
		if def.LocalDir != wantDir {
			t.Errorf("Registry[%q].LocalDir = %q, want %q", editor, def.LocalDir, wantDir)
		}
	}
}

func TestRegistryTier3Editors(t *testing.T) {
	tier3 := []string{
		"cline", "roo", "openhands", "goose", "warp", "continue", "amp",
		"kilo", "opencode", "trae", "junie", "qwen-code", "antigravity",
		"firebender", "kiro",
	}
	for _, editor := range tier3 {
		def := Registry[editor]
		if def.Tier != 3 {
			t.Errorf("Registry[%q].Tier = %d, want 3", editor, def.Tier)
		}
		if def.InstallDir == "" {
			t.Errorf("Registry[%q].InstallDir is empty", editor)
		}
		if def.ConfigDir == "" {
			t.Errorf("Registry[%q].ConfigDir is empty", editor)
		}
		if def.LocalDir == "" {
			t.Errorf("Registry[%q].LocalDir is empty", editor)
		}
		if def.CustomInstall != nil {
			t.Errorf("Registry[%q] should not have CustomInstall (Tier 3)", editor)
		}
		if def.CustomRemove != nil {
			t.Errorf("Registry[%q] should not have CustomRemove (Tier 3)", editor)
		}
		if len(def.Instructions) == 0 {
			t.Errorf("Registry[%q].Instructions is empty", editor)
		}
	}
}

func TestRegistryClaudeNoLocalDir(t *testing.T) {
	def := Registry["claude"]
	if def.LocalDir != "" {
		t.Errorf("Registry[claude].LocalDir = %q, want empty (uses CustomInstall)", def.LocalDir)
	}
}

func TestExtractFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flag     string
		wantArgs []string
		wantFlag bool
	}{
		{
			name:     "flag present",
			args:     []string{"gemini", "--project"},
			flag:     "--project",
			wantArgs: []string{"gemini"},
			wantFlag: true,
		},
		{
			name:     "flag absent",
			args:     []string{"gemini"},
			flag:     "--project",
			wantArgs: []string{"gemini"},
			wantFlag: false,
		},
		{
			name:     "flag before editor",
			args:     []string{"--project", "gemini"},
			flag:     "--project",
			wantArgs: []string{"gemini"},
			wantFlag: true,
		},
		{
			name:     "all with flag",
			args:     []string{"--all", "--project"},
			flag:     "--project",
			wantArgs: []string{"--all"},
			wantFlag: true,
		},
		{
			name:     "empty args",
			args:     []string{},
			flag:     "--project",
			wantArgs: nil,
			wantFlag: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, gotFlag := extractFlag(tt.args, tt.flag)
			if gotFlag != tt.wantFlag {
				t.Errorf("extractFlag() flag = %v, want %v", gotFlag, tt.wantFlag)
			}
			if len(gotArgs) != len(tt.wantArgs) {
				t.Errorf("extractFlag() args = %v, want %v", gotArgs, tt.wantArgs)
				return
			}
			for i := range gotArgs {
				if gotArgs[i] != tt.wantArgs[i] {
					t.Errorf("extractFlag() args[%d] = %q, want %q", i, gotArgs[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestDetectProjectRoot(t *testing.T) {
	// detectProjectRoot should return something (either git root or cwd)
	root, err := detectProjectRoot()
	if err != nil {
		t.Fatalf("detectProjectRoot() error: %v", err)
	}
	if root == "" {
		t.Error("detectProjectRoot() returned empty string")
	}
	// Should be an absolute path
	if !filepath.IsAbs(root) {
		t.Errorf("detectProjectRoot() = %q, want absolute path", root)
	}
}
