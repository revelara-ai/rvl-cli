package plugin

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

// GetPluginDir returns the installation directory for a given editor's plugin.
func GetPluginDir(editor, version string) (string, error) {
	def, ok := Registry[editor]
	if !ok {
		return "", fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	if def.InstallDir == "" {
		// Claude uses a version-dependent path (legacy compat)
		return filepath.Join(home, ".claude", "plugins", "cache", "revelara-api", "revelara", version), nil
	}

	return filepath.Join(home, def.InstallDir), nil
}

// ExtractTarball extracts a tar.gz tarball to the target directory
func ExtractTarball(tarballData []byte, targetDir string) error {
	gzReader, err := gzip.NewReader(bytes.NewReader(tarballData))
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	fileCount := 0

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		targetPath := filepath.Join(targetDir, header.Name)

		// Prevent path traversal: ensure extracted path stays within targetDir
		cleanTarget := filepath.Clean(targetPath)
		if !strings.HasPrefix(cleanTarget, filepath.Clean(targetDir)+string(os.PathSeparator)) && cleanTarget != filepath.Clean(targetDir) {
			return fmt.Errorf("invalid file path in tarball (path traversal): %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("create parent directory: %w", err)
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("write file %s: %w", targetPath, err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", targetPath, err)
			}
			fileCount++
		}
	}

	fmt.Printf("✓ Extracted %d files\n", fileCount)
	return nil
}

// detectProjectRoot returns the project root directory.
// Uses git root if available, otherwise the current working directory.
func detectProjectRoot() (string, error) {
	root := project.DetectGitRoot()
	if root != "" {
		return root, nil
	}
	return os.Getwd()
}

// extractFlag removes a flag from an argument list and returns whether it was present.
func extractFlag(args []string, flag string) ([]string, bool) {
	var filtered []string
	found := false
	for _, a := range args {
		if a == flag {
			found = true
		} else {
			filtered = append(filtered, a)
		}
	}
	return filtered, found
}

// InstallPlugin downloads and installs the Revelara plugin for the specified editor.
// If projectRoot is non-empty, installs to projectRoot/LocalDir (project-local).
func InstallPlugin(editor, projectRoot string) error {
	def, ok := Registry[editor]
	if !ok {
		return fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	isProject := projectRoot != ""

	if isProject {
		if def.LocalDir == "" {
			return fmt.Errorf("--project not supported for %s", editor)
		}
		if def.CustomInstall != nil {
			return fmt.Errorf("--project not supported for %s (uses custom install flow)", editor)
		}
		fmt.Printf("Installing Revelara plugin for %s (project-local)...\n", editor)
	} else {
		fmt.Printf("Installing Revelara plugin for %s...\n", editor)
	}

	if !isProject && editor == "claude" {
		if err := CleanupOldClaudeInstallations(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not clean up old installations: %v\n", err)
		}
	}

	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return fmt.Errorf("no API credentials configured — run 'rvl login' first")
	}

	client := &http.Client{Timeout: 60 * time.Second}
	downloadURL := cfg.APIURL + "/api/v1/plugin/download?editor=" + editor

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	fmt.Printf("Downloading plugin from %s...\n", downloadURL)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download plugin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Prefer X-Plugin-SemVer header (new servers), fall back to Content-Disposition parsing
	version := resp.Header.Get("X-Plugin-SemVer")
	if version == "" {
		version = resp.Header.Get("X-Plugin-Version")
	}
	if version == "" {
		// Legacy fallback: parse from Content-Disposition filename
		cd := resp.Header.Get("Content-Disposition")
		version = strings.TrimPrefix(cd, "attachment; filename=revelara-plugin-")
		version = strings.TrimPrefix(version, "attachment; filename=polaris-plugin-")
		version = strings.TrimSuffix(version, ".tar.gz")
		version = strings.TrimPrefix(version, editor+"-")
	}
	version = SemVerBase(version)
	checksum := resp.Header.Get("X-Checksum")

	tarballData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read tarball: %w", err)
	}

	if checksum != "" {
		hash := sha256.Sum256(tarballData)
		actualChecksum := "sha256:" + hex.EncodeToString(hash[:])
		if actualChecksum != checksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, actualChecksum)
		}
		fmt.Println("✓ Checksum verified")
	}

	// Editors with CustomInstall handle the entire flow themselves (global only)
	if !isProject && def.CustomInstall != nil {
		return def.CustomInstall(version, tarballData)
	}

	var targetDir string
	if isProject {
		targetDir = filepath.Join(projectRoot, def.LocalDir)
	} else {
		targetDir, err = GetPluginDir(editor, version)
		if err != nil {
			return err
		}
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	fmt.Printf("Extracting to %s...\n", targetDir)
	if err := ExtractTarball(tarballData, targetDir); err != nil {
		return err
	}

	// Run post-install hook if defined (e.g., EnableGeminiSubagents) — global only
	if !isProject && def.PostInstall != nil {
		if err := def.PostInstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: post-install hook failed: %v\n", err)
		}
	}

	// Track global installs in metadata; project-local installs live in the repo
	if !isProject {
		if err := SavePluginInfo(editor, version, targetDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
		}
	}

	PrintPostInstallInstructions(editor, targetDir)

	return nil
}

// UpdatePlugin updates installed plugin(s) to the latest version
func UpdatePlugin(editor string) error {
	if editor == "" {
		plugins, err := GetInstalledPlugins()
		if err != nil {
			return err
		}

		if len(plugins) == 0 {
			fmt.Println("No plugins installed.")
			return nil
		}

		fmt.Printf("Updating %d plugin(s)...\n", len(plugins))
		for _, p := range plugins {
			fmt.Printf("\nUpdating %s plugin...\n", p.Editor)
			if err := InstallPlugin(p.Editor, ""); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", p.Editor, err)
			}
		}
		return nil
	}

	return InstallPlugin(editor, "")
}

// listEditors prints all supported editors grouped by integration type.
func listEditors() {
	custom, universal := EditorsByTier()

	fmt.Println("Custom integrations (editor-specific install):")
	for _, e := range custom {
		fmt.Fprintf(os.Stdout, "  %-14s %s\n", e.Name, e.DisplayName)
	}

	fmt.Println("\nUniversal integrations (generic skills directory):")
	for _, e := range universal {
		fmt.Fprintf(os.Stdout, "  %-14s %s\n", e.Name, e.DisplayName)
	}

	fmt.Println("\nInstall:  rvl plugin install <name>")
	fmt.Println("Auto:     rvl plugin install --all")
}

// ListInstalledPlugins lists all installed Revelara plugins
func ListInstalledPlugins() {
	plugins, err := GetInstalledPlugins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if len(plugins) == 0 {
		fmt.Println("No Revelara plugins installed.")
		fmt.Println("\nTo install:")
		fmt.Println("  rvl plugin install <editor>")
		fmt.Printf("  Available: %s\n", EditorNames())
		return
	}

	cfg, _ := config.LoadConfig()
	serverVersion := api.FetchServerPluginVersion(cfg)

	fmt.Println("Installed Revelara plugins:")
	for _, p := range plugins {
		fmt.Printf("\n  %s\n", p.Editor)
		fmt.Printf("    Version:   %s\n", p.Version)
		if serverVersion != "" && SemVerNewer(p.Version, serverVersion) {
			fmt.Printf("    Latest:    %s (update available)\n", serverVersion)
		} else if serverVersion != "" {
			fmt.Printf("    Latest:    %s (up to date)\n", serverVersion)
		}
		fmt.Printf("    Installed: %s\n", p.Installed)
		fmt.Printf("    Location:  %s\n", p.Location)
	}

	if serverVersion != "" {
		for _, p := range plugins {
			if SemVerNewer(p.Version, serverVersion) {
				fmt.Printf("\nRun 'rvl plugin update' to upgrade.\n")
				break
			}
		}
	}

	// Show project-local installations if we're in a project
	root := project.DetectGitRoot()
	if root != "" {
		var localEditors []string
		for name, def := range Registry {
			if def.LocalDir == "" {
				continue
			}
			localDir := filepath.Join(root, def.LocalDir)
			// Check if any current skill dirs exist
			for _, skill := range PolarisSkillNames[:7] {
				if _, err := os.Stat(filepath.Join(localDir, skill)); err == nil {
					localEditors = append(localEditors, name)
					break
				}
			}
		}
		if len(localEditors) > 0 {
			sort.Strings(localEditors)
			fmt.Printf("\nProject-local installations (%s):\n", root)
			for _, e := range localEditors {
				def := Registry[e]
				fmt.Printf("  %s → %s\n", e, filepath.Join(root, def.LocalDir))
			}
		}
	}
}

// RemovePlugin removes an installed plugin (all versions).
// If projectRoot is non-empty, removes from projectRoot/LocalDir (project-local).
func RemovePlugin(editor, projectRoot string) error {
	def, ok := Registry[editor]
	if !ok {
		return fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	isProject := projectRoot != ""

	if isProject && def.LocalDir == "" {
		return fmt.Errorf("--project not supported for %s", editor)
	}

	scope := "global"
	if isProject {
		scope = "project-local"
	}

	fmt.Printf("Remove %s Revelara plugin for %s? [y/N] ", scope, editor)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		return nil
	}

	if isProject {
		// Project-local removal: clean up from project root
		baseDir := filepath.Join(projectRoot, def.LocalDir)
		RemoveSkillDirs(baseDir)

		if def.AgentsDir != "" {
			// Derive project-local agents dir from LocalDir
			agentsDir := filepath.Join(projectRoot, def.LocalDir, "agents")
			removeAgentFilesByGlob(agentsDir, def.effectiveAgentGlob())
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}

		if def.CustomRemove != nil {
			if err := def.CustomRemove(home); err != nil {
				return err
			}
		} else {
			// Standard removal: clean up skill dirs and agent files
			skillsDir := filepath.Join(home, def.effectiveSkillsDir())
			RemoveSkillDirs(skillsDir)

			if def.AgentsDir != "" {
				agentsDir := filepath.Join(home, def.AgentsDir)
				removeAgentFilesByGlob(agentsDir, def.effectiveAgentGlob())
			}
		}

		metadataFile := filepath.Join(home, ".revelara", "plugins.json")
		_ = RemovePluginFromMetadata(editor, metadataFile)
	}

	fmt.Printf("✓ Removed %s plugin (%s)\n", editor, scope)
	return nil
}

// removeAgentFilesByGlob removes agent files matching the given glob pattern.
func removeAgentFilesByGlob(agentsDir, pattern string) {
	matches, err := filepath.Glob(filepath.Join(agentsDir, pattern))
	if err != nil {
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", f, err)
		}
	}
}

// RemoveSkillDirs removes known Revelara skill subdirectories from a base directory
func RemoveSkillDirs(baseDir string) {
	for _, name := range PolarisSkillNames {
		dir := filepath.Join(baseDir, name)
		if _, err := os.Stat(dir); err == nil {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", dir, err)
			}
		}
	}
}

// EnableGeminiSubagents ensures experimental.enableAgents is true in ~/.gemini/settings.json.
func EnableGeminiSubagents() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	settingsPath := filepath.Join(home, ".gemini", "settings.json")

	var settings map[string]any
	if data, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(data, &settings)
	}
	if settings == nil {
		settings = make(map[string]any)
	}

	experimental, ok := settings["experimental"].(map[string]any)
	if !ok {
		experimental = make(map[string]any)
		settings["experimental"] = experimental
	}

	if enabled, ok := experimental["enableAgents"].(bool); ok && enabled {
		return nil
	}

	experimental["enableAgents"] = true

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return err
	}

	fmt.Println("✓ Enabled experimental subagents in ~/.gemini/settings.json")
	return nil
}


// PrintPostInstallInstructions prints editor-specific next steps
func PrintPostInstallInstructions(editor, location string) {
	def, ok := Registry[editor]
	if !ok {
		return
	}

	fmt.Printf("\n✓ Revelara skills installed for %s\n\n", editor)

	if def.AgentsDir != "" {
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
	} else {
		fmt.Printf("Skills installed to: %s\n\n", location)
	}

	for _, line := range def.Instructions {
		fmt.Println(line)
	}
}

// installAll detects installed editors and installs the plugin to each one.
// If projectRoot is non-empty, installs project-locally. Editors without
// LocalDir are skipped for project-local installs.
func installAll(projectRoot string) {
	editors := DetectInstalled()
	if len(editors) == 0 {
		fmt.Println("No supported editors detected.")
		fmt.Printf("Supported: %s\n", EditorNames())
		fmt.Println("\nInstall an editor CLI, then run: rvl plugin install --all")
		return
	}

	fmt.Printf("Detected %d editor(s): %s\n\n", len(editors), strings.Join(editors, ", "))

	var succeeded, failed, skipped int
	for _, editor := range editors {
		// Skip editors that don't support project-local installs
		if projectRoot != "" {
			def := Registry[editor]
			if def.LocalDir == "" || def.CustomInstall != nil {
				fmt.Printf("Skipping %s (--project not supported)\n\n", editor)
				skipped++
				continue
			}
		}
		if err := InstallPlugin(editor, projectRoot); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to install for %s: %v\n\n", editor, err)
			failed++
		} else {
			succeeded++
			fmt.Println()
		}
	}

	fmt.Printf("Done: %d succeeded", succeeded)
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	if skipped > 0 {
		fmt.Printf(", %d skipped", skipped)
	}
	fmt.Println()
}

// CmdPlugin handles plugin management (install, update, list, remove).
func CmdPlugin(args []string) {
	editorList := EditorNames()

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: rvl plugin <command>\n\nCommands:\n  install <editor>            Install skills for editor (%s)\n  install <editor> --project  Install to current project directory\n  install --all               Auto-detect and install to all editors\n  install --all --project     Auto-detect and install project-locally\n  update [editor]             Update skills to latest version\n  update --all                Update all installed plugins\n  list                        List installed skills\n  editors                     List all supported editors\n  remove <editor>             Remove installed skills\n  remove <editor> --project   Remove project-local skills\n\nExamples:\n  rvl plugin install claude         Install Claude Code plugin\n  rvl plugin install gemini --project  Install to project directory\n  rvl plugin install --all          Install to all detected editors\n  rvl plugin update                 Update all installed plugins\n  rvl plugin editors                Show all supported editors\n  rvl plugin list                   Show installed plugins\n", editorList)
		os.Exit(1)
	}

	// Extract --project flag from subcommand args
	subArgs := args[1:]
	subArgs, isProject := extractFlag(subArgs, "--project")

	var projectRoot string
	if isProject {
		var err error
		projectRoot, err = detectProjectRoot()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not detect project root: %v\n", err)
			os.Exit(1)
		}
	}

	switch args[0] {
	case "install":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: rvl plugin install <editor> [--project]")
			fmt.Fprintln(os.Stderr, "       rvl plugin install --all [--project]")
			fmt.Fprintf(os.Stderr, "Available: %s\n", editorList)
			os.Exit(1)
		}
		if subArgs[0] == "--all" {
			installAll(projectRoot)
		} else {
			editor := subArgs[0]
			if err := InstallPlugin(editor, projectRoot); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}
	case "update":
		editor := ""
		if len(subArgs) >= 1 && subArgs[0] != "--all" {
			editor = subArgs[0]
		}
		if err := UpdatePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		ListInstalledPlugins()
	case "editors":
		listEditors()
	case "remove", "uninstall":
		if len(subArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: rvl plugin remove <editor> [--project]")
			os.Exit(1)
		}
		editor := subArgs[0]
		if err := RemovePlugin(editor, projectRoot); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: rvl plugin <install|update|list|editors|remove>")
		os.Exit(1)
	}
}

// IsEditorAvailable checks if the given CLI binary is on the PATH.
func IsEditorAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}
