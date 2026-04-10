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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
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
		return filepath.Join(home, ".claude", "plugins", "cache", "relynce-api", "relynce", version), nil
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

// InstallPlugin downloads and installs the Relynce plugin for the specified editor
func InstallPlugin(editor string) error {
	def, ok := Registry[editor]
	if !ok {
		return fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	fmt.Printf("Installing Relynce plugin for %s...\n", editor)

	if editor == "claude" {
		if err := CleanupOldClaudeInstallations(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not clean up old installations: %v\n", err)
		}
	}

	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return fmt.Errorf("no API credentials configured — run 'rely login' first")
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
		version = strings.TrimPrefix(cd, "attachment; filename=relynce-plugin-")
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

	// Editors with CustomInstall handle the entire flow themselves
	if def.CustomInstall != nil {
		return def.CustomInstall(version, tarballData)
	}

	targetDir, err := GetPluginDir(editor, version)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	fmt.Printf("Extracting to %s...\n", targetDir)
	if err := ExtractTarball(tarballData, targetDir); err != nil {
		return err
	}

	// Run post-install hook if defined (e.g., EnableGeminiSubagents)
	if def.PostInstall != nil {
		if err := def.PostInstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: post-install hook failed: %v\n", err)
		}
	}

	if err := SavePluginInfo(editor, version, targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
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
			if err := InstallPlugin(p.Editor); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", p.Editor, err)
			}
		}
		return nil
	}

	return InstallPlugin(editor)
}

// ListInstalledPlugins lists all installed Relynce plugins
func ListInstalledPlugins() {
	plugins, err := GetInstalledPlugins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if len(plugins) == 0 {
		fmt.Println("No Relynce plugins installed.")
		fmt.Println("\nTo install:")
		fmt.Println("  rely plugin install <editor>")
		fmt.Printf("  Available: %s\n", EditorNames())
		return
	}

	cfg, _ := config.LoadConfig()
	serverVersion := api.FetchServerPluginVersion(cfg)

	fmt.Println("Installed Relynce plugins:")
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
				fmt.Printf("\nRun 'rely plugin update' to upgrade.\n")
				break
			}
		}
	}
}

// RemovePlugin removes an installed plugin (all versions)
func RemovePlugin(editor string) error {
	def, ok := Registry[editor]
	if !ok {
		return fmt.Errorf("unsupported editor: %s (available: %s)", editor, EditorNames())
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	fmt.Printf("Remove Relynce plugin for %s? [y/N] ", editor)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		return nil
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

	metadataFile := filepath.Join(home, ".relynce", "plugins.json")
	_ = RemovePluginFromMetadata(editor, metadataFile)

	fmt.Printf("✓ Removed %s plugin\n", editor)
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

// RemoveSkillDirs removes known Relynce skill subdirectories from a base directory
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

	fmt.Printf("\n✓ Relynce skills installed for %s\n\n", editor)

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
// Failed installs for individual editors print a warning and continue.
func installAll() {
	editors := DetectInstalled()
	if len(editors) == 0 {
		fmt.Println("No supported editors detected.")
		fmt.Printf("Supported: %s\n", EditorNames())
		fmt.Println("\nInstall an editor CLI, then run: rely plugin install --all")
		return
	}

	fmt.Printf("Detected %d editor(s): %s\n\n", len(editors), strings.Join(editors, ", "))

	var succeeded, failed int
	for _, editor := range editors {
		if err := InstallPlugin(editor); err != nil {
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
	fmt.Println()
}

// CmdPlugin handles plugin management (install, update, list, remove).
func CmdPlugin(args []string) {
	editorList := EditorNames()

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: rely plugin <command>\n\nCommands:\n  install <editor>   Install skills for editor (%s)\n  install --all      Auto-detect and install to all editors\n  update [editor]    Update skills to latest version\n  update --all       Update all installed plugins\n  list               List installed skills\n  remove <editor>    Remove installed skills\n\nExamples:\n  rely plugin install claude    Install Claude Code plugin\n  rely plugin install --all     Install to all detected editors\n  rely plugin update            Update all installed plugins\n  rely plugin list              Show installed plugins\n", editorList)
		os.Exit(1)
	}

	switch args[0] {
	case "install":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: rely plugin install <editor>")
			fmt.Fprintln(os.Stderr, "       rely plugin install --all")
			fmt.Fprintf(os.Stderr, "Available: %s\n", editorList)
			os.Exit(1)
		}
		if args[1] == "--all" {
			installAll()
		} else {
			editor := args[1]
			if err := InstallPlugin(editor); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}
	case "update":
		editor := ""
		if len(args) >= 2 && args[1] != "--all" {
			editor = args[1]
		}
		if err := UpdatePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		ListInstalledPlugins()
	case "remove", "uninstall":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: rely plugin remove <editor>")
			os.Exit(1)
		}
		editor := args[1]
		if err := RemovePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: rely plugin <install|update|list|remove>")
		os.Exit(1)
	}
}

// IsEditorAvailable checks if the given CLI binary is on the PATH.
func IsEditorAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}
