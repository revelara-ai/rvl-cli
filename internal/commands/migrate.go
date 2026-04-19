package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CmdMigrate performs a one-shot migration from old naming conventions
// (relynce/rely) to new ones (revelara/rvl). Each step is idempotent.
//
// Steps:
//  1. Config dir: ~/.relynce/ -> ~/.revelara/
//  2. Config file: api_url relynce.ai -> revelara.ai
//  3. Project config: .relynce.yaml -> .revelara.yaml
//  4. CLAUDE.md: RELYNCE MANAGED BLOCK -> REVELARA MANAGED BLOCK
//  5. AGENTS.md: ## Relynce -> ## Revelara
//
// Flags: -y (auto-accept), --dry-run (preview only)
func CmdMigrate(args []string) {
	var yesAll, dryRun bool
	for _, arg := range args {
		switch arg {
		case "-y", "--yes":
			yesAll = true
		case "--dry-run":
			dryRun = true
		case "-h", "--help":
			printMigrateUsage()
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", arg)
			printMigrateUsage()
			os.Exit(1)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	gitRoot := findGitRoot()

	var migrated, skipped int

	// Step 1: Config directory
	action := migrateConfigDirectory(home, yesAll, dryRun)
	if action != "" {
		migrated++
		fmt.Printf("  [migrated] %s\n", action)
	} else {
		skipped++
		fmt.Printf("  [skipped]  Config directory (already at ~/.revelara/ or no old directory found)\n")
	}

	// Step 2: Config file API URL
	action = migrateConfigAPIURL(home, dryRun)
	if action != "" {
		migrated++
		fmt.Printf("  [migrated] %s\n", action)
	} else {
		skipped++
		fmt.Printf("  [skipped]  Config API URL (already points to revelara.ai or no config found)\n")
	}

	// Step 3: Project config file
	if gitRoot != "" {
		action = migrateProjectConfig(gitRoot, dryRun)
		if action != "" {
			migrated++
			fmt.Printf("  [migrated] %s\n", action)
		} else {
			skipped++
			fmt.Printf("  [skipped]  Project config (already .revelara.yaml or no old config found)\n")
		}
	} else {
		skipped++
		fmt.Printf("  [skipped]  Project config (not in a git repository)\n")
	}

	// Step 4: CLAUDE.md managed block markers
	if gitRoot != "" {
		action = migrateClaudeMdMarkers(gitRoot, dryRun)
		if action != "" {
			migrated++
			fmt.Printf("  [migrated] %s\n", action)
		} else {
			skipped++
			fmt.Printf("  [skipped]  CLAUDE.md markers (already updated or no CLAUDE.md found)\n")
		}
	} else {
		skipped++
		fmt.Printf("  [skipped]  CLAUDE.md markers (not in a git repository)\n")
	}

	// Step 5: AGENTS.md section header
	if gitRoot != "" {
		action = migrateAgentsMdHeader(gitRoot, dryRun)
		if action != "" {
			migrated++
			fmt.Printf("  [migrated] %s\n", action)
		} else {
			skipped++
			fmt.Printf("  [skipped]  AGENTS.md header (already updated or no AGENTS.md found)\n")
		}
	} else {
		skipped++
		fmt.Printf("  [skipped]  AGENTS.md header (not in a git repository)\n")
	}

	// Summary
	fmt.Println()
	if dryRun {
		fmt.Printf("Dry run complete: %d would migrate, %d already current\n", migrated, skipped)
	} else {
		fmt.Printf("Migration complete: %d migrated, %d already current\n", migrated, skipped)
	}
}

// findGitRoot returns the git root for the current directory, or "" if not in a repo.
func findGitRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// migrateConfigDirectory renames ~/.relynce/ -> ~/.revelara/ if needed.
func migrateConfigDirectory(home string, yesAll, dryRun bool) string {
	newDir := filepath.Join(home, ".revelara")
	if _, err := os.Stat(newDir); err == nil {
		return "" // already exists
	}

	relynceDir := filepath.Join(home, ".relynce")
	if _, err := os.Stat(relynceDir); err == nil {
		if dryRun {
			return "Would rename ~/.relynce/ -> ~/.revelara/"
		}
		if !yesAll && !confirmStep("Rename ~/.relynce/ to ~/.revelara/?") {
			return ""
		}
		if err := os.Rename(relynceDir, newDir); err != nil {
			fmt.Fprintf(os.Stderr, "  [error]    Failed to rename config dir: %v\n", err)
			return ""
		}
		return "Renamed ~/.relynce/ -> ~/.revelara/"
	}

	polarisDir := filepath.Join(home, ".polaris")
	if _, err := os.Stat(polarisDir); err == nil {
		if dryRun {
			return "Would rename ~/.polaris/ -> ~/.revelara/"
		}
		if !yesAll && !confirmStep("Rename ~/.polaris/ to ~/.revelara/?") {
			return ""
		}
		if err := os.Rename(polarisDir, newDir); err != nil {
			fmt.Fprintf(os.Stderr, "  [error]    Failed to rename config dir: %v\n", err)
			return ""
		}
		return "Renamed ~/.polaris/ -> ~/.revelara/"
	}

	return ""
}

// migrateConfigAPIURL updates api_url in config.yaml from relynce.ai to revelara.ai.
func migrateConfigAPIURL(home string, dryRun bool) string {
	// Try new location first, then old
	configPath := filepath.Join(home, ".revelara", "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = filepath.Join(home, ".relynce", "config.yaml")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return ""
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	content := string(data)
	if !strings.Contains(content, "relynce.ai") {
		return ""
	}

	if dryRun {
		return fmt.Sprintf("Would update api_url in %s (relynce.ai -> revelara.ai)", configPath)
	}

	updated := strings.ReplaceAll(content, "api.relynce.ai", "api.revelara.ai")
	if err := os.WriteFile(configPath, []byte(updated), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "  [error]    Failed to update config: %v\n", err)
		return ""
	}
	return fmt.Sprintf("Updated api_url in %s (relynce.ai -> revelara.ai)", configPath)
}

// migrateProjectConfig renames .relynce.yaml -> .revelara.yaml in the git root.
func migrateProjectConfig(gitRoot string, dryRun bool) string {
	revelaraPath := filepath.Join(gitRoot, ".revelara.yaml")
	if _, err := os.Stat(revelaraPath); err == nil {
		return "" // already migrated
	}

	relyncePath := filepath.Join(gitRoot, ".relynce.yaml")
	if _, err := os.Stat(relyncePath); err == nil {
		if dryRun {
			return "Would rename .relynce.yaml -> .revelara.yaml"
		}
		if err := os.Rename(relyncePath, revelaraPath); err != nil {
			fmt.Fprintf(os.Stderr, "  [error]    Failed to rename project config: %v\n", err)
			return ""
		}
		return "Renamed .relynce.yaml -> .revelara.yaml"
	}

	polarisPath := filepath.Join(gitRoot, ".polaris.yaml")
	if _, err := os.Stat(polarisPath); err == nil {
		if dryRun {
			return "Would rename .polaris.yaml -> .revelara.yaml"
		}
		if err := os.Rename(polarisPath, revelaraPath); err != nil {
			fmt.Fprintf(os.Stderr, "  [error]    Failed to rename project config: %v\n", err)
			return ""
		}
		return "Renamed .polaris.yaml -> .revelara.yaml"
	}

	return ""
}

// migrateClaudeMdMarkers replaces old RELYNCE MANAGED BLOCK markers with REVELARA.
func migrateClaudeMdMarkers(gitRoot string, dryRun bool) string {
	claudeMdPath := filepath.Join(gitRoot, "CLAUDE.md")
	data, err := os.ReadFile(claudeMdPath)
	if err != nil {
		return ""
	}

	content := string(data)
	oldStart := "<!-- BEGIN RELYNCE MANAGED BLOCK - DO NOT EDIT -->"
	oldEnd := "<!-- END RELYNCE MANAGED BLOCK -->"
	newStart := "<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->"
	newEnd := "<!-- END REVELARA MANAGED BLOCK -->"

	if !strings.Contains(content, oldStart) && !strings.Contains(content, oldEnd) {
		return ""
	}

	if dryRun {
		return "Would update CLAUDE.md managed block markers (RELYNCE -> REVELARA)"
	}

	content = strings.ReplaceAll(content, oldStart, newStart)
	content = strings.ReplaceAll(content, oldEnd, newEnd)

	if err := os.WriteFile(claudeMdPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "  [error]    Failed to update CLAUDE.md: %v\n", err)
		return ""
	}
	return "Updated CLAUDE.md managed block markers (RELYNCE -> REVELARA)"
}

// migrateAgentsMdHeader replaces ## Relynce with ## Revelara in AGENTS.md.
func migrateAgentsMdHeader(gitRoot string, dryRun bool) string {
	agentsMdPath := filepath.Join(gitRoot, "AGENTS.md")
	data, err := os.ReadFile(agentsMdPath)
	if err != nil {
		return ""
	}

	content := string(data)
	if !strings.Contains(content, "## Relynce\n") {
		return ""
	}

	if dryRun {
		return "Would update AGENTS.md section header (## Relynce -> ## Revelara)"
	}

	content = strings.Replace(content, "## Relynce\n", "## Revelara\n", 1)

	if err := os.WriteFile(agentsMdPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "  [error]    Failed to update AGENTS.md: %v\n", err)
		return ""
	}
	return "Updated AGENTS.md section header (## Relynce -> ## Revelara)"
}

// confirmStep prompts the user for a y/n confirmation.
func confirmStep(prompt string) bool {
	fmt.Printf("  %s [Y/n] ", prompt)
	var response string
	_, _ = fmt.Scanln(&response)
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "" || response == "y" || response == "yes"
}

func printMigrateUsage() {
	fmt.Println(`rvl migrate - Migrate from old naming conventions (relynce/rely) to new (revelara/rvl)

Usage:
  rvl migrate [flags]

Flags:
  -y, --yes      Auto-accept all migration steps
  --dry-run      Show what would change without modifying anything
  -h, --help     Show this help message

Steps performed:
  1. Config directory:   ~/.relynce/ -> ~/.revelara/
  2. Config API URL:     api.relynce.ai -> api.revelara.ai
  3. Project config:     .relynce.yaml -> .revelara.yaml
  4. CLAUDE.md markers:  RELYNCE MANAGED BLOCK -> REVELARA MANAGED BLOCK
  5. AGENTS.md header:   ## Relynce -> ## Revelara

This command is idempotent: running it multiple times is safe.
Already-migrated items are skipped automatically.`)
}
