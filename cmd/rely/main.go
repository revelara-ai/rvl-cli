// Package main provides the rely CLI for secure interaction with Relynce API.
// This CLI acts as a trusted intermediary - credentials are stored locally and
// never exposed to LLM contexts.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/relynce/rely-cli/internal/commands"
	"github.com/relynce/rely-cli/internal/plugin"
)

// version and gitHash are set at build time via -ldflags "-X main.version=... -X main.gitHash=..."
var version = "source-build"
var gitHash = "dev"

// migrateConfigDir copies ~/.polaris/ to ~/.relynce/ if the old dir exists but the new one doesn't.
func migrateConfigDir() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	oldDir := filepath.Join(home, ".polaris")
	newDir := filepath.Join(home, ".relynce")

	// Only migrate if old exists and new doesn't
	if _, err := os.Stat(oldDir); os.IsNotExist(err) {
		return
	}
	if _, err := os.Stat(newDir); err == nil {
		return // new dir already exists
	}

	// Copy old to new
	if err := os.MkdirAll(newDir, 0700); err != nil {
		return
	}
	entries, err := os.ReadDir(oldDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue // skip subdirectories for now
		}
		data, err := os.ReadFile(filepath.Join(oldDir, entry.Name()))
		if err != nil {
			continue
		}
		os.WriteFile(filepath.Join(newDir, entry.Name()), data, 0600)
	}
	fmt.Fprintf(os.Stderr, "Migrated configuration from ~/.polaris/ to ~/.relynce/\n")
}

func main() {
	// Auto-migrate config directory from ~/.polaris/ to ~/.relynce/
	migrateConfigDir()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "init":
		commands.CmdInit(os.Args[2:])
	case "login":
		commands.CmdLogin()
	case "logout":
		commands.CmdLogout()
	case "status":
		commands.CmdStatus(version, gitHash)
	case "scan":
		commands.CmdScan(os.Args[2:], version)
	case "risk":
		commands.CmdRisk(os.Args[2:])
	case "control":
		commands.CmdControl(os.Args[2:])
	case "knowledge":
		commands.CmdKnowledge(os.Args[2:])
	case "evidence":
		commands.CmdEvidence(os.Args[2:])
	case "config":
		commands.CmdConfig(os.Args[2:])
	case "commands":
		commands.CmdCommands(os.Args[2:])
	case "completion":
		commands.CmdCompletion(os.Args[2:])
	case "plugin":
		plugin.CmdPlugin(os.Args[2:])
	case "version":
		fmt.Printf("rely version %s (%s)\n", version, gitHash)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`rely - Secure CLI for Relynce reliability analysis

Usage:
  rely <command> [options]

Commands:
  init               Initialize Relynce for this repository
  login              Configure credentials interactively
  logout             Remove stored credentials
  status             Check connection and authentication status
  scan               Submit risk findings to Relynce
  risk               Manage risk lifecycle (list, close, resolve, etc.)
  control            Query reliability controls catalog
  knowledge          Query organizational knowledge base (facts, procedures, patterns)
  evidence           Manage control evidence (submit, list, verify)
  commands           List available skills and agents from the API
  plugin             Manage editor plugins (install, update, list, remove)
  completion         Generate shell completion scripts (bash, zsh, fish)
  config show        Show current configuration (API key masked)
  config set <k> <v> Set a configuration value
  version            Show version information
  help               Show this help message

Scan Command:
  rely scan --service <name> --stdin       Read findings JSON from stdin
  rely scan --service <name> --file <path> Read findings from file
  rely scan --service <name> --dry-run     Validate without submitting
  rely scan --target <path> --file <path>  Scan another project (service auto-resolved from .relynce.yaml)

Risk Command:
  rely risk list [--status=detected] [--service=name]  List risks
  rely risk show <risk-code>                           Show risk details with mapped controls
  rely risk stale [--service=name]                     List stale risks
  rely risk close <risk-code> [--reason="..."]         Close a risk
  rely risk resolve <risk-code> --reason="..."         Mark risk as resolved
  rely risk acknowledge <risk-code> [<risk-code>...]   Acknowledge risks
  rely risk accept <risk-code> --reason="..."          Accept risk (won't mitigate)

Control Command:
  rely control list [--category=<cat>]     List controls in catalog
  rely control show <control-code>         Show control details (e.g., RC-018)

Examples:
  # Initial setup
  rely login

  # Submit findings from Claude Code skill
  echo '{"findings":[...]}' | rely scan --service checkout-api --stdin

  # Scan a different project (service name auto-resolved from target's .relynce.yaml)
  rely scan --target /path/to/other-project --file findings.json

  # Check status
  rely status

  # Manage risks
  rely risk list --status=detected
  rely risk close R-001 --reason "Fixed by implementing timeout"
  rely risk stale --service checkout-api

  # Query controls catalog
  rely control list --category=fault_tolerance
  rely control show RC-018

  # Query knowledge base
  rely knowledge search "circuit breaker timeout"
  rely knowledge procedures --control=RC-018
  rely knowledge patterns --type=failure_mode

  # Submit evidence for controls
  rely evidence submit --control=RC-018 --type=code --name="Circuit breaker impl" --url="https://github.com/..."
  rely evidence list --status=configured
  rely evidence verify <evidence-id>

Plugin Command:
  rely plugin install <editor>      Install plugin for editor (claude, codex, gemini, cursor, windsurf, copilot, augment)
  rely plugin update [editor]       Update plugin(s) to latest version
  rely plugin list                  List installed plugins
  rely plugin remove <editor>       Remove installed plugin

Init Command:
  rely init                         Interactive initialization
  rely init --project <name>        Set project name non-interactively
  rely init --skip-plugin           Skip plugin installation
  rely init --force                 Overwrite existing config without prompting
  rely init -y                      Accept all defaults

Configuration:
  Credentials are stored in ~/.relynce/config.yaml
  Never share this file or expose credentials to LLM contexts.`)
}
