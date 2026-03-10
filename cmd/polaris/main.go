// Package main provides the polaris CLI for secure interaction with Polaris API.
// This CLI acts as a trusted intermediary - credentials are stored locally and
// never exposed to LLM contexts.
package main

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
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	configDir  = ".polaris"
	configFile = "config.yaml"
)

// version and gitHash are set at build time via -ldflags "-X main.version=... -X main.gitHash=..."
var version = "source-build"
var gitHash = "dev"

// Config holds the CLI configuration
type Config struct {
	APIURL  string `yaml:"api_url"`
	APIKey  string `yaml:"api_key"`
	OrgName string `yaml:"org_name"`

	// Runtime-only: resolved org UUID (not persisted to YAML)
	resolvedOrgID string
}

// ProjectConfig represents the .polaris.yaml project configuration file
type ProjectConfig struct {
	Project    string             `yaml:"project"`
	Components []ProjectComponent `yaml:"components"`
}

// ProjectComponent represents a component within a project
type ProjectComponent struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// ScanRequest matches the API request format
type ScanRequest struct {
	Service  string        `json:"service"`
	ScanType string        `json:"scan_type"`
	Findings []interface{} `json:"findings"`
	Metadata ScanMetadata  `json:"metadata,omitempty"`
}

// ScanMetadata contains scan context
type ScanMetadata struct {
	GitCommit string `json:"git_commit,omitempty"`
	GitBranch string `json:"git_branch,omitempty"`
	ScannerID string `json:"scanner_id,omitempty"`
}

// ScanResponse matches the API response format
type ScanResponse struct {
	ScanID    string       `json:"scan_id"`
	Service   string       `json:"service"`
	Summary   ScanSummary  `json:"summary"`
	Findings  []ScanResult `json:"findings"`
	Timestamp string       `json:"timestamp"`
}

// ScanSummary provides counts
type ScanSummary struct {
	Total     int `json:"total"`
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
}

// ScanResult represents the result of processing a single finding.
type ScanResult struct {
	RiskID   string `json:"risk_id"`
	RiskCode string `json:"risk_code"`
	Title    string `json:"title"`
	Status   string `json:"status"`   // created, updated, unchanged
	Score    int    `json:"score"`
	Priority string `json:"priority"` // critical, high, medium, low
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "init":
		cmdInit(os.Args[2:])
	case "login":
		cmdLogin()
	case "logout":
		cmdLogout()
	case "status":
		cmdStatus()
	case "scan":
		cmdScan(os.Args[2:])
	case "risk":
		cmdRisk(os.Args[2:])
	case "control":
		cmdControl(os.Args[2:])
	case "knowledge":
		cmdKnowledge(os.Args[2:])
	case "evidence":
		cmdEvidence(os.Args[2:])
	case "config":
		cmdConfig(os.Args[2:])
	case "plugin":
		cmdPlugin(os.Args[2:])
	case "version":
		fmt.Printf("polaris version %s (%s)\n", version, gitHash)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`polaris - Secure CLI for Polaris reliability analysis

Usage:
  polaris <command> [options]

Commands:
  init               Initialize Polaris for this repository
  login              Configure credentials interactively
  logout             Remove stored credentials
  status             Check connection and authentication status
  scan               Submit risk findings to Polaris
  risk               Manage risk lifecycle (list, close, resolve, etc.)
  control            Query reliability controls catalog
  knowledge          Query organizational knowledge base (facts, procedures, patterns)
  evidence           Manage control evidence (submit, list, verify)
  plugin             Manage editor plugins (install, update, list, remove)
  config show        Show current configuration (API key masked)
  config set <k> <v> Set a configuration value
  version            Show version information
  help               Show this help message

Scan Command:
  polaris scan --service <name> --stdin       Read findings JSON from stdin
  polaris scan --service <name> --file <path> Read findings from file
  polaris scan --service <name> --dry-run     Validate without submitting
  polaris scan --target <path> --file <path>  Scan another project (service auto-resolved from .polaris.yaml)

Risk Command:
  polaris risk list [--status=detected] [--service=name]  List risks
  polaris risk show <risk-code>                           Show risk details with mapped controls
  polaris risk stale [--service=name]                     List stale risks
  polaris risk close <risk-code> [--reason="..."]         Close a risk
  polaris risk resolve <risk-code> --reason="..."         Mark risk as resolved
  polaris risk acknowledge <risk-code> [<risk-code>...]   Acknowledge risks
  polaris risk accept <risk-code> --reason="..."          Accept risk (won't mitigate)

Control Command:
  polaris control list [--category=<cat>]     List controls in catalog
  polaris control show <control-code>         Show control details (e.g., RC-018)

Examples:
  # Initial setup
  polaris login

  # Submit findings from Claude Code skill
  echo '{"findings":[...]}' | polaris scan --service checkout-api --stdin

  # Scan a different project (service name auto-resolved from target's .polaris.yaml)
  polaris scan --target /path/to/other-project --file findings.json

  # Check status
  polaris status

  # Manage risks
  polaris risk list --status=detected
  polaris risk close R-001 --reason "Fixed by implementing timeout"
  polaris risk stale --service checkout-api

  # Query controls catalog
  polaris control list --category=fault_tolerance
  polaris control show RC-018

  # Query knowledge base
  polaris knowledge search "circuit breaker timeout"
  polaris knowledge procedures --control=RC-018
  polaris knowledge patterns --type=failure_mode

  # Submit evidence for controls
  polaris evidence submit --control=RC-018 --type=code --name="Circuit breaker impl" --url="https://github.com/..."
  polaris evidence list --status=configured
  polaris evidence verify <evidence-id>

Plugin Command:
  polaris plugin install <editor>      Install plugin for editor (claude, gemini, windsurf, cursor)
  polaris plugin update [editor]       Update plugin(s) to latest version
  polaris plugin list                  List installed plugins
  polaris plugin remove <editor>       Remove installed plugin

Init Command:
  polaris init                         Interactive initialization
  polaris init --project <name>        Set project name non-interactively
  polaris init --skip-plugin           Skip plugin installation
  polaris init --force                 Overwrite existing config without prompting
  polaris init -y                      Accept all defaults

Configuration:
  Credentials are stored in ~/.polaris/config.yaml
  Never share this file or expose credentials to LLM contexts.`)
}

// getConfigPath returns the path to the config file
func getConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, configDir, configFile)
}

// loadConfig loads configuration from disk
func loadConfig() (*Config, error) {
	path := getConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No config yet
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// saveConfig saves configuration to disk
func saveConfig(cfg *Config) error {
	path := getConfigPath()
	dir := filepath.Dir(path)

	// Create directory with restricted permissions
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Write with restricted permissions (owner read/write only)
	return os.WriteFile(path, data, 0600)
}

// cmdLogin handles the login command
func cmdLogin() {
	reader := bufio.NewReader(os.Stdin)

	// Load existing config if any
	cfg, _ := loadConfig()
	if cfg == nil {
		cfg = &Config{}
	}

	// Prompt for API URL
	defaultURL := cfg.APIURL
	if defaultURL == "" {
		defaultURL = "https://api-dev.relynce.ai"
	}
	fmt.Printf("Polaris API URL [%s]: ", defaultURL)
	apiURL, _ := reader.ReadString('\n')
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = defaultURL
	}
	cfg.APIURL = apiURL

	// Prompt for API Key (hidden input, keep existing if user presses Enter)
	if cfg.APIKey != "" {
		masked := cfg.APIKey[:8] + "..." + cfg.APIKey[len(cfg.APIKey)-4:]
		fmt.Printf("API Key [%s] (Enter to keep): ", masked)
	} else {
		fmt.Print("API Key: ")
	}
	apiKeyBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // New line after hidden input
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading API key: %v\n", err)
		os.Exit(1)
	}
	apiKey := strings.TrimSpace(string(apiKeyBytes))
	if apiKey != "" {
		cfg.APIKey = apiKey
	}
	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key is required")
		os.Exit(1)
	}

	// Prompt for Organization name (optional)
	defaultOrg := cfg.OrgName
	fmt.Printf("Organization name [%s]: ", defaultOrg)
	orgName, _ := reader.ReadString('\n')
	orgName = strings.TrimSpace(orgName)
	if orgName == "" {
		orgName = defaultOrg
	}
	cfg.OrgName = orgName

	// Resolve organization name to UUID and validate credentials
	fmt.Println("\nValidating credentials...")
	if cfg.OrgName != "" {
		if err := resolveOrganizationID(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Organization resolved: %s -> %s\n", cfg.OrgName, cfg.resolvedOrgID)
	}
	if err := validateCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Save config
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Configuration saved to ~/.polaris/config.yaml")
}

// cmdLogout removes stored credentials
func cmdLogout() {
	path := getConfigPath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No credentials stored.")
			return
		}
		fmt.Fprintf(os.Stderr, "Error removing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Credentials removed.")
}

// cmdStatus checks connection and auth status
func cmdStatus() {
	cfg := loadAndResolveConfig()

	fmt.Printf("Polaris CLI v%s (%s)\n", version, gitHash)
	fmt.Printf("API URL: %s\n", cfg.APIURL)
	if len(cfg.APIKey) > 8 {
		fmt.Printf("API Key: %s...%s\n", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
	} else {
		fmt.Println("API Key: (set)")
	}
	if cfg.OrgName != "" {
		fmt.Printf("Organization: %s\n", cfg.OrgName)
	}

	fmt.Println("\nChecking connection...")
	if err := validateCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Status: Connected")

	// Check installed plugins with version comparison
	fmt.Println("\nPlugins:")
	serverVersion := fetchServerPluginVersion(cfg)
	plugins, err := getInstalledPlugins()
	if err != nil || len(plugins) == 0 {
		fmt.Println("  No plugins installed")
		fmt.Println("  Run 'polaris plugin install <editor>' to install")
		fmt.Println("  Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
	} else {
		for _, p := range plugins {
			if serverVersion != "" && p.Version != serverVersion {
				fmt.Printf("  %s: v%s (update available: v%s)\n", p.Editor, p.Version, serverVersion)
				fmt.Printf("    Run 'polaris plugin update %s' to upgrade\n", p.Editor)
			} else if serverVersion != "" {
				fmt.Printf("  %s: v%s (up to date)\n", p.Editor, p.Version)
			} else {
				fmt.Printf("  %s: v%s\n", p.Editor, p.Version)
			}
		}
	}
}

// fetchServerPluginVersion queries the API for the latest plugin version.
// Returns empty string if the server is unreachable or returns an error.
func fetchServerPluginVersion(cfg *Config) string {
	if cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/plugin", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	return result.Version
}

// cmdPlugin handles plugin management (install, update, list, remove).
func cmdPlugin(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `Usage: polaris plugin <command>

Commands:
  install <editor>   Install skills for editor (claude, codex, gemini, cursor, windsurf, copilot, augment)
  update [editor]    Update skills to latest version
  list               List installed skills
  remove <editor>    Remove installed skills

Examples:
  polaris plugin install claude    Install Claude Code plugin
  polaris plugin install codex     Install Codex CLI skills
  polaris plugin install gemini    Install Gemini CLI skills + agents
  polaris plugin update            Update all installed plugins
  polaris plugin list              Show installed plugins`)
		os.Exit(1)
	}

	switch args[0] {
	case "install":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: polaris plugin install <editor>")
			fmt.Fprintln(os.Stderr, "Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
			os.Exit(1)
		}
		editor := args[1]
		if err := installPlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "update":
		editor := ""
		if len(args) >= 2 {
			editor = args[1]
		}
		if err := updatePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		listInstalledPlugins()
	case "remove", "uninstall":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: editor name required")
			fmt.Fprintln(os.Stderr, "Usage: polaris plugin remove <editor>")
			os.Exit(1)
		}
		editor := args[1]
		if err := removePlugin(editor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown plugin command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: polaris plugin <install|update|list|remove>")
		os.Exit(1)
	}
}

// cmdConfig handles config subcommands
func cmdConfig(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: polaris config <show|set>")
		os.Exit(1)
	}

	switch args[0] {
	case "show":
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if cfg == nil {
			fmt.Println("No configuration found. Run 'polaris login' first.")
			return
		}
		fmt.Printf("api_url: %s\n", cfg.APIURL)
		if len(cfg.APIKey) > 8 {
			fmt.Printf("api_key: %s...%s\n", cfg.APIKey[:4], cfg.APIKey[len(cfg.APIKey)-4:])
		} else {
			fmt.Println("api_key: (set)")
		}
		fmt.Printf("org_name: %s\n", cfg.OrgName)

	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: polaris config set <key> <value>")
			os.Exit(1)
		}
		key, value := args[1], args[2]
		cfg, _ := loadConfig()
		if cfg == nil {
			cfg = &Config{}
		}
		switch key {
		case "api_url":
			cfg.APIURL = value
		case "api_key":
			cfg.APIKey = value
		case "org_name":
			cfg.OrgName = value
		default:
			fmt.Fprintf(os.Stderr, "Unknown config key: %s\n", key)
			fmt.Fprintln(os.Stderr, "Valid keys: api_url, api_key, org_name")
			os.Exit(1)
		}
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Set %s = %s\n", key, value)

	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", args[0])
		os.Exit(1)
	}
}

// cmdScan handles the scan command
func cmdScan(args []string) {
	var service string
	var inputFile string
	var useStdin bool
	var dryRun bool
	var targetDir string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--service", "-s":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --service requires a value")
				os.Exit(1)
			}
			i++
			service = args[i]
		case "--target", "-t":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --target requires a value")
				os.Exit(1)
			}
			i++
			targetDir = args[i]
		case "--stdin":
			useStdin = true
		case "--file", "-f":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --file requires a value")
				os.Exit(1)
			}
			i++
			inputFile = args[i]
		case "--dry-run":
			dryRun = true
		default:
			if strings.HasPrefix(args[i], "--target=") {
				targetDir = strings.TrimPrefix(args[i], "--target=")
			} else if !strings.HasPrefix(args[i], "-") && service == "" {
				// If no flag, treat as service name for convenience
				service = args[i]
			}
		}
	}

	// Validate target directory if specified
	if targetDir != "" {
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid target path: %v\n", err)
			os.Exit(1)
		}
		info, err := os.Stat(absTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: target directory does not exist: %s\n", absTarget)
			os.Exit(1)
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: target is not a directory: %s\n", absTarget)
			os.Exit(1)
		}
		targetDir = absTarget
	}

	// Auto-resolve service name from target project's .polaris.yaml if --service not provided
	if service == "" && targetDir != "" {
		if projectCfg := loadProjectConfigFrom(targetDir); projectCfg != nil && projectCfg.Project != "" {
			service = projectCfg.Project
		}
	}

	if service == "" {
		fmt.Fprintln(os.Stderr, "Error: --service is required (or use --target with a project that has .polaris.yaml)")
		fmt.Fprintln(os.Stderr, "Usage: polaris scan --service <name> [--stdin|--file <path>] [--target <path>] [--dry-run]")
		os.Exit(1)
	}

	// Load config
	cfg := loadAndResolveConfig()

	// Read input
	var err error
	var inputData []byte
	if useStdin {
		inputData, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	} else if inputFile != "" {
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: Must specify --stdin or --file")
		os.Exit(1)
	}

	// Parse input - could be full ScanRequest or just findings array
	var scanReq ScanRequest
	if err := json.Unmarshal(inputData, &scanReq); err != nil {
		// Try parsing as just findings array
		var findings []interface{}
		if err2 := json.Unmarshal(inputData, &findings); err2 != nil {
			fmt.Fprintf(os.Stderr, "Error parsing input: %v\n", err)
			os.Exit(1)
		}
		scanReq.Findings = findings
	}

	// Set service and metadata
	scanReq.Service = service
	if scanReq.ScanType == "" {
		scanReq.ScanType = "full"
	}
	scanReq.Metadata.ScannerID = "polaris-cli-" + version

	// Map findings to components from .polaris.yaml (deterministic)
	if projectCfg := loadProjectConfigFrom(targetDir); projectCfg != nil && len(projectCfg.Components) > 0 {
		mapFindingsToComponents(scanReq.Findings, projectCfg)
	}

	// Dry run - just validate and show what would be sent
	if dryRun {
		fmt.Printf("Dry run - would submit to %s:\n", cfg.APIURL)
		fmt.Printf("  Service: %s\n", scanReq.Service)
		if targetDir != "" {
			fmt.Printf("  Target: %s\n", targetDir)
		}
		fmt.Printf("  Findings: %d\n", len(scanReq.Findings))
		fmt.Printf("  Scan Type: %s\n", scanReq.ScanType)
		return
	}

	// Submit to API
	response, err := submitScan(cfg, &scanReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Output results
	fmt.Printf("Scan submitted successfully\n")
	fmt.Printf("  Scan ID: %s\n", response.ScanID)
	fmt.Printf("  Service: %s\n", response.Service)
	fmt.Printf("  Total: %d (Created: %d, Updated: %d, Unchanged: %d)\n",
		response.Summary.Total, response.Summary.Created,
		response.Summary.Updated, response.Summary.Unchanged)
	if response.Summary.Critical > 0 || response.Summary.High > 0 {
		fmt.Printf("  Priority: Critical=%d, High=%d, Medium=%d, Low=%d\n",
			response.Summary.Critical, response.Summary.High,
			response.Summary.Medium, response.Summary.Low)
	}
	fmt.Println()

	// Print individual findings with risk codes
	if len(response.Findings) > 0 {
		fmt.Println("Findings:")
		for _, f := range response.Findings {
			status := f.Status
			if status == "created" {
				status = "NEW"
			} else if status == "updated" {
				status = "UPD"
			} else {
				status = "---"
			}
			fmt.Printf("  [%s] %s: %s (score: %d, %s)\n",
				status, f.RiskCode, f.Title, f.Score, f.Priority)
		}
		fmt.Println()
	}

	fmt.Printf("View results: %s/risks\n", cfg.APIURL)
}

// loadAndResolveConfig loads config and resolves org name to UUID.
func loadAndResolveConfig() *Config {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if cfg == nil || cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: Not configured. Run 'polaris login' first.")
		os.Exit(1)
	}
	if err := resolveOrganizationID(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// resolveOrganizationID resolves an org name to its UUID by listing the user's orgs.
func resolveOrganizationID(cfg *Config) error {
	if cfg.OrgName == "" {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/organizations", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("fetch organizations failed (status %d)", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var orgsResp struct {
		Organizations []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"organizations"`
	}
	if err := json.Unmarshal(body, &orgsResp); err != nil {
		return fmt.Errorf("parse organizations: %w", err)
	}

	for _, org := range orgsResp.Organizations {
		if strings.EqualFold(org.Name, cfg.OrgName) {
			cfg.resolvedOrgID = org.ID
			return nil
		}
	}

	// List available org names to help the user
	names := make([]string, len(orgsResp.Organizations))
	for i, org := range orgsResp.Organizations {
		names[i] = org.Name
	}
	return fmt.Errorf("organization %q not found; available: %s", cfg.OrgName, strings.Join(names, ", "))
}

// validateCredentials checks if credentials are valid
func validateCredentials(cfg *Config) error {
	// Try to call a simple endpoint to validate
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/risks/stats", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.resolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.resolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("authentication failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server error (status %d)", resp.StatusCode)
	}

	return nil
}

// submitScan sends findings to the API
func submitScan(cfg *Config, scanReq *ScanRequest) (*ScanResponse, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(scanReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.APIURL+"/api/v1/risks/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.resolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.resolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed - run 'polaris login' to reconfigure")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	var scanResp ScanResponse
	if err := json.Unmarshal(respBody, &scanResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &scanResp, nil
}

// ============================================================================
// Risk Lifecycle Commands
// ============================================================================

// Risk represents a risk from the API
type Risk struct {
	ID           string   `json:"id"`
	RiskCode     string   `json:"risk_code"`
	Title        string   `json:"title"`
	Category     string   `json:"category"`
	Score        int      `json:"score"`
	Status       string   `json:"status"`
	Services     []string `json:"linked_services"`
	ControlCodes []string `json:"control_codes,omitempty"`
	StaleSince   string   `json:"stale_since,omitempty"`
	LastSeenAt   string   `json:"last_seen_at,omitempty"`
	ResolvedAt   string   `json:"resolved_at,omitempty"`
	ClosedAt     string   `json:"closed_at,omitempty"`
}

// RiskDetail represents a full risk response with mapped controls
type RiskDetail struct {
	Risk
	MappedControls []MappedControl `json:"mapped_controls,omitempty"`
	Narrative      string          `json:"narrative,omitempty"`
}

// MappedControl represents a control mapped to a risk
type MappedControl struct {
	ControlCode string `json:"control_code"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category"`
	Type        string `json:"type"`
	Objective   string `json:"objective,omitempty"`
}

// ListRisksResponse matches the API response
type ListRisksResponse struct {
	Risks []Risk `json:"risks"`
	Total int    `json:"total"`
}

// cmdRisk handles the risk command
func cmdRisk(args []string) {
	if len(args) == 0 {
		printRiskUsage()
		os.Exit(1)
	}

	subcmd := args[0]
	switch subcmd {
	case "list":
		cmdRiskList(args[1:])
	case "show":
		cmdRiskShow(args[1:])
	case "context":
		cmdRiskContext(args[1:])
	case "stale":
		cmdRiskStale(args[1:])
	case "close":
		cmdRiskClose(args[1:])
	case "resolve":
		cmdRiskResolve(args[1:])
	case "acknowledge", "ack":
		cmdRiskAcknowledge(args[1:])
	case "accept":
		cmdRiskAccept(args[1:])
	case "help", "--help", "-h":
		printRiskUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown risk command: %s\n", subcmd)
		printRiskUsage()
		os.Exit(1)
	}
}

func printRiskUsage() {
	fmt.Println(`polaris risk - Manage risk lifecycle

Usage:
  polaris risk <subcommand> [options]

Subcommands:
  list                List risks with optional filters
  show                Show risk details with mapped controls
  context             Get unified risk context (risk + controls + knowledge + incidents)
  stale               List stale risks (not seen in recent scans)
  close               Close a risk
  resolve             Mark a risk as resolved
  acknowledge (ack)   Acknowledge risks
  accept              Accept a risk (won't mitigate)

List Options:
  --status=<status>   Filter by status (detected, acknowledged, accepted, mitigating, resolved, closed, archived)
  --service=<name>    Filter by service name
  --limit=<n>         Maximum results (default 20)

Examples:
  polaris risk list
  polaris risk show R-009
  polaris risk list --status=detected --service=checkout-api
  polaris risk stale --service=checkout-api
  polaris risk close R-001 --reason "Implemented circuit breaker"
  polaris risk resolve R-002 --reason "Added timeout to all DB queries"
  polaris risk acknowledge R-003 R-004 R-005
  polaris risk accept R-006 --reason "Low impact, cost of fix exceeds benefit"`)
}

// cmdRiskList lists risks
func cmdRiskList(args []string) {
	var status, service string
	limit := 20

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--status=") {
			status = strings.TrimPrefix(arg, "--status=")
		} else if strings.HasPrefix(arg, "--service=") {
			service = strings.TrimPrefix(arg, "--service=")
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	// Build URL with query params
	url := cfg.APIURL + "/api/v1/risks?limit=" + fmt.Sprintf("%d", limit)
	if status != "" {
		url += "&status=" + status
	}
	if service != "" {
		url += "&service=" + service
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var listResp ListRisksResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(listResp.Risks) == 0 {
		fmt.Println("No risks found.")
		return
	}

	fmt.Printf("Found %d risks:\n\n", listResp.Total)
	for _, r := range listResp.Risks {
		statusBadge := formatStatus(r.Status)
		priority := formatPriority(r.Score)
		services := strings.Join(r.Services, ", ")
		if services == "" {
			services = "-"
		}
		fmt.Printf("%-7s %s [%s] %s\n", r.RiskCode, statusBadge, priority, r.Title)
		fmt.Printf("        Services: %s\n", services)
		if len(r.ControlCodes) > 0 {
			fmt.Printf("        Controls: %s\n", strings.Join(r.ControlCodes, ", "))
		}
	}
}

// cmdRiskShow shows risk details with mapped controls
func cmdRiskShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: risk code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris risk show <risk-code>")
		os.Exit(1)
	}

	riskCode := args[0]

	cfg := loadAndResolveConfig()

	// First, find the risk ID by code
	riskID, err := findRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Fetch full risk details
	url := cfg.APIURL + "/api/v1/risks/" + riskID

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var riskDetail RiskDetail
	if err := json.Unmarshal(resp, &riskDetail); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// Display risk details
	priority := formatPriority(riskDetail.Score)
	statusBadge := formatStatus(riskDetail.Status)
	fmt.Printf("Risk: %s - %s\n", riskDetail.RiskCode, riskDetail.Title)
	fmt.Printf("Category: %s\n", riskDetail.Category)
	fmt.Printf("Status: %s\n", statusBadge)
	fmt.Printf("Score: %d (%s)\n", riskDetail.Score, priority)

	if riskDetail.Narrative != "" {
		fmt.Println()
		fmt.Printf("Narrative:\n  %s\n", wrapText(riskDetail.Narrative, 78, "  "))
	}

	if len(riskDetail.MappedControls) > 0 {
		fmt.Println()
		fmt.Println("Mapped Controls:")
		for _, ctrl := range riskDetail.MappedControls {
			typeBadge := formatControlType(ctrl.Type)
			fmt.Printf("  %s %s %s\n", ctrl.ControlCode, typeBadge, ctrl.Name)
			if ctrl.Description != "" {
				fmt.Printf("    %s\n", wrapText(ctrl.Description, 74, "    "))
			}
		}

		fmt.Println()
		fmt.Println("To implement these controls:")
		for _, ctrl := range riskDetail.MappedControls {
			fmt.Printf("  polaris control show %s\n", ctrl.ControlCode)
		}
		if len(riskDetail.MappedControls) > 0 {
			fmt.Printf("  /polaris:control-guidance %s\n", riskDetail.MappedControls[0].ControlCode)
		}
	} else if len(riskDetail.ControlCodes) > 0 {
		fmt.Println()
		fmt.Printf("Control Codes: %s\n", strings.Join(riskDetail.ControlCodes, ", "))
	}
}

// RiskContextResponse represents the unified risk context from the API.
type RiskContextResponse struct {
	Risk           RiskDetail              `json:"risk"`
	Controls       []ControlContextItem    `json:"controls"`
	Knowledge      KnowledgeContextResp    `json:"knowledge"`
	ServiceContext *ServiceContextResp     `json:"service_context,omitempty"`
	ScoreBreakdown []ScoreFactorResp       `json:"score_breakdown,omitempty"`
}

// ControlContextItem is a control with evidence and gaps.
type ControlContextItem struct {
	Control          MappedControl        `json:"control"`
	ExistingEvidence []ContextEvidenceItem `json:"existing_evidence"`
	EvidenceGaps     []string             `json:"evidence_gaps"`
}

// ContextEvidenceItem represents a piece of control evidence in the context response.
type ContextEvidenceItem struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	URL         string `json:"url_or_identifier,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
}

// KnowledgeContextResp contains knowledge items relevant to the risk.
type KnowledgeContextResp struct {
	Patterns   []PatternItem   `json:"patterns"`
	Procedures []ProcedureItem `json:"procedures"`
	Facts      []FactItem      `json:"facts"`
}

// PatternItem represents a knowledge pattern with causal chain.
type PatternItem struct {
	Title              string      `json:"title"`
	PatternType        string      `json:"pattern_type"`
	CausalChain        []ChainLink `json:"causal_chain,omitempty"`
	TriggerEvent       string      `json:"trigger_event,omitempty"`
	OccurrenceCount    int         `json:"occurrence_count"`
	TypicalMTTR        string      `json:"typical_mttr,omitempty"`
	TypicalBlastRadius string      `json:"typical_blast_radius,omitempty"`
	PreventionStrategies []string  `json:"prevention_strategies,omitempty"`
	Score              float64     `json:"score"`
}

// ChainLink is a single event in a causal chain.
type ChainLink struct {
	Order        int    `json:"order"`
	Event        string `json:"event"`
	TypicalDelay string `json:"typical_delay,omitempty"`
}

// ProcedureItem represents a remediation procedure.
type ProcedureItem struct {
	Title              string  `json:"title"`
	EffectivenessScore float64 `json:"effectiveness_score"`
	AppliedCount       int     `json:"applied_count"`
	SuccessCount       int     `json:"success_count"`
	RelatedControls    []string `json:"related_controls,omitempty"`
	Score              float64 `json:"score"`
}

// FactItem represents a validated reliability fact.
type FactItem struct {
	Content          string  `json:"content"`
	Confidence       float64 `json:"confidence"`
	ValidationStatus string  `json:"validation_status"`
	Score            float64 `json:"score"`
}

// ServiceContextResp contains service-specific incident history.
type ServiceContextResp struct {
	ServiceName  string               `json:"service_name"`
	Tier         string               `json:"tier,omitempty"`
	Incidents    *IncidentHistoryResp `json:"incidents,omitempty"`
}

// IncidentHistoryResp contains historical incident stats.
type IncidentHistoryResp struct {
	TotalIncidents  int    `json:"total_incidents"`
	Last30Days      int    `json:"last_30_days"`
	Last90Days      int    `json:"last_90_days"`
	CriticalCount   int    `json:"critical_count"`
	HighCount       int    `json:"high_count"`
	MostRecentTitle string `json:"most_recent_title,omitempty"`
	AverageMTTR     *int   `json:"average_mttr,omitempty"`
}

// ScoreFactorResp explains one component of the risk score.
type ScoreFactorResp struct {
	Description string `json:"description"`
	Points      int    `json:"points"`
	Source      string `json:"source"`
}

// cmdRiskContext fetches unified risk context for risk guidance.
func cmdRiskContext(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: risk code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris risk context <risk-code> [--format=json]")
		os.Exit(1)
	}

	riskCode := args[0]
	formatJSON := false
	for _, a := range args[1:] {
		if a == "--format=json" {
			formatJSON = true
		}
	}

	cfg := loadAndResolveConfig()

	// Resolve risk code to UUID
	riskID, err := findRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	url := cfg.APIURL + "/api/v1/risks/" + riskID + "/context"
	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if formatJSON {
		fmt.Println(string(resp))
		return
	}

	var ctx RiskContextResponse
	if err := json.Unmarshal(resp, &ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	printRiskContext(ctx)
}

func printRiskContext(ctx RiskContextResponse) {
	// Risk overview
	priority := formatPriority(ctx.Risk.Score)
	statusBadge := formatStatus(ctx.Risk.Status)
	fmt.Printf("Risk: %s - %s\n", ctx.Risk.RiskCode, ctx.Risk.Title)
	fmt.Printf("Category: %s | Status: %s | Score: %d (%s)\n",
		ctx.Risk.Category, statusBadge, ctx.Risk.Score, priority)

	if ctx.Risk.Narrative != "" {
		fmt.Println()
		fmt.Printf("Narrative:\n  %s\n", wrapText(ctx.Risk.Narrative, 78, "  "))
	}

	// Score breakdown
	if len(ctx.ScoreBreakdown) > 0 {
		fmt.Println()
		fmt.Println("Score Breakdown:")
		for _, f := range ctx.ScoreBreakdown {
			fmt.Printf("  +%d pts: %s (%s)\n", f.Points, f.Description, f.Source)
		}
	}

	// Causal chains from patterns
	if len(ctx.Knowledge.Patterns) > 0 {
		for _, p := range ctx.Knowledge.Patterns {
			if len(p.CausalChain) > 0 {
				fmt.Println()
				fmt.Printf("Failure Chain: %s (observed %d times)\n", p.Title, p.OccurrenceCount)
				for i, link := range p.CausalChain {
					fmt.Printf("  %d. %s\n", link.Order, link.Event)
					if i < len(p.CausalChain)-1 && link.TypicalDelay != "" {
						fmt.Printf("     ↓ (%s)\n", link.TypicalDelay)
					}
				}
				if p.TypicalBlastRadius != "" || p.TypicalMTTR != "" {
					fmt.Printf("  → Blast radius: %s | Typical MTTR: %s\n", p.TypicalBlastRadius, p.TypicalMTTR)
				}
				break // Show the top pattern's chain
			}
		}
	}

	// Service incident history
	if ctx.ServiceContext != nil && ctx.ServiceContext.Incidents != nil {
		inc := ctx.ServiceContext.Incidents
		fmt.Println()
		fmt.Printf("Service: %s (tier: %s)\n", ctx.ServiceContext.ServiceName, ctx.ServiceContext.Tier)
		fmt.Printf("  Incidents: %d total (%d in last 30 days)\n", inc.TotalIncidents, inc.Last30Days)
		if inc.CriticalCount > 0 || inc.HighCount > 0 {
			fmt.Printf("  Severity: %d critical, %d high\n", inc.CriticalCount, inc.HighCount)
		}
		if inc.AverageMTTR != nil {
			fmt.Printf("  Avg MTTR: %d minutes\n", *inc.AverageMTTR)
		}
		if inc.MostRecentTitle != "" {
			fmt.Printf("  Most recent: %s\n", inc.MostRecentTitle)
		}
	}

	// Controls with evidence status
	if len(ctx.Controls) > 0 {
		fmt.Println()
		fmt.Println("Controls:")
		for _, cc := range ctx.Controls {
			evidenceStatus := "✓ has evidence"
			if len(cc.ExistingEvidence) == 0 {
				evidenceStatus = "✗ no evidence"
			} else if len(cc.EvidenceGaps) > 0 {
				evidenceStatus = fmt.Sprintf("◐ partial (missing: %s)", strings.Join(cc.EvidenceGaps, ", "))
			}
			fmt.Printf("  %s [%s] %s — %s\n",
				cc.Control.ControlCode, cc.Control.Type, cc.Control.Name, evidenceStatus)
		}
	}

	// Proven procedures
	if len(ctx.Knowledge.Procedures) > 0 {
		fmt.Println()
		fmt.Println("Proven Remediation Approaches:")
		for i, p := range ctx.Knowledge.Procedures {
			label := ""
			if i == 0 {
				label = " [Recommended]"
			}
			successRate := 0.0
			if p.AppliedCount > 0 {
				successRate = float64(p.SuccessCount) / float64(p.AppliedCount) * 100
			}
			fmt.Printf("  %d.%s %s (%.0f%% success, applied %d times)\n",
				i+1, label, p.Title, successRate, p.AppliedCount)
		}
	}

	// Relevant facts
	if len(ctx.Knowledge.Facts) > 0 {
		fmt.Println()
		fmt.Println("Key Facts:")
		for _, f := range ctx.Knowledge.Facts {
			badge := ""
			if f.ValidationStatus == "analyst_validated" {
				badge = " [validated]"
			}
			fmt.Printf("  • %s%s\n", f.Content, badge)
		}
	}

	// Quick reference
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Printf("  /polaris:risk-guidance %s    — Full remediation plan\n", ctx.Risk.RiskCode)
	fmt.Printf("  /polaris:remediate-risks %s  — Auto-implement fixes\n", ctx.Risk.RiskCode)
}

// cmdRiskStale lists stale risks
func cmdRiskStale(args []string) {
	var service string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--service=") {
			service = strings.TrimPrefix(arg, "--service=")
		}
	}

	cfg := loadAndResolveConfig()

	url := cfg.APIURL + "/api/v1/risks/stale"
	if service != "" {
		url += "?service=" + service
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var listResp ListRisksResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(listResp.Risks) == 0 {
		fmt.Println("No stale risks found.")
		return
	}

	fmt.Printf("Found %d stale risks (not seen in recent scans):\n\n", listResp.Total)
	for _, r := range listResp.Risks {
		priority := formatPriority(r.Score)
		staleSince := r.StaleSince
		if staleSince == "" {
			staleSince = "unknown"
		} else if len(staleSince) > 10 {
			staleSince = staleSince[:10]
		}
		fmt.Printf("%-7s [%s] %s (stale since %s)\n", r.RiskCode, priority, r.Title, staleSince)
	}
}

// cmdRiskClose closes a risk
func cmdRiskClose(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: risk code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris risk close <risk-code> [--reason=\"...\"]")
		os.Exit(1)
	}

	riskCode := args[0]
	var reason string

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--reason=") {
			reason = strings.TrimPrefix(arg, "--reason=")
		}
	}

	cfg := loadAndResolveConfig()

	// First, find the risk ID by code
	riskID, err := findRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Close the risk
	body := map[string]string{"reason": reason}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/v1/risks/" + riskID + "/close"
	_, err = makeAPIRequest(cfg, "POST", url, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Risk %s closed.\n", riskCode)
}

// cmdRiskResolve resolves a risk
func cmdRiskResolve(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: risk code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris risk resolve <risk-code> --reason=\"...\"")
		os.Exit(1)
	}

	riskCode := args[0]
	var reason string

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--reason=") {
			reason = strings.TrimPrefix(arg, "--reason=")
		}
	}

	if reason == "" {
		fmt.Fprintln(os.Stderr, "Error: --reason is required when resolving a risk")
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	// Find the risk ID by code
	riskID, err := findRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Resolve the risk
	body := map[string]string{"reason": reason}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/v1/risks/" + riskID + "/resolve"
	_, err = makeAPIRequest(cfg, "POST", url, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Risk %s resolved.\n", riskCode)
}

// cmdRiskAcknowledge acknowledges one or more risks
func cmdRiskAcknowledge(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one risk code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris risk acknowledge <risk-code> [<risk-code>...]")
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	for _, riskCode := range args {
		if strings.HasPrefix(riskCode, "-") {
			continue // Skip flags
		}

		// Find the risk ID by code
		riskID, err := findRiskIDByCode(cfg, riskCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s - %v\n", riskCode, err)
			continue
		}

		// Update status to acknowledged
		body := map[string]string{"status": "acknowledged"}
		bodyBytes, _ := json.Marshal(body)

		url := cfg.APIURL + "/api/v1/risks/" + riskID + "/status"
		_, err = makeAPIRequest(cfg, "PATCH", url, bodyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error acknowledging %s: %v\n", riskCode, err)
			continue
		}

		fmt.Printf("Risk %s acknowledged.\n", riskCode)
	}
}

// cmdRiskAccept accepts a risk (intentionally not mitigating)
func cmdRiskAccept(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: risk code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris risk accept <risk-code> --reason=\"...\"")
		os.Exit(1)
	}

	riskCode := args[0]
	var reason string

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--reason=") {
			reason = strings.TrimPrefix(arg, "--reason=")
		}
	}

	if reason == "" {
		fmt.Fprintln(os.Stderr, "Error: --reason is required when accepting a risk")
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	riskID, err := findRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	body := map[string]string{"status": "accepted", "reason": reason}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/v1/risks/" + riskID + "/status"
	_, err = makeAPIRequest(cfg, "PATCH", url, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Risk %s accepted: %s\n", riskCode, reason)
}

// findRiskIDByCode looks up a risk by its code and returns its UUID
func findRiskIDByCode(cfg *Config, riskCode string) (string, error) {
	// List risks and find the one with matching code
	url := cfg.APIURL + "/api/v1/risks?limit=100"
	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		return "", err
	}

	var listResp ListRisksResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	for _, r := range listResp.Risks {
		if r.RiskCode == riskCode {
			return r.ID, nil
		}
	}

	return "", fmt.Errorf("risk %s not found", riskCode)
}

// makeAPIRequest makes an authenticated API request
func makeAPIRequest(cfg *Config, method, url string, body []byte) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if cfg.resolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.resolvedOrgID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed - run 'polaris login' to reconfigure")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// formatStatus formats risk status for display
func formatStatus(status string) string {
	switch status {
	case "detected":
		return "[DETECTED]"
	case "acknowledged":
		return "[ACKNOWLEDGED]"
	case "accepted":
		return "[ACCEPTED]"
	case "mitigating":
		return "[MITIGATING]"
	case "resolved":
		return "[RESOLVED]"
	case "closed":
		return "[CLOSED]"
	case "archived":
		return "[ARCHIVED]"
	default:
		return "[" + strings.ToUpper(status) + "]"
	}
}

// formatPriority formats risk score as priority
func formatPriority(score int) string {
	if score >= 20 {
		return "CRITICAL"
	} else if score >= 15 {
		return "HIGH"
	} else if score >= 10 {
		return "MEDIUM"
	}
	return "LOW"
}

// ============================================================================
// Control Catalog Commands
// ============================================================================

// Control represents a control from the API
type Control struct {
	ID                    string   `json:"id"`
	ControlCode           string   `json:"control_code"`
	Name                  string   `json:"name"`
	Category              string   `json:"category"`
	Type                  string   `json:"type"`
	Objective             string   `json:"objective"`
	Description           string   `json:"description"`
	RiskStatement         string   `json:"risk_statement,omitempty"`
	TestDescription       string   `json:"test_description,omitempty"`
	Remediation           string   `json:"remediation,omitempty"`
	ExpectedEvidenceTypes []string `json:"expected_evidence_types"`
	Treatment             string   `json:"treatment,omitempty"`
	Weight                int      `json:"weight"`
	Implementation        string   `json:"implementation,omitempty"`
	RiskCodes             []string `json:"risk_codes,omitempty"`
}

// ListControlsResponse matches the API response
type ListControlsResponse struct {
	Controls []Control `json:"controls"`
	Total    int       `json:"total"`
}

// cmdControl handles the control command
func cmdControl(args []string) {
	if len(args) == 0 {
		printControlUsage()
		os.Exit(1)
	}

	subcmd := args[0]
	switch subcmd {
	case "list":
		cmdControlList(args[1:])
	case "show":
		cmdControlShow(args[1:])
	case "help", "--help", "-h":
		printControlUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown control command: %s\n", subcmd)
		printControlUsage()
		os.Exit(1)
	}
}

func printControlUsage() {
	fmt.Println(`polaris control - Query reliability controls catalog

Usage:
  polaris control <subcommand> [options]

Subcommands:
  list              List controls in the catalog
  show              Show control details by code

List Options:
  --category=<cat>  Filter by category (fault_tolerance, monitoring, change_management, etc.)
  --limit=<n>       Maximum results (default 50)

Examples:
  polaris control list
  polaris control list --category=fault_tolerance
  polaris control show RC-018
  polaris control show RC-019`)
}

// cmdControlList lists controls
func cmdControlList(args []string) {
	var category string
	limit := 50

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--category=") {
			category = strings.TrimPrefix(arg, "--category=")
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	// Build URL with query params
	url := cfg.APIURL + "/api/v1/controls?limit=" + fmt.Sprintf("%d", limit)
	if category != "" {
		url += "&category=" + category
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var listResp ListControlsResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(listResp.Controls) == 0 {
		fmt.Println("No controls found.")
		return
	}

	fmt.Printf("Found %d controls:\n\n", listResp.Total)
	for _, c := range listResp.Controls {
		typeBadge := formatControlType(c.Type)
		fmt.Printf("%-8s %-14s %d/10 %-12s [%s] %s\n", c.ControlCode, typeBadge, c.Weight, formatWeightTier(c.Weight), formatCategory(c.Category), c.Name)
	}
}

// cmdControlShow shows control details by code
func cmdControlShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: control code required")
		fmt.Fprintln(os.Stderr, "Usage: polaris control show <control-code>")
		os.Exit(1)
	}

	controlCode := args[0]

	// Check if user passed a risk code instead of control code
	if strings.HasPrefix(controlCode, "R-") && !strings.HasPrefix(controlCode, "RC-") {
		fmt.Fprintf(os.Stderr, "Note: \"%s\" is a risk code, not a control code (RC-XXX).\n", controlCode)
		fmt.Fprintf(os.Stderr, "Use \"polaris risk show %s\" to see its mapped controls.\n", controlCode)
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	url := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var control Control
	if err := json.Unmarshal(resp, &control); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// Output in a format suitable for further processing or display
	fmt.Printf("Control: %s - %s\n", control.ControlCode, control.Name)
	fmt.Printf("Category: %s\n", formatCategory(control.Category))
	fmt.Printf("Type: %s\n", control.Type)
	fmt.Printf("Weight: %d/10 (%s)\n", control.Weight, formatWeightTier(control.Weight))
	if control.Treatment != "" {
		fmt.Printf("Treatment: %s\n", control.Treatment)
	}
	if control.Description != "" {
		fmt.Println()
		fmt.Printf("Description:\n  %s\n", wrapText(control.Description, 78, "  "))
	}
	if control.Objective != "" {
		fmt.Println()
		fmt.Printf("Objective:\n  %s\n", wrapText(control.Objective, 78, "  "))
	}
	if control.RiskStatement != "" {
		fmt.Println()
		fmt.Printf("Risk Statement:\n  %s\n", wrapText(control.RiskStatement, 78, "  "))
	}
	if control.TestDescription != "" {
		fmt.Println()
		fmt.Printf("Test Description:\n  %s\n", wrapText(control.TestDescription, 78, "  "))
	}
	if control.Remediation != "" {
		fmt.Println()
		fmt.Printf("Remediation:\n  %s\n", wrapText(control.Remediation, 78, "  "))
	}
	if len(control.ExpectedEvidenceTypes) > 0 {
		fmt.Println()
		fmt.Printf("Expected Evidence: %s\n", strings.Join(control.ExpectedEvidenceTypes, ", "))
	}
	if control.Implementation != "" {
		fmt.Println()
		fmt.Printf("Implementation:\n  %s\n", wrapText(control.Implementation, 78, "  "))
	}
	if len(control.RiskCodes) > 0 {
		fmt.Println()
		fmt.Printf("Related Risks: %s\n", strings.Join(control.RiskCodes, ", "))
	}
}

// formatControlType formats control type for display
func formatControlType(controlType string) string {
	switch controlType {
	case "preventive":
		return "[PREVENTIVE]"
	case "detective":
		return "[DETECTIVE]"
	case "corrective":
		return "[CORRECTIVE]"
	default:
		return "[" + strings.ToUpper(controlType) + "]"
	}
}

// formatWeightTier returns a human-readable tier label for a control weight (1-10)
func formatWeightTier(weight int) string {
	if weight >= 9 {
		return "Critical"
	} else if weight >= 7 {
		return "Required"
	} else if weight >= 5 {
		return "Important"
	} else if weight >= 3 {
		return "Recommended"
	}
	return "Advisory"
}

// formatCategory formats a snake_case category into Title Case
func formatCategory(category string) string {
	words := strings.Split(category, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// ============================================================================
// Knowledge Commands
// ============================================================================

// KnowledgeSearchResult represents a unified search result from the knowledge API
type KnowledgeSearchResult struct {
	Type       string  `json:"type"` // fact, procedure, pattern
	ID         string  `json:"id"`
	Title      string  `json:"title,omitempty"`
	Content    string  `json:"content,omitempty"`
	Vertical   string  `json:"vertical,omitempty"`
	Score      float64 `json:"score,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// KnowledgeSearchResponse represents the search API response
type KnowledgeSearchResponse struct {
	Results []KnowledgeSearchResult `json:"results"`
	Total   int                     `json:"total"`
}

// KnowledgeFact represents a fact from the knowledge API
type KnowledgeFact struct {
	ID               string   `json:"id"`
	Content          string   `json:"content"`
	Vertical         string   `json:"vertical"`
	FactType         string   `json:"fact_type"`
	Technologies     []string `json:"technologies,omitempty"`
	Services         []string `json:"services,omitempty"`
	Confidence       float64  `json:"confidence"`
	ValidationStatus string   `json:"validation_status"`
	ValidationCount  int      `json:"validation_count"`
	Score            float64  `json:"score,omitempty"`
}

// KnowledgeFactsResponse represents the facts list API response
type KnowledgeFactsResponse struct {
	Facts []KnowledgeFact `json:"facts"`
	Total int             `json:"total"`
}

// KnowledgeProcedure represents a procedure from the knowledge API
type KnowledgeProcedure struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description,omitempty"`
	Vertical           string   `json:"vertical"`
	ProcedureType      string   `json:"procedure_type"`
	RelatedControls    []string `json:"related_controls,omitempty"`
	Technologies       []string `json:"technologies,omitempty"`
	EffectivenessScore float64  `json:"effectiveness_score"`
	AppliedCount       int      `json:"applied_count"`
	SuccessCount       int      `json:"success_count"`
	Confidence         float64  `json:"confidence"`
	Score              float64  `json:"score,omitempty"`
}

// KnowledgeProceduresResponse represents the procedures list API response
type KnowledgeProceduresResponse struct {
	Procedures []KnowledgeProcedure `json:"procedures"`
	Total      int                  `json:"total"`
}

// KnowledgePattern represents a pattern from the knowledge API
type KnowledgePattern struct {
	ID                   string   `json:"id"`
	Title                string   `json:"title"`
	Description          string   `json:"description,omitempty"`
	PatternType          string   `json:"pattern_type"`
	Vertical             string   `json:"vertical"`
	OccurrenceCount      int      `json:"occurrence_count"`
	TypicalBlastRadius   string   `json:"typical_blast_radius,omitempty"`
	TypicalMTTR          string   `json:"typical_mttr,omitempty"`
	RelatedControls      []string `json:"related_controls,omitempty"`
	PreventionStrategies []string `json:"prevention_strategies,omitempty"`
	MitigationSteps      []string `json:"mitigation_steps,omitempty"`
	Confidence           float64  `json:"confidence"`
	Score                float64  `json:"score,omitempty"`
}

// KnowledgePatternsResponse represents the patterns list API response
type KnowledgePatternsResponse struct {
	Patterns []KnowledgePattern `json:"patterns"`
	Total    int                `json:"total"`
}

// KnowledgeHealth represents the knowledge base health stats
type KnowledgeHealth struct {
	TotalFacts          int     `json:"total_facts"`
	TotalProcedures     int     `json:"total_procedures"`
	TotalPatterns       int     `json:"total_patterns"`
	ValidatedPercentage float64 `json:"validated_percentage"`
	AvgConfidence       float64 `json:"avg_confidence"`
	StaleCount          int     `json:"stale_count"`
	ContradictionCount  int     `json:"contradiction_count"`
}

// KnowledgeRelationship represents a relationship from the knowledge API
type KnowledgeRelationship struct {
	ID               string   `json:"id"`
	RelationType     string   `json:"relation_type"`
	SourceType       string   `json:"source_type"`
	SourceID         string   `json:"source_id"`
	SourceLabel      string   `json:"source_label"`
	TargetType       string   `json:"target_type"`
	TargetID         string   `json:"target_id"`
	TargetLabel      string   `json:"target_label"`
	Strength         float64  `json:"strength"`
	Direction        string   `json:"direction"`
	Evidence         []string `json:"evidence,omitempty"`
	ObservationCount int      `json:"observation_count"`
}

// KnowledgeRelationshipsResponse represents the relationships API response
type KnowledgeRelationshipsResponse struct {
	Relationships []KnowledgeRelationship `json:"relationships"`
	Total         int                     `json:"total"`
}

// KnowledgeTraversalResult represents a node from graph traversal
type KnowledgeTraversalResult struct {
	EntityType   string  `json:"entity_type"`
	EntityID     string  `json:"entity_id"`
	EntityLabel  string  `json:"entity_label"`
	RelationType string  `json:"relation_type"`
	Strength     float64 `json:"strength"`
	Depth        int     `json:"depth"`
}

// KnowledgeTraversalResponse represents the graph traversal API response
type KnowledgeTraversalResponse struct {
	Results []KnowledgeTraversalResult `json:"results"`
	Total   int                        `json:"total"`
}

// KnowledgeGraphSearchResult extends search results with graph metadata
type KnowledgeGraphSearchResult struct {
	Type            string  `json:"type"`
	ID              string  `json:"id"`
	Title           string  `json:"title,omitempty"`
	Content         string  `json:"content,omitempty"`
	Vertical        string  `json:"vertical,omitempty"`
	Similarity      float64 `json:"similarity,omitempty"`
	Confidence      float64 `json:"confidence,omitempty"`
	DiscoveryMethod string  `json:"discovery_method,omitempty"`
	GraphPath       string  `json:"graph_path,omitempty"`
}

// KnowledgeGraphSearchResponse represents graph-expanded search API response
type KnowledgeGraphSearchResponse struct {
	Results       []KnowledgeGraphSearchResult `json:"results"`
	Total         int                          `json:"total"`
	GraphExpanded bool                         `json:"graph_expanded"`
}

// cmdKnowledge handles the knowledge command
func cmdKnowledge(args []string) {
	if len(args) == 0 {
		printKnowledgeUsage()
		os.Exit(1)
	}

	subcmd := args[0]
	switch subcmd {
	case "search":
		cmdKnowledgeSearch(args[1:])
	case "facts":
		cmdKnowledgeFacts(args[1:])
	case "procedures":
		cmdKnowledgeProcedures(args[1:])
	case "patterns":
		cmdKnowledgePatterns(args[1:])
	case "relationships":
		cmdKnowledgeRelationships(args[1:])
	case "graph":
		cmdKnowledgeGraph(args[1:])
	case "graph-search":
		cmdKnowledgeGraphSearch(args[1:])
	case "enrich":
		cmdKnowledgeEnrich(args[1:])
	case "health":
		cmdKnowledgeHealth()
	case "help", "--help", "-h":
		printKnowledgeUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown knowledge command: %s\n", subcmd)
		printKnowledgeUsage()
		os.Exit(1)
	}
}

func printKnowledgeUsage() {
	fmt.Println(`polaris knowledge - Query organizational knowledge base

Usage:
  polaris knowledge <subcommand> [options]

Subcommands:
  enrich              Fetch patterns, procedures, and health in one call
  search              Semantic search across all knowledge types
  graph-search        Graph-expanded semantic search (search + graph neighbors)
  facts               List or search facts
  procedures          List or search procedures (with control mappings)
  patterns            List or search failure patterns
  relationships       List relationships for a knowledge entity
  graph               Traverse the knowledge graph from an entity
  health              Show knowledge base health statistics

Enrich Options:
  --vertical=<v>      Filter by SRE vertical (default: fault-tolerance)
  --control=<RC-XXX>  Include procedures for a specific control
  --technology=<t>    Include facts for a specific technology
  --query=<q>         Include semantic search results for a query
  --limit=<n>         Maximum results per section (default 10)

Search Options:
  polaris knowledge search <query> [--limit=N]

Graph-Search Options:
  polaris knowledge graph-search <query> [--limit=N] [--depth=N] [--types=causes,mitigates]

Facts Options:
  --vertical=<v>      Filter by SRE vertical (e.g., fault-tolerance, monitoring-alerting)
  --technology=<t>    Filter by technology (e.g., redis, kafka, go)
  --status=<s>        Filter by validation status (auto_extracted, analyst_validated)
  --limit=<n>         Maximum results (default 20)

Procedures Options:
  --vertical=<v>      Filter by SRE vertical
  --technology=<t>    Filter by technology
  --type=<t>          Filter by procedure type (troubleshooting, runbook, best_practice, workflow)
  --control=<RC-XXX>  Filter procedures related to a specific control
  --limit=<n>         Maximum results (default 20)

Patterns Options:
  --vertical=<v>      Filter by SRE vertical
  --type=<t>          Filter by pattern type (causal_chain, correlation, anti_pattern, failure_mode)
  --min-occurrences=N Minimum occurrence count
  --limit=<n>         Maximum results (default 20)

Relationships Options:
  polaris knowledge relationships <entity_type> <entity_id>
  Entity types: fact, procedure, pattern, service, technology, control

Graph Options:
  polaris knowledge graph <entity_type> <entity_id> [--depth=N] [--min-strength=0.3] [--type=causes,mitigates]

Examples:
  polaris knowledge enrich --vertical=fault-tolerance
  polaris knowledge enrich --control=RC-018 --query="timeout failure"
  polaris knowledge search "circuit breaker timeout patterns"
  polaris knowledge graph-search "timeout failures" --depth=2
  polaris knowledge facts --vertical=fault-tolerance --technology=go
  polaris knowledge procedures --control=RC-018
  polaris knowledge patterns --type=failure_mode --min-occurrences=3
  polaris knowledge relationships fact fact_abc12
  polaris knowledge graph fact fact_abc12 --depth=2 --type=causes,mitigates
  polaris knowledge health`)
}

// cmdKnowledgeSearch performs a semantic search across all knowledge types
func cmdKnowledgeSearch(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		fmt.Fprintln(os.Stderr, "Usage: polaris knowledge search <query> [--limit=N]")
		os.Exit(1)
	}

	var queryParts []string
	limit := 20

	for _, arg := range args {
		if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		} else if !strings.HasPrefix(arg, "-") {
			queryParts = append(queryParts, arg)
		}
	}

	query := strings.Join(queryParts, " ")
	if query == "" {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	// POST /api/knowledge/search
	body := map[string]interface{}{
		"query": query,
		"limit": limit,
	}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/knowledge/search"
	resp, err := makeAPIRequest(cfg, "POST", url, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var searchResp KnowledgeSearchResponse
	if err := json.Unmarshal(resp, &searchResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if searchResp.Total == 0 {
		fmt.Println("No knowledge found matching query.")
		return
	}

	fmt.Printf("Found %d results for \"%s\":\n\n", searchResp.Total, query)
	for _, r := range searchResp.Results {
		typeBadge := "[" + strings.ToUpper(r.Type) + "]"
		title := r.Title
		if title == "" {
			title = truncateText(r.Content, 80)
		}
		fmt.Printf("  %-12s %s %s\n", r.ID, typeBadge, title)
		if r.Score > 0 {
			fmt.Printf("               Score: %.2f  Vertical: %s\n", r.Score, r.Vertical)
		}
	}
}

// cmdKnowledgeFacts lists or searches facts
func cmdKnowledgeFacts(args []string) {
	var vertical, technology, status string
	limit := 20

	for _, arg := range args {
		if strings.HasPrefix(arg, "--vertical=") {
			vertical = strings.TrimPrefix(arg, "--vertical=")
		} else if strings.HasPrefix(arg, "--technology=") {
			technology = strings.TrimPrefix(arg, "--technology=")
		} else if strings.HasPrefix(arg, "--status=") {
			status = strings.TrimPrefix(arg, "--status=")
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	// GET /api/knowledge/facts with query params
	url := cfg.APIURL + "/api/knowledge/facts?limit=" + fmt.Sprintf("%d", limit)
	if vertical != "" {
		url += "&vertical=" + vertical
	}
	if technology != "" {
		url += "&technology=" + technology
	}
	if status != "" {
		url += "&status=" + status
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var factsResp KnowledgeFactsResponse
	if err := json.Unmarshal(resp, &factsResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if factsResp.Total == 0 {
		fmt.Println("No facts found.")
		return
	}

	fmt.Printf("Found %d facts:\n\n", factsResp.Total)
	for _, f := range factsResp.Facts {
		validBadge := formatValidationStatus(f.ValidationStatus)
		content := truncateText(f.Content, 80)
		fmt.Printf("  %s %s [%s] (confidence: %.0f%%)\n", f.ID, validBadge, f.Vertical, f.Confidence*100)
		fmt.Printf("    %s\n", content)
		if len(f.Technologies) > 0 {
			fmt.Printf("    Technologies: %s\n", strings.Join(f.Technologies, ", "))
		}
	}
}

// cmdKnowledgeProcedures lists or searches procedures
func cmdKnowledgeProcedures(args []string) {
	var vertical, technology, procType, control string
	limit := 20

	for _, arg := range args {
		if strings.HasPrefix(arg, "--vertical=") {
			vertical = strings.TrimPrefix(arg, "--vertical=")
		} else if strings.HasPrefix(arg, "--technology=") {
			technology = strings.TrimPrefix(arg, "--technology=")
		} else if strings.HasPrefix(arg, "--type=") {
			procType = strings.TrimPrefix(arg, "--type=")
		} else if strings.HasPrefix(arg, "--control=") {
			control = strings.TrimPrefix(arg, "--control=")
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	// GET /api/knowledge/procedures with query params
	url := cfg.APIURL + "/api/knowledge/procedures?limit=" + fmt.Sprintf("%d", limit)
	if vertical != "" {
		url += "&vertical=" + vertical
	}
	if technology != "" {
		url += "&technology=" + technology
	}
	if procType != "" {
		url += "&type=" + procType
	}
	// Control filter: use as query text since API doesn't have a direct control filter param
	if control != "" {
		url += "&q=" + control
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var procsResp KnowledgeProceduresResponse
	if err := json.Unmarshal(resp, &procsResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if procsResp.Total == 0 {
		fmt.Println("No procedures found.")
		return
	}

	// If filtering by control code, filter client-side on related_controls
	var filtered []KnowledgeProcedure
	if control != "" {
		for _, p := range procsResp.Procedures {
			for _, rc := range p.RelatedControls {
				if rc == control {
					filtered = append(filtered, p)
					break
				}
			}
		}
		if len(filtered) == 0 {
			// Fall back to showing all results from query
			filtered = procsResp.Procedures
		} else {
			procsResp.Procedures = filtered
		}
	}

	fmt.Printf("Found %d procedures:\n\n", procsResp.Total)
	for _, p := range procsResp.Procedures {
		effectiveness := ""
		if p.AppliedCount > 0 {
			effectiveness = fmt.Sprintf(" (effectiveness: %.0f%%, applied: %d)", p.EffectivenessScore*100, p.AppliedCount)
		}
		fmt.Printf("  %s [%s] %s%s\n", p.ID, p.ProcedureType, p.Title, effectiveness)
		if p.Description != "" {
			fmt.Printf("    %s\n", truncateText(p.Description, 78))
		}
		if len(p.RelatedControls) > 0 {
			fmt.Printf("    Controls: %s\n", strings.Join(p.RelatedControls, ", "))
		}
		if len(p.Technologies) > 0 {
			fmt.Printf("    Technologies: %s\n", strings.Join(p.Technologies, ", "))
		}
	}
}

// cmdKnowledgePatterns lists or searches patterns
func cmdKnowledgePatterns(args []string) {
	var vertical, patternType string
	minOccurrences := 0
	limit := 20

	for _, arg := range args {
		if strings.HasPrefix(arg, "--vertical=") {
			vertical = strings.TrimPrefix(arg, "--vertical=")
		} else if strings.HasPrefix(arg, "--type=") {
			patternType = strings.TrimPrefix(arg, "--type=")
		} else if strings.HasPrefix(arg, "--min-occurrences=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--min-occurrences="), "%d", &minOccurrences)
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	// GET /api/knowledge/patterns with query params
	url := cfg.APIURL + "/api/knowledge/patterns?limit=" + fmt.Sprintf("%d", limit)
	if vertical != "" {
		url += "&vertical=" + vertical
	}
	if patternType != "" {
		url += "&type=" + patternType
	}
	if minOccurrences > 0 {
		url += "&min_occurrences=" + fmt.Sprintf("%d", minOccurrences)
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var patternsResp KnowledgePatternsResponse
	if err := json.Unmarshal(resp, &patternsResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if patternsResp.Total == 0 {
		fmt.Println("No patterns found.")
		return
	}

	fmt.Printf("Found %d patterns:\n\n", patternsResp.Total)
	for _, p := range patternsResp.Patterns {
		occurrences := ""
		if p.OccurrenceCount > 0 {
			occurrences = fmt.Sprintf(" (seen %dx", p.OccurrenceCount)
			if p.TypicalBlastRadius != "" {
				occurrences += ", blast: " + p.TypicalBlastRadius
			}
			if p.TypicalMTTR != "" {
				occurrences += ", MTTR: " + p.TypicalMTTR
			}
			occurrences += ")"
		}
		fmt.Printf("  %s [%s] %s%s\n", p.ID, p.PatternType, p.Title, occurrences)
		if p.Description != "" {
			fmt.Printf("    %s\n", truncateText(p.Description, 78))
		}
		if len(p.RelatedControls) > 0 {
			fmt.Printf("    Controls: %s\n", strings.Join(p.RelatedControls, ", "))
		}
		if len(p.PreventionStrategies) > 0 {
			fmt.Printf("    Prevention: %s\n", strings.Join(p.PreventionStrategies, "; "))
		}
	}
}

// cmdKnowledgeHealth shows knowledge base health stats
func cmdKnowledgeHealth() {
	cfg := loadAndResolveConfig()

	url := cfg.APIURL + "/api/knowledge/health"
	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var health KnowledgeHealth
	if err := json.Unmarshal(resp, &health); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	total := health.TotalFacts + health.TotalProcedures + health.TotalPatterns
	fmt.Printf("Knowledge Base Health\n\n")
	fmt.Printf("  Total Items:       %d\n", total)
	fmt.Printf("    Facts:           %d\n", health.TotalFacts)
	fmt.Printf("    Procedures:      %d\n", health.TotalProcedures)
	fmt.Printf("    Patterns:        %d\n", health.TotalPatterns)
	fmt.Printf("  Validated:         %.0f%%\n", health.ValidatedPercentage)
	fmt.Printf("  Avg Confidence:    %.0f%%\n", health.AvgConfidence*100)
	if health.StaleCount > 0 {
		fmt.Printf("  Stale:             %d\n", health.StaleCount)
	}
	if health.ContradictionCount > 0 {
		fmt.Printf("  Contradictions:    %d\n", health.ContradictionCount)
	}
}

// cmdKnowledgeRelationships lists relationships for a knowledge entity
func cmdKnowledgeRelationships(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: entity type and entity ID required")
		fmt.Fprintln(os.Stderr, "Usage: polaris knowledge relationships <type> <id>")
		fmt.Fprintln(os.Stderr, "Types: fact, procedure, pattern, service, technology, control")
		os.Exit(1)
	}

	entityType := args[0]
	entityID := args[1]

	cfg := loadAndResolveConfig()

	url := cfg.APIURL + "/api/knowledge/entities/" + entityType + "/" + entityID + "/relationships"
	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var relsResp KnowledgeRelationshipsResponse
	if err := json.Unmarshal(resp, &relsResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if relsResp.Total == 0 {
		fmt.Printf("No relationships found for %s %s\n", entityType, entityID)
		return
	}

	fmt.Printf("Relationships for %s %s (%d total):\n\n", entityType, entityID, relsResp.Total)
	for _, rel := range relsResp.Relationships {
		strengthPct := fmt.Sprintf("%.0f%%", rel.Strength*100)
		dirIcon := " -> "
		if rel.Direction == "bidirectional" {
			dirIcon = " <-> "
		}
		fmt.Printf("  %s [%s]%s%s [%s] (strength: %s", rel.SourceLabel, rel.SourceType, dirIcon, rel.TargetLabel, rel.TargetType, strengthPct)
		if rel.ObservationCount > 1 {
			fmt.Printf(", seen %dx", rel.ObservationCount)
		}
		fmt.Println(")")
		fmt.Printf("    Relation: %s  ID: %s\n", rel.RelationType, rel.ID)
		if len(rel.Evidence) > 0 {
			fmt.Printf("    Evidence: %s\n", rel.Evidence[0])
		}
	}
}

// cmdKnowledgeGraph traverses the knowledge graph from an entity
func cmdKnowledgeGraph(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: entity type and entity ID required")
		fmt.Fprintln(os.Stderr, "Usage: polaris knowledge graph <type> <id> [--depth=N] [--min-strength=0.3] [--type=causes,mitigates]")
		os.Exit(1)
	}

	entityType := args[0]
	entityID := args[1]
	depth := 3
	minStrength := "0.3"
	var relationType string

	for _, arg := range args[2:] {
		if strings.HasPrefix(arg, "--depth=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--depth="), "%d", &depth)
		} else if strings.HasPrefix(arg, "--min-strength=") {
			minStrength = strings.TrimPrefix(arg, "--min-strength=")
		} else if strings.HasPrefix(arg, "--type=") {
			relationType = strings.TrimPrefix(arg, "--type=")
		}
	}

	cfg := loadAndResolveConfig()

	url := fmt.Sprintf("%s/api/knowledge/entities/%s/%s/graph?max_depth=%d&min_strength=%s",
		cfg.APIURL, entityType, entityID, depth, minStrength)
	if relationType != "" {
		url += "&relation_type=" + relationType
	}

	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var travResp KnowledgeTraversalResponse
	if err := json.Unmarshal(resp, &travResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if travResp.Total == 0 {
		fmt.Printf("No connected nodes found from %s %s\n", entityType, entityID)
		return
	}

	fmt.Printf("Graph traversal from %s %s (%d nodes):\n\n", entityType, entityID, travResp.Total)

	// Group by depth for readability
	maxDepth := 0
	for _, n := range travResp.Results {
		if n.Depth > maxDepth {
			maxDepth = n.Depth
		}
	}

	for d := 1; d <= maxDepth; d++ {
		fmt.Printf("  Depth %d:\n", d)
		for _, n := range travResp.Results {
			if n.Depth != d {
				continue
			}
			indent := strings.Repeat("  ", d)
			fmt.Printf("  %s-[%s]-> %s [%s] (strength: %.0f%%)\n",
				indent, n.RelationType, n.EntityLabel, n.EntityType, n.Strength*100)
			fmt.Printf("  %s         ID: %s\n", indent, n.EntityID)
		}
	}
}

// cmdKnowledgeGraphSearch performs a graph-expanded semantic search
func cmdKnowledgeGraphSearch(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		fmt.Fprintln(os.Stderr, "Usage: polaris knowledge graph-search <query> [--limit=N] [--depth=N] [--types=causes,mitigates]")
		os.Exit(1)
	}

	var queryParts []string
	limit := 20
	depth := 1
	var expandTypes string

	for _, arg := range args {
		if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		} else if strings.HasPrefix(arg, "--depth=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--depth="), "%d", &depth)
		} else if strings.HasPrefix(arg, "--types=") {
			expandTypes = strings.TrimPrefix(arg, "--types=")
		} else if !strings.HasPrefix(arg, "-") {
			queryParts = append(queryParts, arg)
		}
	}

	query := strings.Join(queryParts, " ")
	if query == "" {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	body := map[string]interface{}{
		"query":        query,
		"limit":        limit,
		"graph_expand": true,
		"expand_depth": depth,
	}
	if expandTypes != "" {
		body["expand_types"] = strings.Split(expandTypes, ",")
	}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/knowledge/graph-search"
	resp, err := makeAPIRequest(cfg, "POST", url, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var searchResp KnowledgeGraphSearchResponse
	if err := json.Unmarshal(resp, &searchResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if searchResp.Total == 0 {
		fmt.Println("No knowledge found matching query.")
		return
	}

	fmt.Printf("Found %d results for \"%s\" (graph-expanded):\n\n", searchResp.Total, query)
	for _, r := range searchResp.Results {
		typeBadge := "[" + strings.ToUpper(r.Type) + "]"
		title := r.Title
		if title == "" {
			title = truncateText(r.Content, 80)
		}

		methodBadge := ""
		switch r.DiscoveryMethod {
		case "semantic":
			methodBadge = " [SEM]"
		case "graph":
			methodBadge = " [GRAPH]"
		case "both":
			methodBadge = " [SEM+GRAPH]"
		}

		fmt.Printf("  %-12s %s%s %s\n", r.ID, typeBadge, methodBadge, title)
		if r.Similarity > 0 {
			fmt.Printf("               Score: %.2f", r.Similarity)
			if r.Vertical != "" {
				fmt.Printf("  Vertical: %s", r.Vertical)
			}
			fmt.Println()
		}
		if r.GraphPath != "" {
			fmt.Printf("               Path: %s\n", r.GraphPath)
		}
	}
}

// cmdKnowledgeEnrich fetches patterns, procedures, health, and optionally
// facts and search results in parallel, printing combined output.
func cmdKnowledgeEnrich(args []string) {
	vertical := "fault-tolerance"
	var control, technology, query string
	limit := 10

	for _, arg := range args {
		if strings.HasPrefix(arg, "--vertical=") {
			vertical = strings.TrimPrefix(arg, "--vertical=")
		} else if strings.HasPrefix(arg, "--control=") {
			control = strings.TrimPrefix(arg, "--control=")
		} else if strings.HasPrefix(arg, "--technology=") {
			technology = strings.TrimPrefix(arg, "--technology=")
		} else if strings.HasPrefix(arg, "--query=") {
			query = strings.TrimPrefix(arg, "--query=")
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	var (
		mu           sync.Mutex
		patternsResp KnowledgePatternsResponse
		procsResp    KnowledgeProceduresResponse
		health       KnowledgeHealth
		factsResp    KnowledgeFactsResponse
		searchResp   KnowledgeSearchResponse
		errs         []string
	)

	var wg sync.WaitGroup

	// Always fetch patterns
	wg.Add(1)
	go func() {
		defer wg.Done()
		url := cfg.APIURL + fmt.Sprintf("/api/knowledge/patterns?limit=%d&vertical=%s", limit, vertical)
		resp, err := makeAPIRequest(cfg, "GET", url, nil)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Sprintf("patterns: %v", err))
			return
		}
		if err := json.Unmarshal(resp, &patternsResp); err != nil {
			errs = append(errs, fmt.Sprintf("patterns parse: %v", err))
		}
	}()

	// Always fetch procedures
	wg.Add(1)
	go func() {
		defer wg.Done()
		url := cfg.APIURL + fmt.Sprintf("/api/knowledge/procedures?limit=%d&vertical=%s", limit, vertical)
		if control != "" {
			url += "&q=" + control
		}
		resp, err := makeAPIRequest(cfg, "GET", url, nil)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Sprintf("procedures: %v", err))
			return
		}
		if err := json.Unmarshal(resp, &procsResp); err != nil {
			errs = append(errs, fmt.Sprintf("procedures parse: %v", err))
		}
	}()

	// Always fetch health
	wg.Add(1)
	go func() {
		defer wg.Done()
		url := cfg.APIURL + "/api/knowledge/health"
		resp, err := makeAPIRequest(cfg, "GET", url, nil)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Sprintf("health: %v", err))
			return
		}
		if err := json.Unmarshal(resp, &health); err != nil {
			errs = append(errs, fmt.Sprintf("health parse: %v", err))
		}
	}()

	// Optionally fetch facts (when technology is specified)
	if technology != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := cfg.APIURL + fmt.Sprintf("/api/knowledge/facts?limit=%d&technology=%s", limit, technology)
			if vertical != "" {
				url += "&vertical=" + vertical
			}
			resp, err := makeAPIRequest(cfg, "GET", url, nil)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("facts: %v", err))
				return
			}
			if err := json.Unmarshal(resp, &factsResp); err != nil {
				errs = append(errs, fmt.Sprintf("facts parse: %v", err))
			}
		}()
	}

	// Optionally fetch search results (when query is specified)
	if query != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := map[string]interface{}{
				"query": query,
				"limit": limit,
			}
			bodyBytes, _ := json.Marshal(body)
			url := cfg.APIURL + "/api/knowledge/search"
			resp, err := makeAPIRequest(cfg, "POST", url, bodyBytes)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("search: %v", err))
				return
			}
			if err := json.Unmarshal(resp, &searchResp); err != nil {
				errs = append(errs, fmt.Sprintf("search parse: %v", err))
			}
		}()
	}

	wg.Wait()

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", e)
		}
		fmt.Fprintln(os.Stderr)
	}

	// --- Patterns ---
	fmt.Printf("=== Patterns (%d) ===\n\n", patternsResp.Total)
	for _, p := range patternsResp.Patterns {
		occurrences := ""
		if p.OccurrenceCount > 0 {
			occurrences = fmt.Sprintf(" (seen %dx", p.OccurrenceCount)
			if p.TypicalBlastRadius != "" {
				occurrences += ", blast: " + p.TypicalBlastRadius
			}
			if p.TypicalMTTR != "" {
				occurrences += ", MTTR: " + p.TypicalMTTR
			}
			occurrences += ")"
		}
		fmt.Printf("  %s [%s] %s%s\n", p.ID, p.PatternType, p.Title, occurrences)
		if p.Description != "" {
			fmt.Printf("    %s\n", truncateText(p.Description, 78))
		}
		if len(p.RelatedControls) > 0 {
			fmt.Printf("    Controls: %s\n", strings.Join(p.RelatedControls, ", "))
		}
		if len(p.PreventionStrategies) > 0 {
			fmt.Printf("    Prevention: %s\n", strings.Join(p.PreventionStrategies, "; "))
		}
	}

	// --- Procedures ---
	fmt.Printf("\n=== Procedures (%d) ===\n\n", procsResp.Total)
	// If control filter, filter client-side on related_controls
	if control != "" {
		var filtered []KnowledgeProcedure
		for _, p := range procsResp.Procedures {
			for _, rc := range p.RelatedControls {
				if rc == control {
					filtered = append(filtered, p)
					break
				}
			}
		}
		if len(filtered) > 0 {
			procsResp.Procedures = filtered
		}
	}
	for _, p := range procsResp.Procedures {
		effectiveness := ""
		if p.AppliedCount > 0 {
			effectiveness = fmt.Sprintf(" (effectiveness: %.0f%%, applied: %d)", p.EffectivenessScore*100, p.AppliedCount)
		}
		fmt.Printf("  %s [%s] %s%s\n", p.ID, p.ProcedureType, p.Title, effectiveness)
		if p.Description != "" {
			fmt.Printf("    %s\n", truncateText(p.Description, 78))
		}
		if len(p.RelatedControls) > 0 {
			fmt.Printf("    Controls: %s\n", strings.Join(p.RelatedControls, ", "))
		}
	}

	// --- Facts (optional) ---
	if technology != "" {
		fmt.Printf("\n=== Facts for %s (%d) ===\n\n", technology, factsResp.Total)
		for _, f := range factsResp.Facts {
			validBadge := formatValidationStatus(f.ValidationStatus)
			content := truncateText(f.Content, 80)
			fmt.Printf("  %s %s [%s] (confidence: %.0f%%)\n", f.ID, validBadge, f.Vertical, f.Confidence*100)
			fmt.Printf("    %s\n", content)
		}
	}

	// --- Search (optional) ---
	if query != "" {
		fmt.Printf("\n=== Search Results for \"%s\" (%d) ===\n\n", query, searchResp.Total)
		for _, r := range searchResp.Results {
			typeBadge := "[" + strings.ToUpper(r.Type) + "]"
			title := r.Title
			if title == "" {
				title = truncateText(r.Content, 80)
			}
			fmt.Printf("  %-12s %s %s\n", r.ID, typeBadge, title)
			if r.Score > 0 {
				fmt.Printf("               Score: %.2f  Vertical: %s\n", r.Score, r.Vertical)
			}
		}
	}

	// --- Health ---
	total := health.TotalFacts + health.TotalProcedures + health.TotalPatterns
	fmt.Printf("\n=== Knowledge Health ===\n\n")
	fmt.Printf("  Total Items:       %d\n", total)
	fmt.Printf("    Facts:           %d\n", health.TotalFacts)
	fmt.Printf("    Procedures:      %d\n", health.TotalProcedures)
	fmt.Printf("    Patterns:        %d\n", health.TotalPatterns)
	fmt.Printf("  Validated:         %.0f%%\n", health.ValidatedPercentage)
	fmt.Printf("  Avg Confidence:    %.0f%%\n", health.AvgConfidence*100)
	if health.StaleCount > 0 {
		fmt.Printf("  Stale:             %d\n", health.StaleCount)
	}
	if health.ContradictionCount > 0 {
		fmt.Printf("  Contradictions:    %d\n", health.ContradictionCount)
	}
}

// formatValidationStatus formats validation status for display
func formatValidationStatus(status string) string {
	switch status {
	case "analyst_validated":
		return "[VALIDATED]"
	case "auto_extracted":
		return "[AUTO]"
	case "contradicted":
		return "[CONTRADICTED]"
	default:
		return "[" + strings.ToUpper(status) + "]"
	}
}

// truncateText truncates text to maxLen with ellipsis
func truncateText(text string, maxLen int) string {
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen-3] + "..."
}

// ============================================================================
// Evidence Commands
// ============================================================================

// EvidenceItem represents an evidence record from the API
type EvidenceItem struct {
	ID              string  `json:"id"`
	ControlID       string  `json:"control_id"`
	Type            string  `json:"type"`
	Name            string  `json:"name"`
	URLOrIdentifier string  `json:"url_or_identifier,omitempty"`
	Description     string  `json:"description,omitempty"`
	GitHash         *string `json:"git_hash,omitempty"`
	Status          string  `json:"status"`
	VerifiedAt      *string `json:"verified_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

// ListEvidenceResponse matches the API response
type ListEvidenceAPIResponse struct {
	Evidence []EvidenceItem `json:"evidence"`
	Total    int            `json:"total"`
}

// cmdEvidence handles the evidence command
func cmdEvidence(args []string) {
	if len(args) == 0 {
		printEvidenceUsage()
		os.Exit(1)
	}

	subcmd := args[0]
	switch subcmd {
	case "submit":
		cmdEvidenceSubmit(args[1:])
	case "list":
		cmdEvidenceList(args[1:])
	case "verify":
		cmdEvidenceVerify(args[1:])
	case "help", "--help", "-h":
		printEvidenceUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown evidence command: %s\n", subcmd)
		printEvidenceUsage()
		os.Exit(1)
	}
}

func printEvidenceUsage() {
	fmt.Println(`polaris evidence - Manage control evidence

Usage:
  polaris evidence <subcommand> [options]

Subcommands:
  submit              Submit evidence for a control
  list                List evidence records
  verify              Mark evidence as verified

Submit Options:
  --control=<RC-XXX>  Control code to submit evidence for (required)
  --type=<type>       Evidence type: code, test, dashboard, document, configuration, runbook, other (required)
  --name=<name>       Evidence name/title (required)
  --url=<url>         URL or identifier for the evidence
  --description=<d>   Description of the evidence
  --git-hash=<hash>   Git commit hash (auto-detected from HEAD if omitted)

List Options:
  --control=<RC-XXX>  Filter by control code
  --type=<type>       Filter by evidence type
  --status=<status>   Filter by status (not_configured, configured, sample, verified)
  --limit=<n>         Maximum results (default 20)

Verify Options:
  polaris evidence verify <evidence-id>

Examples:
  polaris evidence submit --control=RC-018 --type=code --name="Circuit breaker for payment service" --url="https://github.com/org/repo/pull/42"
  polaris evidence submit --control=RC-019 --type=configuration --name="HTTP client timeouts" --description="30s timeout on all external calls"
  polaris evidence list --control=RC-018
  polaris evidence list --status=configured
  polaris evidence verify 550e8400-e29b-41d4-a716-446655440000`)
}

// cmdEvidenceSubmit submits evidence for a control
func cmdEvidenceSubmit(args []string) {
	var controlCode, evidenceType, name, url, description, gitHash string

	for _, arg := range args {
		if strings.HasPrefix(arg, "--control=") {
			controlCode = strings.TrimPrefix(arg, "--control=")
		} else if strings.HasPrefix(arg, "--type=") {
			evidenceType = strings.TrimPrefix(arg, "--type=")
		} else if strings.HasPrefix(arg, "--name=") {
			name = strings.TrimPrefix(arg, "--name=")
		} else if strings.HasPrefix(arg, "--url=") {
			url = strings.TrimPrefix(arg, "--url=")
		} else if strings.HasPrefix(arg, "--description=") {
			description = strings.TrimPrefix(arg, "--description=")
		} else if strings.HasPrefix(arg, "--git-hash=") {
			gitHash = strings.TrimPrefix(arg, "--git-hash=")
		}
	}

	// Auto-capture git hash from HEAD if not provided
	if gitHash == "" {
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			gitHash = strings.TrimSpace(string(out))
		}
	}

	if controlCode == "" {
		fmt.Fprintln(os.Stderr, "Error: --control is required (e.g., --control=RC-018)")
		os.Exit(1)
	}
	if evidenceType == "" {
		fmt.Fprintln(os.Stderr, "Error: --type is required (code, test, dashboard, document, configuration, runbook, other)")
		os.Exit(1)
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		os.Exit(1)
	}

	// Check if user passed a risk code instead of control code
	if strings.HasPrefix(controlCode, "R-") && !strings.HasPrefix(controlCode, "RC-") {
		fmt.Fprintf(os.Stderr, "Note: \"%s\" is a risk code, not a control code (RC-XXX).\n", controlCode)
		fmt.Fprintf(os.Stderr, "Evidence is submitted per control. Use \"polaris risk show %s\" to find mapped controls.\n", controlCode)
		os.Exit(1)
	}

	cfg := loadAndResolveConfig()

	// Fetch the full control to get ID and expected evidence types
	controlURL := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode
	controlResp, err := makeAPIRequest(cfg, "GET", controlURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: control %s not found: %v\n", controlCode, err)
		os.Exit(1)
	}

	var control Control
	if err := json.Unmarshal(controlResp, &control); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing control response: %v\n", err)
		os.Exit(1)
	}
	if control.ID == "" {
		fmt.Fprintf(os.Stderr, "Error: control %s not found\n", controlCode)
		os.Exit(1)
	}

	// Warn if evidence type doesn't match expected types
	if len(control.ExpectedEvidenceTypes) > 0 {
		matched := false
		for _, et := range control.ExpectedEvidenceTypes {
			if et == evidenceType {
				matched = true
				break
			}
		}
		if !matched {
			fmt.Fprintf(os.Stderr, "Note: %s expects evidence types: %s (submitting \"%s\" anyway)\n",
				controlCode, strings.Join(control.ExpectedEvidenceTypes, ", "), evidenceType)
		}
	}

	// Submit evidence
	body := map[string]string{
		"control_id":        control.ID,
		"type":              evidenceType,
		"name":              name,
		"url_or_identifier": url,
		"description":       description,
	}
	if gitHash != "" {
		body["git_hash"] = gitHash
	}
	bodyBytes, _ := json.Marshal(body)

	apiURL := cfg.APIURL + "/api/v1/evidence"
	resp, err := makeAPIRequest(cfg, "POST", apiURL, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var evidence EvidenceItem
	if err := json.Unmarshal(resp, &evidence); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Evidence submitted successfully.\n")
	fmt.Printf("  ID:      %s\n", evidence.ID)
	fmt.Printf("  Control: %s (%s)\n", controlCode, control.Name)
	fmt.Printf("  Type:    %s\n", evidence.Type)
	fmt.Printf("  Name:    %s\n", evidence.Name)
	fmt.Printf("  Status:  %s\n", evidence.Status)
	if url != "" {
		fmt.Printf("  URL:     %s\n", url)
	}
	if evidence.GitHash != nil && *evidence.GitHash != "" {
		fmt.Printf("  Commit:  %s\n", *evidence.GitHash)
	}
}

// cmdEvidenceList lists evidence records
func cmdEvidenceList(args []string) {
	var controlCode, evidenceType, status string
	limit := 20

	for _, arg := range args {
		if strings.HasPrefix(arg, "--control=") {
			controlCode = strings.TrimPrefix(arg, "--control=")
		} else if strings.HasPrefix(arg, "--type=") {
			evidenceType = strings.TrimPrefix(arg, "--type=")
		} else if strings.HasPrefix(arg, "--status=") {
			status = strings.TrimPrefix(arg, "--status=")
		} else if strings.HasPrefix(arg, "--limit=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := loadAndResolveConfig()

	// Build URL with query params
	apiURL := cfg.APIURL + "/api/v1/evidence?limit=" + fmt.Sprintf("%d", limit)
	if evidenceType != "" {
		apiURL += "&type=" + evidenceType
	}
	if status != "" {
		apiURL += "&status=" + status
	}

	// If control code given, resolve to UUID first
	if controlCode != "" {
		controlID, err := findControlIDByCode(cfg, controlCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		apiURL += "&control_id=" + controlID
	}

	resp, err := makeAPIRequest(cfg, "GET", apiURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var listResp ListEvidenceAPIResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(listResp.Evidence) == 0 {
		fmt.Println("No evidence found.")
		return
	}

	fmt.Printf("Found %d evidence records:\n\n", listResp.Total)
	for _, e := range listResp.Evidence {
		statusBadge := formatEvidenceStatus(e.Status)
		commitInfo := ""
		if e.GitHash != nil && *e.GitHash != "" {
			commitInfo = " @ " + (*e.GitHash)[:8]
		}
		fmt.Printf("  %s %s [%s] %s%s\n", e.ID[:8]+"...", statusBadge, e.Type, e.Name, commitInfo)
		if e.URLOrIdentifier != "" {
			fmt.Printf("    URL: %s\n", e.URLOrIdentifier)
		}
	}
}

// cmdEvidenceVerify marks evidence as verified
func cmdEvidenceVerify(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: evidence ID required")
		fmt.Fprintln(os.Stderr, "Usage: polaris evidence verify <evidence-id>")
		os.Exit(1)
	}

	evidenceID := args[0]

	cfg := loadAndResolveConfig()

	apiURL := cfg.APIURL + "/api/v1/evidence/" + evidenceID + "/verify"
	resp, err := makeAPIRequest(cfg, "POST", apiURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var evidence EvidenceItem
	if err := json.Unmarshal(resp, &evidence); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Evidence %s verified.\n", evidenceID)
	fmt.Printf("  Name:   %s\n", evidence.Name)
	fmt.Printf("  Status: %s\n", evidence.Status)
}

// findControlIDByCode looks up a control by its RC-XXX code and returns its UUID
func findControlIDByCode(cfg *Config, controlCode string) (string, error) {
	url := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode
	resp, err := makeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("control %s not found: %w", controlCode, err)
	}

	var control struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp, &control); err != nil {
		return "", fmt.Errorf("parse control response: %w", err)
	}

	if control.ID == "" {
		return "", fmt.Errorf("control %s not found", controlCode)
	}

	return control.ID, nil
}

// formatEvidenceStatus formats evidence status for display
func formatEvidenceStatus(status string) string {
	switch status {
	case "not_configured":
		return "[NOT CONFIGURED]"
	case "configured":
		return "[CONFIGURED]"
	case "sample":
		return "[SAMPLE]"
	case "verified":
		return "[VERIFIED]"
	default:
		return "[" + strings.ToUpper(status) + "]"
	}
}

// ============================================================================
// Init Command
// ============================================================================

func printInitUsage() {
	fmt.Println(`polaris init - Initialize Polaris for this repository

Usage:
  polaris init [options]

Options:
  --project <name>    Set project name (default: from git remote or directory name)
  --skip-plugin       Skip installing the Polaris plugin for Claude Code
  --force             Overwrite existing config and plugin without prompting
  -y, --yes           Accept all defaults non-interactively

What it does:
  1. Creates .polaris.yaml with project name and detected components
  2. Installs the Polaris plugin for Claude Code (if available)
  3. Adds Polaris sections to AGENTS.md (creates or appends)
  4. Checks if API credentials are configured

Examples:
  polaris init                         Interactive setup
  polaris init --project my-service    Set project name directly
  polaris init -y                      Accept all auto-detected defaults
  polaris init --force                 Overwrite existing config`)
}

// editorBinaries maps editor names to their CLI binary names for PATH detection
var editorBinaries = []struct {
	name   string
	binary string
}{
	{"claude", "claude"},
	{"codex", "codex"},
	{"gemini", "gemini"},
	{"cursor", "cursor"},
	{"windsurf", "windsurf"},
	{"copilot", "copilot"},
	{"augment", "auggie"},
}

// isEditorAvailable checks if the given CLI binary is on the PATH.
func isEditorAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// isClaudeCodeAvailable checks if the claude CLI is on the PATH.
func isClaudeCodeAvailable() bool {
	return isEditorAvailable("claude")
}

// cmdInit initializes Polaris for a repository
func cmdInit(args []string) {
	var projectName string
	var skipPlugin bool
	var force bool
	var yesAll bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "help", "--help", "-h":
			printInitUsage()
			return
		case "--skip-plugin", "--skip-skills":
			skipPlugin = true
		case "--force":
			force = true
		case "-y", "--yes":
			yesAll = true
		case "--project":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --project requires a value")
				os.Exit(1)
			}
			i++
			projectName = args[i]
		default:
			if strings.HasPrefix(args[i], "--project=") {
				projectName = strings.TrimPrefix(args[i], "--project=")
			}
		}
	}

	fmt.Println("Initializing Polaris...")
	fmt.Println()

	// Step 1: Require git repo
	gitRoot := detectGitRoot()
	if gitRoot == "" {
		fmt.Fprintln(os.Stderr, "Error: not a git repository.")
		fmt.Fprintln(os.Stderr, "Polaris must be initialized inside a git repository.")
		fmt.Fprintln(os.Stderr, "Run 'git init' first, then try again.")
		os.Exit(1)
	}

	// Step 2: Generate .polaris.yaml
	configPath := filepath.Join(gitRoot, ".polaris.yaml")
	writeConfig := true

	if _, err := os.Stat(configPath); err == nil {
		// File exists — always prompt before overwriting (--force only affects skills)
		if yesAll {
			writeConfig = false
			fmt.Println("Keeping existing .polaris.yaml (use interactive mode to overwrite)")
		} else {
			existing, _ := os.ReadFile(configPath)
			fmt.Println("Existing .polaris.yaml found:")
			fmt.Println(string(existing))

			var overwrite bool
			err := huh.NewConfirm().
				Title("Overwrite existing .polaris.yaml?").
				Affirmative("Yes").
				Negative("No").
				Value(&overwrite).
				Run()
			if err != nil || !overwrite {
				writeConfig = false
				fmt.Println("Keeping existing .polaris.yaml")
			}
		}
	}

	var cfg *ProjectConfig
	if writeConfig {
		cfg = buildProjectConfig(gitRoot, projectName, yesAll)
		if err := writeProjectConfig(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing .polaris.yaml: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created .polaris.yaml (project: %s, %d components)\n", cfg.Project, len(cfg.Components))
	} else {
		// Load existing config for summary
		data, _ := os.ReadFile(configPath)
		cfg = &ProjectConfig{}
		_ = yaml.Unmarshal(data, cfg)
	}
	fmt.Println()

	// Step 3: Install skills for detected editors
	pluginInstalled := false
	pluginVersion := ""
	if !skipPlugin {
		plugins, _ := getInstalledPlugins()
		installedMap := make(map[string]*pluginInfo)
		for i := range plugins {
			installedMap[plugins[i].Editor] = &plugins[i]
		}

		// Fetch server version once for update checks
		loginCfgForPlugin, _ := loadConfig()
		serverVersion := fetchServerPluginVersion(loginCfgForPlugin)

		// Detect available editors
		var detectedEditors []string
		for _, e := range editorBinaries {
			if isEditorAvailable(e.binary) {
				detectedEditors = append(detectedEditors, e.name)
			}
		}

		if len(detectedEditors) == 0 {
			fmt.Println("Skills: No supported editors detected on PATH")
			fmt.Println("  Supported: claude, codex, gemini, cursor, windsurf, copilot, augment")
			fmt.Println("  Install an editor, then run: polaris plugin install <editor>")
		}

		for _, editorName := range detectedEditors {
			existing := installedMap[editorName]

			if existing != nil {
				// Already installed — check for updates
				if serverVersion != "" && serverVersion != existing.Version {
					doUpdate := force || yesAll
					if !doUpdate {
						err := huh.NewConfirm().
							Title(fmt.Sprintf("Update Polaris skills for %s? (v%s → v%s)", editorName, existing.Version, serverVersion)).
							Affirmative("Yes").
							Negative("No").
							Value(&doUpdate).
							Run()
						if err != nil {
							doUpdate = false
						}
					}
					if doUpdate {
						if err := installPlugin(editorName); err != nil {
							fmt.Fprintf(os.Stderr, "Warning: could not update %s skills: %v\n", editorName, err)
						} else {
							pluginInstalled = true
							pluginVersion = serverVersion
						}
					} else {
						pluginInstalled = true
						pluginVersion = existing.Version
						fmt.Printf("Skills (%s): Keeping v%s\n", editorName, existing.Version)
					}
				} else {
					pluginInstalled = true
					pluginVersion = existing.Version
					fmt.Printf("Skills (%s): Up to date (v%s)\n", editorName, existing.Version)
				}
			} else {
				// Editor available but skills not installed
				doInstall := yesAll
				if !yesAll {
					err := huh.NewConfirm().
						Title(fmt.Sprintf("Install Polaris skills for %s?", editorName)).
						Affirmative("Yes").
						Negative("No").
						Value(&doInstall).
						Run()
					if err != nil {
						doInstall = false
					}
				}
				if doInstall {
					if err := installPlugin(editorName); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: could not install %s skills: %v\n", editorName, err)
					} else {
						pluginInstalled = true
						// Read back the version from metadata
						updatedPlugins, _ := getInstalledPlugins()
						for _, p := range updatedPlugins {
							if p.Editor == editorName {
								pluginVersion = p.Version
								break
							}
						}
					}
				}
			}
		}
		fmt.Println()
	}

	// Step 4: Set up AGENTS.md
	agentsMdAction := ""
	action, err := ensureAgentsMd(gitRoot, force, yesAll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set up AGENTS.md: %v\n", err)
	} else {
		agentsMdAction = action
		switch action {
		case "created":
			fmt.Println("Created AGENTS.md with Polaris sections")
		case "appended":
			fmt.Println("Appended Polaris sections to AGENTS.md")
		case "updated":
			fmt.Println("Updated Polaris sections in AGENTS.md")
		case "skipped":
			fmt.Println("AGENTS.md: Skipped")
		}
	}
	fmt.Println()

	// Step 5: Check credentials
	credentialsConfigured := false
	credentialsURL := ""
	loginCfg, _ := loadConfig()
	if loginCfg != nil && loginCfg.APIKey != "" {
		credentialsConfigured = true
		credentialsURL = loginCfg.APIURL
		fmt.Printf("Credentials: Configured (API URL: %s)\n", credentialsURL)
	} else {
		fmt.Println("Credentials: Not configured")
		fmt.Println("  Run 'polaris login' to set up API credentials.")
	}
	fmt.Println()

	// Step 6: Print summary
	printInitSummary(cfg, pluginInstalled, pluginVersion, credentialsConfigured, agentsMdAction)
}

// buildProjectConfig creates a ProjectConfig interactively or from defaults
func buildProjectConfig(gitRoot, projectName string, yesAll bool) *ProjectConfig {
	// Auto-detect project name
	if projectName == "" {
		projectName = detectProjectName(gitRoot)
	}

	// Auto-detect components
	components := detectComponents(gitRoot)

	if yesAll {
		if len(components) == 0 {
			components = []ProjectComponent{{Name: projectName, Path: "."}}
		}
		return &ProjectConfig{Project: projectName, Components: components}
	}

	// Interactive: prompt for project name
	err := huh.NewInput().
		Title("Project name").
		Value(&projectName).
		Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Show detected components
	if len(components) > 0 {
		fmt.Println("Detected components:")
		for i, c := range components {
			fmt.Printf("  %d. %-20s %s\n", i+1, c.Name, c.Path)
		}
		fmt.Println()

		var accept bool
		err := huh.NewConfirm().
			Title("Accept detected components?").
			Affirmative("Yes").
			Negative("No, let me edit").
			Value(&accept).
			Run()
		if err != nil {
			os.Exit(1)
		}

		if !accept {
			components = promptComponents()
		}
	} else {
		fmt.Println("No components auto-detected.")
		fmt.Println()

		var addManual bool
		err := huh.NewConfirm().
			Title("Add components manually?").
			Affirmative("Yes").
			Negative("No, use project root").
			Value(&addManual).
			Run()
		if err != nil {
			os.Exit(1)
		}

		if addManual {
			components = promptComponents()
		} else {
			components = []ProjectComponent{{Name: projectName, Path: "."}}
		}
	}

	return &ProjectConfig{Project: projectName, Components: components}
}

// promptComponents interactively collects component definitions
func promptComponents() []ProjectComponent {
	var components []ProjectComponent
	for {
		var name, path string

		err := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Component name").
					Value(&name),
				huh.NewInput().
					Title("Component path (relative to repo root)").
					Value(&path),
			),
		).Run()
		if err != nil {
			break
		}

		if name == "" || path == "" {
			break
		}

		// Ensure path ends with /
		if path != "." && !strings.HasSuffix(path, "/") {
			path += "/"
		}

		components = append(components, ProjectComponent{Name: name, Path: path})
		fmt.Printf("  Added: %s -> %s\n", name, path)

		var addMore bool
		err = huh.NewConfirm().
			Title("Add another component?").
			Affirmative("Yes").
			Negative("Done").
			Value(&addMore).
			Run()
		if err != nil || !addMore {
			break
		}
	}
	return components
}

// detectGitRoot returns the git repo root, or empty string if not in a git repo
func detectGitRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// detectProjectName extracts a project name from git remote or directory name
func detectProjectName(gitRoot string) string {
	// Try git remote
	out, err := exec.Command("git", "-C", gitRoot, "remote", "get-url", "origin").Output()
	if err == nil {
		remote := strings.TrimSpace(string(out))
		// Extract repo name from URL
		// Handles: git@github.com:user/repo.git, https://github.com/user/repo.git, etc.
		remote = strings.TrimSuffix(remote, ".git")
		parts := strings.Split(remote, "/")
		if len(parts) > 0 {
			name := parts[len(parts)-1]
			// Also handle SSH style with ':'
			if idx := strings.LastIndex(name, ":"); idx >= 0 {
				name = name[idx+1:]
			}
			if name != "" {
				return name
			}
		}
	}

	// Fall back to directory name
	return filepath.Base(gitRoot)
}

// detectLanguages scans the root directory for language indicator files
func detectLanguages(rootDir string) []string {
	indicators := map[string][]string{
		"Go":         {"go.mod", "go.work"},
		"Java":       {"pom.xml", "build.gradle", "build.gradle.kts"},
		"Python":     {"pyproject.toml", "setup.py", "requirements.txt", "Pipfile"},
		"Rust":       {"Cargo.toml"},
		"Ruby":       {"Gemfile"},
		"JavaScript": {"package.json"},
		"TypeScript": {"tsconfig.json"},
		"C#":         {},
		"C/C++":      {"CMakeLists.txt"},
		"PHP":        {"composer.json"},
		"Elixir":     {"mix.exs"},
		"Scala":      {"build.sbt"},
	}

	// Glob-based indicators
	globIndicators := map[string]string{
		"C#":   "*.csproj",
		"Ruby": "*.gemspec",
	}

	var detected []string
	seen := make(map[string]bool)

	// Check file-based indicators
	for lang, files := range indicators {
		for _, f := range files {
			if _, err := os.Stat(filepath.Join(rootDir, f)); err == nil {
				if !seen[lang] {
					detected = append(detected, lang)
					seen[lang] = true
				}
				break
			}
		}
	}

	// Check glob-based indicators
	for lang, pattern := range globIndicators {
		if seen[lang] {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(rootDir, pattern))
		if len(matches) > 0 {
			detected = append(detected, lang)
			seen[lang] = true
		}
		// Also check one level deep
		matches, _ = filepath.Glob(filepath.Join(rootDir, "*", pattern))
		if len(matches) > 0 && !seen[lang] {
			detected = append(detected, lang)
			seen[lang] = true
		}
	}

	// Check for .sln files (C#)
	if !seen["C#"] {
		matches, _ := filepath.Glob(filepath.Join(rootDir, "*.sln"))
		if len(matches) > 0 {
			detected = append(detected, "C#")
		}
	}

	return detected
}

// detectComponents performs multi-phase language-agnostic component detection
func detectComponents(rootDir string) []ProjectComponent {
	var components []ProjectComponent
	seen := make(map[string]bool)

	addComponent := func(name, path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		components = append(components, ProjectComponent{Name: name, Path: path})
	}

	excludeDirs := map[string]bool{
		"node_modules": true, "vendor": true, "venv": true, ".venv": true,
		"target": true, "build": true, "dist": true, ".git": true,
		"__pycache__": true, ".tox": true, "env": true,
	}

	// Phase 1: Workspace declarations

	// Go workspaces (go.work)
	if data, err := os.ReadFile(filepath.Join(rootDir, "go.work")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "use ") || (strings.HasPrefix(line, "./") && !strings.HasPrefix(line, "//")) {
				dir := strings.TrimPrefix(line, "use ")
				dir = strings.TrimSpace(dir)
				dir = strings.Trim(dir, "./")
				if dir != "" && dir != "." {
					name := filepath.Base(dir)
					addComponent(name, dir+"/")
				}
			}
		}
	}

	// Rust workspaces (Cargo.toml [workspace] members)
	if data, err := os.ReadFile(filepath.Join(rootDir, "Cargo.toml")); err == nil {
		content := string(data)
		if strings.Contains(content, "[workspace]") {
			// Simple extraction of members array
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "\"") && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "members") {
					// Extract quoted paths
					for _, part := range strings.Split(line, "\"") {
						part = strings.TrimSpace(part)
						if part != "" && !strings.ContainsAny(part, "[]=#,") {
							if _, err := os.Stat(filepath.Join(rootDir, part)); err == nil {
								addComponent(filepath.Base(part), part+"/")
							}
						}
					}
				}
			}
		}
	}

	// JS/TS workspaces (package.json "workspaces")
	if data, err := os.ReadFile(filepath.Join(rootDir, "package.json")); err == nil {
		var pkg map[string]interface{}
		if json.Unmarshal(data, &pkg) == nil {
			if ws, ok := pkg["workspaces"]; ok {
				var patterns []string
				switch v := ws.(type) {
				case []interface{}:
					for _, p := range v {
						if s, ok := p.(string); ok {
							patterns = append(patterns, s)
						}
					}
				case map[string]interface{}:
					// Yarn v1 style: { "packages": ["..."] }
					if pkgs, ok := v["packages"]; ok {
						if arr, ok := pkgs.([]interface{}); ok {
							for _, p := range arr {
								if s, ok := p.(string); ok {
									patterns = append(patterns, s)
								}
							}
						}
					}
				}
				for _, pattern := range patterns {
					matches, _ := filepath.Glob(filepath.Join(rootDir, pattern))
					for _, m := range matches {
						rel, _ := filepath.Rel(rootDir, m)
						if rel != "" && rel != "." {
							info, err := os.Stat(m)
							if err == nil && info.IsDir() {
								addComponent(filepath.Base(rel), rel+"/")
							}
						}
					}
				}
			}
		}
	}

	// Java Maven modules (pom.xml <modules>)
	if data, err := os.ReadFile(filepath.Join(rootDir, "pom.xml")); err == nil {
		content := string(data)
		// Simple XML extraction - find <module>...</module> tags
		for {
			start := strings.Index(content, "<module>")
			if start < 0 {
				break
			}
			content = content[start+8:]
			end := strings.Index(content, "</module>")
			if end < 0 {
				break
			}
			module := strings.TrimSpace(content[:end])
			content = content[end+9:]
			if module != "" {
				if _, err := os.Stat(filepath.Join(rootDir, module)); err == nil {
					addComponent(filepath.Base(module), module+"/")
				}
			}
		}
	}

	// Gradle subprojects (settings.gradle)
	for _, settingsFile := range []string{"settings.gradle", "settings.gradle.kts"} {
		if data, err := os.ReadFile(filepath.Join(rootDir, settingsFile)); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "include") {
					// Extract quoted project names like ':subproject'
					for _, part := range strings.Split(line, "'") {
						part = strings.TrimSpace(part)
						part = strings.TrimPrefix(part, ":")
						if part != "" && !strings.ContainsAny(part, "()=,") {
							dir := strings.ReplaceAll(part, ":", "/")
							if _, err := os.Stat(filepath.Join(rootDir, dir)); err == nil {
								addComponent(filepath.Base(dir), dir+"/")
							}
						}
					}
				}
			}
		}
	}

	// C# solution files (.sln)
	slnFiles, _ := filepath.Glob(filepath.Join(rootDir, "*.sln"))
	for _, slnFile := range slnFiles {
		if data, err := os.ReadFile(slnFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "Project(") && strings.Contains(line, ".csproj") {
					// Extract project path from: Project("...") = "Name", "path/to/proj.csproj", "..."
					parts := strings.Split(line, "\"")
					for _, part := range parts {
						if strings.HasSuffix(part, ".csproj") || strings.HasSuffix(part, ".fsproj") {
							dir := filepath.Dir(part)
							if dir != "." && dir != "" {
								dir = strings.ReplaceAll(dir, "\\", "/")
								if _, err := os.Stat(filepath.Join(rootDir, dir)); err == nil {
									addComponent(filepath.Base(dir), dir+"/")
								}
							}
						}
					}
				}
			}
		}
	}

	// Phase 2: Directory scanning for build files in common locations
	buildFiles := []string{
		"go.mod", "package.json", "Cargo.toml", "pom.xml",
		"build.gradle", "build.gradle.kts", "pyproject.toml",
		"setup.py", "Gemfile", "mix.exs", "build.sbt",
		"CMakeLists.txt", "composer.json",
	}

	scanPatterns := []string{"services", "cmd", "apps", "packages", "libs", "modules", "internal"}
	for _, dir := range scanPatterns {
		fullPath := filepath.Join(rootDir, dir)
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || excludeDirs[entry.Name()] {
				continue
			}
			subPath := filepath.Join(dir, entry.Name())
			for _, bf := range buildFiles {
				if _, err := os.Stat(filepath.Join(rootDir, subPath, bf)); err == nil {
					addComponent(entry.Name(), subPath+"/")
					break
				}
			}
		}
	}

	// Phase 3: Go cmd/ pattern (directories with main.go)
	cmdDir := filepath.Join(rootDir, "cmd")
	if entries, err := os.ReadDir(cmdDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			mainPath := filepath.Join(cmdDir, entry.Name(), "main.go")
			if _, err := os.Stat(mainPath); err == nil {
				addComponent(entry.Name(), "cmd/"+entry.Name()+"/")
			}
		}
	}

	// Phase 4: Directories with Dockerfiles
	entries, err := os.ReadDir(rootDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || excludeDirs[entry.Name()] {
				continue
			}
			dockerPath := filepath.Join(rootDir, entry.Name(), "Dockerfile")
			if _, err := os.Stat(dockerPath); err == nil {
				addComponent(entry.Name(), entry.Name()+"/")
			}
		}
	}

	// Phase 5: Root directory itself if it has a build file and no other components found
	if len(components) == 0 {
		for _, bf := range buildFiles {
			if _, err := os.Stat(filepath.Join(rootDir, bf)); err == nil {
				// Root has a build file — will be handled by caller as fallback
				break
			}
		}
	}

	return components
}

// loadProjectConfigFrom reads .polaris.yaml from the specified directory's git root.
// If targetDir is empty, uses the current working directory (existing behavior).
func loadProjectConfigFrom(targetDir string) *ProjectConfig {
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

	data, err := os.ReadFile(filepath.Join(gitRoot, ".polaris.yaml"))
	if err != nil {
		return nil
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

// loadProjectConfig reads .polaris.yaml from the current directory's git root.
func loadProjectConfig() *ProjectConfig {
	return loadProjectConfigFrom("")
}

// mapFindingsToComponents sets linked_services on each finding based on
// evidence paths matched against .polaris.yaml components. Uses longest-prefix
// matching so nested paths (e.g. services/x/frontend/) beat parent paths.
func mapFindingsToComponents(findings []interface{}, projectCfg *ProjectConfig) {
	if projectCfg == nil || len(projectCfg.Components) == 0 {
		return
	}

	// Sort components by path length descending for longest-prefix-first matching
	type comp struct {
		name string
		path string
	}
	sorted := make([]comp, len(projectCfg.Components))
	for i, c := range projectCfg.Components {
		sorted[i] = comp{name: c.Name, path: c.Path}
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[j].path) > len(sorted[i].path) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	project := projectCfg.Project

	for _, f := range findings {
		finding, ok := f.(map[string]interface{})
		if !ok {
			continue
		}

		// Skip if finding already has linked_services set
		if existing, ok := finding["linked_services"]; ok {
			if arr, ok := existing.([]interface{}); ok && len(arr) > 0 {
				continue
			}
		}

		// Collect evidence paths
		evidence, ok := finding["evidence"].([]interface{})
		if !ok || len(evidence) == 0 {
			continue
		}

		matched := make(map[string]bool)
		for _, ev := range evidence {
			evMap, ok := ev.(map[string]interface{})
			if !ok {
				continue
			}
			path, _ := evMap["path"].(string)
			if path == "" {
				continue
			}

			// Find best (longest prefix) component match
			for _, c := range sorted {
				if strings.HasPrefix(path, c.path) {
					matched[project+"/"+c.name] = true
					break // longest prefix wins
				}
			}
		}

		if len(matched) > 0 {
			services := make([]interface{}, 0, len(matched))
			for svc := range matched {
				services = append(services, svc)
			}
			finding["linked_services"] = services
		}
	}
}

// writeProjectConfig writes a ProjectConfig to disk as .polaris.yaml
func writeProjectConfig(path string, cfg *ProjectConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := "# Polaris project configuration\n# Used by detect-risks and reliability-review skills for consistent service naming\n"
	return os.WriteFile(path, []byte(header+string(data)), 0644)
}


// =============================================================================
// Plugin Management Functions
// =============================================================================

// pluginInfo tracks installed plugin metadata
type pluginInfo struct {
	Editor    string `json:"editor"`
	Version   string `json:"version"`
	Installed string `json:"installed"` // ISO8601 timestamp
	Location  string `json:"location"`
}

// getPluginDir returns the installation directory for a given editor's plugin.
// For Claude, returns the marketplace cache path. For other editors, returns
// the canonical skill/agent directory where the tarball is extracted directly.
func getPluginDir(editor, version string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	switch editor {
	case "claude":
		// Claude Code plugin cache format: ~/.claude/plugins/cache/<source>/<plugin>/<version>/
		return filepath.Join(home, ".claude", "plugins", "cache", "polaris-api", "polaris", version), nil
	case "codex":
		// Codex skills: ~/.agents/skills/ (tarball has {name}/SKILL.md layout)
		return filepath.Join(home, ".agents", "skills"), nil
	case "gemini":
		// Gemini: ~/.gemini/ (tarball has skills/{name}/SKILL.md + agents/polaris-*.md)
		return filepath.Join(home, ".gemini"), nil
	case "cursor":
		// Cursor: ~/.cursor/ (tarball has skills/{name}/SKILL.md + agents/polaris-*.md)
		return filepath.Join(home, ".cursor"), nil
	case "windsurf":
		// Windsurf skills: ~/.codeium/windsurf/skills/ (tarball has {name}/SKILL.md layout)
		return filepath.Join(home, ".codeium", "windsurf", "skills"), nil
	case "copilot":
		// Copilot: ~/.copilot/ (tarball has skills/{name}/SKILL.md + agents/polaris-*.agent.md)
		return filepath.Join(home, ".copilot"), nil
	case "augment":
		// Augment: ~/.augment/ (tarball has skills/{name}/SKILL.md + agents/polaris-*.md)
		return filepath.Join(home, ".augment"), nil
	default:
		return "", fmt.Errorf("unsupported editor: %s (available: claude, codex, gemini, cursor, windsurf, copilot, augment, copilot, augment)", editor)
	}
}

// installPlugin downloads and installs the Polaris plugin for the specified editor
// cleanupOldClaudeInstallations removes old Polaris installations from Claude Code directories
func cleanupOldClaudeInstallations() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Remove old commands from ~/.claude/commands/polaris/
	oldCommandsDir := filepath.Join(home, ".claude", "commands", "polaris")
	if _, err := os.Stat(oldCommandsDir); err == nil {
		fmt.Printf("Removing old Polaris commands from %s...\n", oldCommandsDir)
		if err := os.RemoveAll(oldCommandsDir); err != nil {
			return fmt.Errorf("remove old commands: %w", err)
		}
		fmt.Println("✓ Removed old commands")
	}

	// Note: We do NOT touch ~/.claude/agents/ as those are community agents, not Polaris-specific

	return nil
}

// extractTarball extracts a tar.gz tarball to the target directory
func extractTarball(tarballData []byte, targetDir string) error {
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

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("create parent directory: %w", err)
			}

			// Create file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("write file %s: %w", targetPath, err)
			}
			outFile.Close()
			fileCount++
		}
	}

	fmt.Printf("✓ Extracted %d files\n", fileCount)
	return nil
}

// installClaudePlugin installs the plugin using Claude Code's local marketplace mechanism
func installClaudePlugin(version string, tarballData []byte) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Create local marketplace structure at ~/.polaris/marketplace
	marketplaceDir := filepath.Join(home, ".polaris", "marketplace")
	pluginDir := filepath.Join(marketplaceDir, "plugins", "polaris")

	// Clean up existing installation
	if err := os.RemoveAll(marketplaceDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clean up old marketplace: %w", err)
	}

	// Create plugin directory
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	// Extract plugin to local marketplace
	fmt.Printf("Setting up local marketplace at %s...\n", marketplaceDir)
	if err := extractTarball(tarballData, pluginDir); err != nil {
		return fmt.Errorf("extract plugin: %w", err)
	}

	// Create marketplace.json
	marketplaceJSON := fmt.Sprintf(`{
  "$schema": "https://anthropic.com/claude-code/marketplace.schema.json",
  "name": "polaris-local",
  "description": "Polaris plugin for reliability risk analysis",
  "owner": {
    "name": "Relynce",
    "email": "team@relynce.ai"
  },
  "plugins": [
    {
      "name": "polaris",
      "version": "%s",
      "description": "Reliability risk analysis and incident prevention for engineering teams",
      "author": {
        "name": "Relynce",
        "email": "team@relynce.ai"
      },
      "source": "./plugins/polaris",
      "category": "development",
      "homepage": "https://docs.relynce.ai/polaris"
    }
  ]
}`, version)

	marketplaceManifestDir := filepath.Join(marketplaceDir, ".claude-plugin")
	if err := os.MkdirAll(marketplaceManifestDir, 0755); err != nil {
		return fmt.Errorf("create marketplace manifest directory: %w", err)
	}

	marketplaceManifestPath := filepath.Join(marketplaceManifestDir, "marketplace.json")
	if err := os.WriteFile(marketplaceManifestPath, []byte(marketplaceJSON), 0644); err != nil {
		return fmt.Errorf("write marketplace manifest: %w", err)
	}

	fmt.Println("✓ Created local marketplace")

	// Remove old marketplace if it exists
	fmt.Println("Removing old Polaris marketplace (if exists)...")
	cmd := exec.Command("claude", "plugin", "marketplace", "remove", "polaris-local")
	cmd.Run() // Ignore error - marketplace might not exist

	// Add marketplace using claude CLI
	fmt.Println("Registering marketplace with Claude Code...")
	cmd = exec.Command("claude", "plugin", "marketplace", "add", marketplaceDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add marketplace: %w\nOutput: %s", err, string(output))
	}
	fmt.Println("✓ Marketplace registered")

	// Install plugin using claude CLI
	fmt.Println("Installing plugin...")
	cmd = exec.Command("claude", "plugin", "install", "polaris@polaris-local")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install plugin: %w\nOutput: %s", err, string(output))
	}
	fmt.Println("✓ Plugin installed")

	// Save metadata for polaris CLI tracking
	if err := savePluginInfo("claude", version, pluginDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
	}

	fmt.Printf("\n✅ Polaris plugin successfully installed!\n")
	fmt.Printf("Commands are now available: /polaris:detect-risks, /polaris:analyze-risks, etc.\n")
	fmt.Printf("\nRestart Claude Code to ensure all commands are loaded.\n")

	return nil
}

func installPlugin(editor string) error {
	fmt.Printf("Installing Polaris plugin for %s...\n", editor)

	// Clean up old installations first (if applicable)
	if editor == "claude" {
		if err := cleanupOldClaudeInstallations(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not clean up old installations: %v\n", err)
		}
	}

	// Load credentials
	cfg, err := loadConfig()
	if err != nil || cfg == nil || cfg.APIKey == "" || cfg.APIURL == "" {
		return fmt.Errorf("no API credentials configured — run 'polaris login' first")
	}

	// Download plugin tarball
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

	// Get version and checksum from headers
	version := strings.TrimPrefix(filepath.Base(resp.Header.Get("Content-Disposition")), "attachment; filename=polaris-plugin-")
	version = strings.TrimSuffix(version, ".tar.gz")
	checksum := resp.Header.Get("X-Checksum")

	// Read tarball
	tarballData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read tarball: %w", err)
	}

	// Verify checksum if provided
	if checksum != "" {
		hash := sha256.Sum256(tarballData)
		actualChecksum := "sha256:" + hex.EncodeToString(hash[:])
		if actualChecksum != checksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, actualChecksum)
		}
		fmt.Println("✓ Checksum verified")
	}

	// For Claude Code, use local marketplace approach
	if editor == "claude" {
		return installClaudePlugin(version, tarballData)
	}

	// For other editors, use the old direct installation approach
	targetDir, err := getPluginDir(editor, version)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create plugin directory: %w", err)
	}

	// Extract tarball
	fmt.Printf("Extracting to %s...\n", targetDir)
	if err := extractTarball(tarballData, targetDir); err != nil {
		return err
	}

	// Editor-specific post-extraction setup
	if editor == "gemini" {
		if err := enableGeminiSubagents(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not enable Gemini subagents: %v\n", err)
		}
	}

	// Save plugin metadata
	if err := savePluginInfo(editor, version, targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save plugin metadata: %v\n", err)
	}

	// Print next steps
	printPostInstallInstructions(editor, targetDir)

	return nil
}

// updatePlugin updates installed plugin(s) to the latest version
func updatePlugin(editor string) error {
	if editor == "" {
		// Update all installed plugins
		plugins, err := getInstalledPlugins()
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
			if err := installPlugin(p.Editor); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", p.Editor, err)
			}
		}
		return nil
	}

	// Update specific plugin
	return installPlugin(editor)
}

// listInstalledPlugins lists all installed Polaris plugins
func listInstalledPlugins() {
	plugins, err := getInstalledPlugins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if len(plugins) == 0 {
		fmt.Println("No Polaris plugins installed.")
		fmt.Println("\nTo install:")
		fmt.Println("  polaris plugin install <editor>")
		fmt.Println("  Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
		return
	}

	// Check server version for upgrade indicator
	cfg, _ := loadConfig()
	serverVersion := fetchServerPluginVersion(cfg)

	fmt.Println("Installed Polaris plugins:")
	for _, p := range plugins {
		fmt.Printf("\n  %s\n", p.Editor)
		fmt.Printf("    Version:   %s\n", p.Version)
		if serverVersion != "" && p.Version != serverVersion {
			fmt.Printf("    Latest:    %s (update available)\n", serverVersion)
		} else if serverVersion != "" {
			fmt.Printf("    Latest:    %s (up to date)\n", serverVersion)
		}
		fmt.Printf("    Installed: %s\n", p.Installed)
		fmt.Printf("    Location:  %s\n", p.Location)
	}

	if serverVersion != "" {
		for _, p := range plugins {
			if p.Version != serverVersion {
				fmt.Printf("\nRun 'polaris plugin update' to upgrade.\n")
				break
			}
		}
	}
}

// polarisSkillNames lists all Polaris skill directory names for cleanup
var polarisSkillNames = []string{
	"detect-risks", "analyze-risks", "remediate-risks", "risk-check",
	"risk-guidance", "control-guidance", "submit-evidence", "reliability-review",
	"incident-patterns", "sre-context", "list-open",
}

// removePlugin removes an installed plugin (all versions)
func removePlugin(editor string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	// Confirm removal
	fmt.Printf("Remove Polaris plugin for %s? [y/N] ", editor)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		return nil
	}

	switch editor {
	case "claude":
		// Use official CLI to uninstall
		fmt.Println("Uninstalling plugin via Claude Code CLI...")
		cmd := exec.Command("claude", "plugin", "uninstall", "polaris@polaris-local")
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: claude plugin uninstall failed: %v\n", err)
			fmt.Println("Attempting manual cleanup...")
		} else {
			fmt.Println(string(output))
		}

		// Remove local marketplace
		marketplaceDir := filepath.Join(home, ".polaris", "marketplace")
		if err := os.RemoveAll(marketplaceDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove marketplace: %v\n", err)
		} else {
			fmt.Println("✓ Removed local marketplace")
		}

		// Remove marketplace registration
		fmt.Println("Removing marketplace registration...")
		cmd = exec.Command("claude", "plugin", "marketplace", "remove", "polaris-local")
		cmd.Run() // Ignore error - marketplace might not exist

	case "codex":
		// Remove known Polaris skill subdirectories from ~/.agents/skills/
		skillsDir := filepath.Join(home, ".agents", "skills")
		removeSkillDirs(skillsDir)

	case "gemini":
		// Remove skill subdirectories + polaris-*.md agent files
		removeSkillDirs(filepath.Join(home, ".gemini", "skills"))
		removeAgentFiles(filepath.Join(home, ".gemini", "agents"))

	case "cursor":
		// Remove skill subdirectories + polaris-*.md agent files
		removeSkillDirs(filepath.Join(home, ".cursor", "skills"))
		removeAgentFiles(filepath.Join(home, ".cursor", "agents"))

	case "windsurf":
		// Remove known Polaris skill subdirectories from ~/.codeium/windsurf/skills/
		skillsDir := filepath.Join(home, ".codeium", "windsurf", "skills")
		removeSkillDirs(skillsDir)

	case "copilot":
		// Remove skill subdirectories + polaris-*.agent.md agent files
		removeSkillDirs(filepath.Join(home, ".copilot", "skills"))
		removeCopilotAgentFiles(filepath.Join(home, ".copilot", "agents"))

	case "augment":
		// Remove skill subdirectories + polaris-*.md agent files
		removeSkillDirs(filepath.Join(home, ".augment", "skills"))
		removeAgentFiles(filepath.Join(home, ".augment", "agents"))

	default:
		return fmt.Errorf("unsupported editor: %s", editor)
	}

	// Remove metadata
	metadataFile := filepath.Join(home, ".polaris", "plugins.json")
	_ = removePluginFromMetadata(editor, metadataFile)

	fmt.Printf("✓ Removed %s plugin\n", editor)
	return nil
}

// removeSkillDirs removes known Polaris skill subdirectories from a base directory
func removeSkillDirs(baseDir string) {
	for _, name := range polarisSkillNames {
		dir := filepath.Join(baseDir, name)
		if _, err := os.Stat(dir); err == nil {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", dir, err)
			}
		}
	}
}

// enableGeminiSubagents ensures experimental.enableAgents is true in ~/.gemini/settings.json.
// Gemini CLI requires this flag to discover subagent files in ~/.gemini/agents/.
func enableGeminiSubagents() error {
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

	// Get or create experimental section
	experimental, ok := settings["experimental"].(map[string]any)
	if !ok {
		experimental = make(map[string]any)
		settings["experimental"] = experimental
	}

	// Check if already enabled
	if enabled, ok := experimental["enableAgents"].(bool); ok && enabled {
		return nil
	}

	experimental["enableAgents"] = true

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return err
	}

	fmt.Println("✓ Enabled experimental subagents in ~/.gemini/settings.json")
	return nil
}

// removeAgentFiles removes polaris-*.md agent files from a directory
func removeAgentFiles(agentsDir string) {
	matches, err := filepath.Glob(filepath.Join(agentsDir, "polaris-*.md"))
	if err != nil {
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", f, err)
		}
	}
}

// removeCopilotAgentFiles removes polaris-*.agent.md agent files from a directory.
// Copilot uses the .agent.md extension instead of .md.
func removeCopilotAgentFiles(agentsDir string) {
	matches, err := filepath.Glob(filepath.Join(agentsDir, "polaris-*.agent.md"))
	if err != nil {
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", f, err)
		}
	}
}

// Helper functions

// registerWithClaudeCode updates ~/.claude/plugins/installed_plugins.json
func registerWithClaudeCode(version, installPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	registryFile := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")

	// Load existing registry
	type pluginEntry struct {
		Scope        string `json:"scope"`
		InstallPath  string `json:"installPath"`
		Version      string `json:"version"`
		InstalledAt  string `json:"installedAt"`
		LastUpdated  string `json:"lastUpdated"`
		Enabled      bool   `json:"enabled"`
		GitCommitSha string `json:"gitCommitSha,omitempty"`
	}

	type registry struct {
		Version int                          `json:"version"`
		Plugins map[string][]pluginEntry `json:"plugins"`
	}

	var reg registry
	if data, err := os.ReadFile(registryFile); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	// Initialize if empty
	if reg.Version == 0 {
		reg.Version = 2
	}
	if reg.Plugins == nil {
		reg.Plugins = make(map[string][]pluginEntry)
	}

	// Add or update polaris plugin entry
	now := time.Now().Format(time.RFC3339)
	entry := pluginEntry{
		Scope:       "user",
		InstallPath: installPath,
		Version:     version,
		InstalledAt: now,
		LastUpdated: now,
		Enabled:     true, // Auto-enable on install
	}

	// Use key format: plugin@source
	key := "polaris@polaris-api"
	reg.Plugins[key] = []pluginEntry{entry}

	// Save registry
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(registryFile, data, 0644); err != nil {
		return err
	}

	// Also enable plugin in settings.json
	return enablePluginInSettings(key)
}

// enablePluginInSettings enables the plugin in ~/.claude/settings.json
func enablePluginInSettings(pluginKey string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	settingsFile := filepath.Join(home, ".claude", "settings.json")

	// Load existing settings
	var settings map[string]interface{}
	if data, err := os.ReadFile(settingsFile); err == nil {
		_ = json.Unmarshal(data, &settings)
	}

	// Initialize if empty
	if settings == nil {
		settings = make(map[string]interface{})
	}

	// Get or create enabledPlugins object
	enabledPlugins, ok := settings["enabledPlugins"].(map[string]interface{})
	if !ok {
		enabledPlugins = make(map[string]interface{})
		settings["enabledPlugins"] = enabledPlugins
	}

	// Enable this plugin
	enabledPlugins[pluginKey] = true

	// Save settings
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsFile, data, 0644)
}

// disablePluginInSettings disables the plugin in ~/.claude/settings.json
func disablePluginInSettings(pluginKey string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	settingsFile := filepath.Join(home, ".claude", "settings.json")

	// Load existing settings
	var settings map[string]interface{}
	if data, err := os.ReadFile(settingsFile); err == nil {
		_ = json.Unmarshal(data, &settings)
	}

	if settings == nil {
		return nil // Nothing to disable
	}

	// Get enabledPlugins object
	enabledPlugins, ok := settings["enabledPlugins"].(map[string]interface{})
	if !ok {
		return nil // Nothing to disable
	}

	// Remove this plugin
	delete(enabledPlugins, pluginKey)

	// Save settings
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsFile, data, 0644)
}

// unregisterFromClaudeCode removes polaris from ~/.claude/plugins/installed_plugins.json
func unregisterFromClaudeCode() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	registryFile := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")

	// Load existing registry
	type pluginEntry struct {
		Scope        string `json:"scope"`
		InstallPath  string `json:"installPath"`
		Version      string `json:"version"`
		InstalledAt  string `json:"installedAt"`
		LastUpdated  string `json:"lastUpdated"`
		GitCommitSha string `json:"gitCommitSha,omitempty"`
	}

	type registry struct {
		Version int                          `json:"version"`
		Plugins map[string][]pluginEntry `json:"plugins"`
	}

	var reg registry
	if data, err := os.ReadFile(registryFile); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	if reg.Plugins == nil {
		return nil // Nothing to remove
	}

	// Remove polaris plugin entry
	key := "polaris@polaris-api"
	delete(reg.Plugins, key)

	// Save registry
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(registryFile, data, 0644); err != nil {
		return err
	}

	// Also disable plugin in settings.json
	return disablePluginInSettings(key)
}

func savePluginInfo(editor, version, location string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	metadataDir := filepath.Join(home, ".polaris")
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return err
	}

	metadataFile := filepath.Join(metadataDir, "plugins.json")

	// Load existing metadata
	var plugins []pluginInfo
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
		plugins = append(plugins, pluginInfo{
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

func getInstalledPlugins() ([]pluginInfo, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	metadataFile := filepath.Join(home, ".polaris", "plugins.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []pluginInfo{}, nil
		}
		return nil, err
	}

	var plugins []pluginInfo
	if err := json.Unmarshal(data, &plugins); err != nil {
		return nil, err
	}

	return plugins, nil
}

func removePluginFromMetadata(editor, metadataFile string) error {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return err
	}

	var plugins []pluginInfo
	if err := json.Unmarshal(data, &plugins); err != nil {
		return err
	}

	// Filter out the removed plugin
	var updated []pluginInfo
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

func printPostInstallInstructions(editor, location string) {
	fmt.Printf("\n✓ Polaris skills installed for %s\n\n", editor)

	switch editor {
	case "claude":
		fmt.Println("To use the plugin:")
		fmt.Println("  1. Add to your settings.json:")
		fmt.Printf("     \"enabledPlugins\": [\"polaris@%s\"]\n\n", location)
		fmt.Println("  2. Or start Claude Code with:")
		fmt.Printf("     claude --plugin-dir %s\n\n", location)
		fmt.Println("Available commands:")
		fmt.Println("  /polaris:detect-risks     - Scan for reliability risks")
		fmt.Println("  /polaris:analyze-risks    - Analyze detected risks")
		fmt.Println("  /polaris:remediate-risks  - Generate remediation plans")
	case "codex":
		fmt.Printf("Skills installed to: %s\n\n", location)
		fmt.Println("Skills are auto-discovered by Codex CLI.")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	case "gemini":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills are auto-discovered by Gemini CLI.")
		fmt.Println("Subagents enabled via experimental.enableAgents in ~/.gemini/settings.json")
		fmt.Println("\nNote: Subagents are experimental and run in YOLO mode (no per-tool confirmation).")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	case "cursor":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills and agents are auto-discovered by Cursor.")
		fmt.Println("Use /detect-risks or ask naturally.")
	case "windsurf":
		fmt.Printf("Skills installed to: %s\n\n", location)
		fmt.Println("Skills are auto-discovered by Windsurf.")
		fmt.Println("Use @detect-risks or ask Cascade naturally.")
	case "copilot":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills and agents are auto-discovered by Copilot CLI.")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	case "augment":
		fmt.Printf("Skills and agents installed to: %s\n\n", location)
		fmt.Println("Skills and agents are auto-discovered by Augment CLI.")
		fmt.Println("Try: \"scan this codebase for reliability risks\"")
	}
}

// printInitSummary prints the final summary after initialization
func printInitSummary(cfg *ProjectConfig, pluginInstalled bool, pluginVersion string, credentialsConfigured bool, agentsMdAction string) {
	fmt.Println("Polaris initialized!")
	fmt.Println()

	componentNames := make([]string, len(cfg.Components))
	for i, c := range cfg.Components {
		componentNames[i] = c.Name
	}

	fmt.Printf("  Config:      .polaris.yaml (project: %s, %d components)\n", cfg.Project, len(cfg.Components))
	if len(componentNames) > 0 {
		fmt.Printf("               [%s]\n", strings.Join(componentNames, ", "))
	}

	if pluginInstalled {
		fmt.Printf("  Plugin:      Installed (v%s)\n", pluginVersion)
	} else {
		fmt.Println("  Plugin:      Not installed")
	}

	switch agentsMdAction {
	case "created":
		fmt.Println("  AGENTS.md:   Created")
	case "appended":
		fmt.Println("  AGENTS.md:   Updated (Polaris sections appended)")
	case "updated":
		fmt.Println("  AGENTS.md:   Updated (Polaris sections refreshed)")
	case "skipped":
		fmt.Println("  AGENTS.md:   Skipped")
	default:
		fmt.Println("  AGENTS.md:   Not configured")
	}

	if credentialsConfigured {
		fmt.Println("  Credentials: Configured")
	} else {
		fmt.Println("  Credentials: Not configured")
	}

	fmt.Println()
	fmt.Println("Next steps:")
	if !credentialsConfigured {
		fmt.Println("  polaris login               Set up API credentials")
	}
	if !pluginInstalled {
		fmt.Println("  polaris plugin install <editor>  Install skills (claude, codex, gemini, cursor, windsurf, copilot, augment)")
	}
	fmt.Println("  polaris status              Check API connection")
	fmt.Println("  /polaris:detect-risks       Run first risk scan")
	fmt.Println("  /polaris:sre-context        Load reliability context")
}

// polarisAgentsMarker is used to detect existing Polaris content in AGENTS.md
const polarisAgentsMarker = "<!-- polaris-agents-start -->"
const polarisAgentsEndMarker = "<!-- polaris-agents-end -->"

// polarisAgentsContent is the Polaris-specific content appended to AGENTS.md
const polarisAgentsContent = `
<!-- polaris-agents-start -->
## Polaris Reliability Analysis

This project uses **Polaris** for reliability risk analysis. Use ` + "`/polaris:*`" + ` skills during development.

### Polaris Quick Reference

` + "```bash" + `
# Reliability analysis
/polaris:detect-risks <service>    # Scan for risks and persist findings
/polaris:risk-check <service>      # Quick risk assessment
/polaris:risk-guidance R-XXX       # Remediation guidance for a specific risk
/polaris:control-guidance RC-XXX   # Implementation guidance for a control
/polaris:submit-evidence RC-XXX    # Submit evidence after implementing a control
/polaris:reliability-review        # Review code changes for reliability
polaris risk show R-XXX            # See which controls map to a risk
polaris knowledge search <query>   # Search organizational knowledge base
polaris evidence list              # List evidence records
` + "```" + `

### Session Close-Out (Risks)

When ending a work session where reliability risks were addressed:

1. **Submit evidence** for each control you implemented:
   ` + "```bash" + `
   polaris evidence submit --control=RC-XXX --type=code --name="description" --url="file or PR URL"
   ` + "```" + `

2. **Resolve risks** that were fully addressed:
   ` + "```bash" + `
   polaris risk resolve R-XXX --reason="Implemented <brief description>"
   ` + "```" + `

3. **Scan for regressions** if significant code changed:
   ` + "```bash" + `
   /polaris:detect-risks <service>
   ` + "```" + `

### Polaris Skills Reference

| Skill | Purpose |
| ----- | ------- |
| ` + "`/polaris:detect-risks <service>`" + ` | Full codebase scan, persists risks to register |
| ` + "`/polaris:risk-check <service>`" + ` | Quick assessment without persisting |
| ` + "`/polaris:risk-guidance R-XXX`" + ` | Remediation guidance for a specific risk |
| ` + "`/polaris:control-guidance RC-XXX`" + ` | Implement a specific control |
| ` + "`/polaris:submit-evidence RC-XXX`" + ` | Submit evidence after implementing a control |
| ` + "`/polaris:reliability-review`" + ` | Review git diff for reliability issues |
| ` + "`/polaris:incident-patterns <query>`" + ` | Search historical incident patterns |
| ` + "`/polaris:sre-context`" + ` | Load full reliability context for session |
| ` + "`polaris risk show R-XXX`" + ` | See which controls (RC-XXX) map to a risk |
| ` + "`polaris knowledge search <query>`" + ` | Search knowledge base |
<!-- polaris-agents-end -->
`

// ensureAgentsMd appends Polaris-specific sections to the repo's AGENTS.md file.
// If the file doesn't exist, it creates it. If Polaris content already exists
// (detected by marker comment), it replaces the existing Polaris section.
func ensureAgentsMd(gitRoot string, force, yesAll bool) (action string, err error) {
	agentsPath := filepath.Join(gitRoot, "AGENTS.md")

	existing, readErr := os.ReadFile(agentsPath)
	fileExists := readErr == nil

	if fileExists {
		content := string(existing)
		// Check if Polaris content already exists
		if strings.Contains(content, polarisAgentsMarker) {
			if !force {
				fmt.Println("AGENTS.md already contains Polaris sections.")
				if !yesAll {
					var update bool
					err := huh.NewConfirm().
						Title("Update Polaris sections in AGENTS.md?").
						Affirmative("Yes").
						Negative("No").
						Value(&update).
						Run()
					if err != nil || !update {
						return "skipped", nil
					}
				} else {
					fmt.Println("Updating Polaris sections (--yes mode)")
				}
			}
			// Replace existing Polaris section
			startIdx := strings.Index(content, polarisAgentsMarker)
			endIdx := strings.Index(content, polarisAgentsEndMarker)
			if startIdx >= 0 && endIdx >= 0 {
				endIdx += len(polarisAgentsEndMarker)
				// Consume trailing newline if present
				if endIdx < len(content) && content[endIdx] == '\n' {
					endIdx++
				}
				newContent := content[:startIdx] + strings.TrimLeft(polarisAgentsContent, "\n") + content[endIdx:]
				if err := os.WriteFile(agentsPath, []byte(newContent), 0644); err != nil {
					return "", fmt.Errorf("writing AGENTS.md: %w", err)
				}
				return "updated", nil
			}
		}

		// File exists but no Polaris content — append
		if !yesAll {
			var doAppend bool
			err := huh.NewConfirm().
				Title("Append Polaris sections to existing AGENTS.md?").
				Affirmative("Yes").
				Negative("No").
				Value(&doAppend).
				Run()
			if err != nil || !doAppend {
				return "skipped", nil
			}
		}

		// Ensure file ends with newline before appending
		if len(content) > 0 && content[len(content)-1] != '\n' {
			content += "\n"
		}
		newContent := content + polarisAgentsContent
		if err := os.WriteFile(agentsPath, []byte(newContent), 0644); err != nil {
			return "", fmt.Errorf("writing AGENTS.md: %w", err)
		}
		return "appended", nil
	}

	// File doesn't exist — create with Polaris content
	header := "# Agent Instructions\n" + polarisAgentsContent
	if err := os.WriteFile(agentsPath, []byte(header), 0644); err != nil {
		return "", fmt.Errorf("creating AGENTS.md: %w", err)
	}
	return "created", nil
}

// wrapText wraps text to a specified width with optional indent
func wrapText(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	currentLine := words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= width-len(indent) {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)

	return strings.Join(lines, "\n"+indent)
}
