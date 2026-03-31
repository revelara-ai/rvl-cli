package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
	"github.com/relynce/rely-cli/internal/plugin"
	"golang.org/x/term"
)

// readAPIKeyWithEcho reads an API key with brief visual echo before masking.
// Characters are displayed as typed/pasted, then replaced with * after a short delay.
// Falls back to term.ReadPassword if raw mode is unavailable (e.g., piped input).
func readAPIKeyWithEcho(fd int) (string, error) {
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Fall back to standard hidden password input
		b, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	defer term.Restore(fd, oldState)

	var (
		key          []byte
		maskedCount  int // asterisks currently on screen
		visibleCount int // cleartext chars currently on screen
		mu           sync.Mutex
		maskTimer    *time.Timer
	)

	maskVisible := func() {
		if visibleCount > 0 {
			os.Stdout.WriteString(strings.Repeat("\b", visibleCount) + strings.Repeat("*", visibleCount))
			maskedCount += visibleCount
			visibleCount = 0
		}
	}

	scheduleMask := func() {
		if maskTimer != nil {
			maskTimer.Stop()
		}
		maskTimer = time.AfterFunc(500*time.Millisecond, func() {
			mu.Lock()
			defer mu.Unlock()
			maskVisible()
		})
	}

	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			return "", err
		}

		mu.Lock()
		b := buf[0]

		switch {
		case b == '\r' || b == '\n':
			if maskTimer != nil {
				maskTimer.Stop()
			}
			maskVisible()
			mu.Unlock()
			os.Stdout.WriteString("\r\n")
			return string(key), nil

		case b == 127 || b == 8: // Backspace / Delete
			if len(key) > 0 {
				key = key[:len(key)-1]
				os.Stdout.WriteString("\b \b")
				if visibleCount > 0 {
					visibleCount--
				} else if maskedCount > 0 {
					maskedCount--
				}
			}
			mu.Unlock()

		case b == 3: // Ctrl+C
			if maskTimer != nil {
				maskTimer.Stop()
			}
			mu.Unlock()
			os.Stdout.WriteString("\r\n")
			return "", fmt.Errorf("interrupted")

		case b >= 32 && b < 127: // Printable ASCII
			key = append(key, b)
			visibleCount++
			os.Stdout.Write([]byte{b})
			scheduleMask()
			mu.Unlock()

		default:
			mu.Unlock()
		}
	}
}

// CmdLogin handles the login command
func CmdLogin() {
	reader := bufio.NewReader(os.Stdin)
	cfg, _ := config.LoadConfig()
	if cfg == nil {
		cfg = &config.Config{}
	}
	defaultURL := cfg.APIURL
	if defaultURL == "" {
		defaultURL = "https://api-dev.relynce.ai"
	}
	fmt.Printf("Relynce API URL [%s]: ", defaultURL)
	apiURL, _ := reader.ReadString('\n')
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = defaultURL
	}
	cfg.APIURL = apiURL

	if cfg.APIKey != "" {
		if len(cfg.APIKey) > 12 {
			masked := cfg.APIKey[:8] + "..." + cfg.APIKey[len(cfg.APIKey)-4:]
			fmt.Printf("API Key [%s] (Enter to keep): ", masked)
		} else {
			fmt.Print("API Key [set] (Enter to keep): ")
		}
	} else {
		fmt.Print("API Key: ")
	}
	apiKey, err := readAPIKeyWithEcho(int(syscall.Stdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading API key: %v\n", err)
		os.Exit(1)
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey != "" {
		cfg.APIKey = apiKey
	} else if cfg.APIKey != "" {
		fmt.Println("  Keeping existing API key.")
	}
	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key is required")
		os.Exit(1)
	}

	defaultOrg := cfg.OrgName
	fmt.Printf("Organization name [%s]: ", defaultOrg)
	orgName, _ := reader.ReadString('\n')
	orgName = strings.TrimSpace(orgName)
	if orgName == "" {
		orgName = defaultOrg
	}
	cfg.OrgName = orgName

	fmt.Println("\nValidating credentials...")
	if cfg.OrgName != "" {
		if err := api.ResolveOrganizationID(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Organization resolved: %s -> %s\n", cfg.OrgName, cfg.ResolvedOrgID)
	}
	if err := api.ValidateCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := config.SaveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Configuration saved to ~/.relynce/config.yaml")
}

// CmdLogout removes stored credentials
func CmdLogout() {
	path := config.GetConfigPath()
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

// CmdStatus checks connection and auth status
// Takes version and gitHash as params since they're defined in main
func CmdStatus(version, gitHash string) {
	cfg := api.LoadAndResolveConfig()
	fmt.Printf("Relynce CLI v%s (%s)\n", version, gitHash)
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
	if err := api.ValidateCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Status: Connected")

	fmt.Println("\nPlugins:")
	serverVersion := api.FetchServerPluginVersion(cfg)
	plugins, err := plugin.GetInstalledPlugins()
	if err != nil || len(plugins) == 0 {
		fmt.Println("  No plugins installed")
		fmt.Println("  Run 'rely plugin install <editor>' to install")
		fmt.Println("  Available: claude, codex, gemini, cursor, windsurf, copilot, augment")
	} else {
		for _, p := range plugins {
			if serverVersion != "" && plugin.SemVerNewer(p.Version, serverVersion) {
				fmt.Printf("  %s: v%s (update available: v%s)\n", p.Editor, p.Version, serverVersion)
				fmt.Printf("    Run 'rely plugin update %s' to upgrade\n", p.Editor)
			} else if serverVersion != "" {
				fmt.Printf("  %s: v%s (up to date)\n", p.Editor, p.Version)
			} else {
				fmt.Printf("  %s: v%s\n", p.Editor, p.Version)
			}
		}
	}
}
