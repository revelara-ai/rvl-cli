package commands

import (
	"fmt"
	"os"

	"github.com/relynce/rely-cli/internal/config"
)

// CmdConfig handles config subcommands (show, set)
func CmdConfig(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl config <show|set>")
		os.Exit(1)
	}
	switch args[0] {
	case "show":
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if cfg == nil {
			fmt.Println("No configuration found. Run 'rvl login' first.")
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
			fmt.Fprintln(os.Stderr, "Usage: rvl config set <key> <value>")
			os.Exit(1)
		}
		key, value := args[1], args[2]
		cfg, _ := config.LoadConfig()
		if cfg == nil {
			cfg = &config.Config{APIURL: config.DefaultAPIURL}
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
		if err := config.SaveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Set %s = %s\n", key, value)
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", args[0])
		os.Exit(1)
	}
}
