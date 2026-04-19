package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/display"
)

// CmdSTPAListUCAs is exported for the main dispatcher.
// CmdSTPA dispatches STPA subcommands.
func CmdSTPA(args []string) {
	if len(args) == 0 {
		printSTPAUsage()
		os.Exit(1)
	}
	subcmd := args[0]
	switch subcmd {
	case "list-ucas":
		cmdSTPAListUCAs(args[1:])
	case "help", "--help", "-h":
		printSTPAUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown stpa command: %s\n", subcmd)
		printSTPAUsage()
		os.Exit(1)
	}
}

func printSTPAUsage() {
	fmt.Println(`rvl stpa - STPA safety analysis tools

Usage:
  rvl stpa <subcommand> [options]

Subcommands:
  list-ucas         List unsafe control actions identified by STPA analysis

List-UCAs Options:
  --source=<src>        Filter by source (scan, design_review, cast, manual)
  --uca-type=<type>     Filter by UCA type (not_provided, providing_incorrectly, wrong_timing, wrong_duration)
  --control-code=<code> Filter by control code (e.g., RC-018)
  --limit=<n>           Maximum results (default 50)

Examples:
  rvl stpa list-ucas
  rvl stpa list-ucas --source=design_review
  rvl stpa list-ucas --uca-type=not_provided --limit=20
  rvl stpa list-ucas --control-code=RC-018`)
}

// ucaListItem matches the API response structure from GET /api/v1/ucas.
type ucaListItem struct {
	ID               string   `json:"id"`
	Content          string   `json:"content"`
	UCAType          string   `json:"uca_type"`
	Source           string   `json:"source"`
	ControlCode      string   `json:"control_code,omitempty"`
	DetectionCount   int      `json:"detection_count"`
	Confidence       float64  `json:"confidence"`
	ValidationStatus string   `json:"validation_status"`
	CausalFactors    []string `json:"causal_factors"`
}

type ucaListResponse struct {
	UCAs []ucaListItem `json:"ucas"`
}

func cmdSTPAListUCAs(args []string) {
	var source, ucaType, controlCode string
	limit := 50

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--source="):
			source = strings.TrimPrefix(arg, "--source=")
		case strings.HasPrefix(arg, "--uca-type="):
			ucaType = strings.TrimPrefix(arg, "--uca-type=")
		case strings.HasPrefix(arg, "--control-code="):
			controlCode = strings.TrimPrefix(arg, "--control-code=")
		case strings.HasPrefix(arg, "--limit="):
			fmt.Sscanf(strings.TrimPrefix(arg, "--limit="), "%d", &limit)
		}
	}

	cfg := api.LoadAndResolveConfig()

	// Build query string
	params := []string{fmt.Sprintf("limit=%d", limit)}
	if source != "" {
		params = append(params, "source="+source)
	}
	if ucaType != "" {
		params = append(params, "type="+ucaType)
	}

	url := cfg.APIURL + "/api/v1/ucas?" + strings.Join(params, "&")

	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var listResp ucaListResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// Filter by control code client-side (API returns control_code in response)
	if controlCode != "" {
		var filtered []ucaListItem
		for _, u := range listResp.UCAs {
			if strings.EqualFold(u.ControlCode, controlCode) {
				filtered = append(filtered, u)
			}
		}
		listResp.UCAs = filtered
	}

	if len(listResp.UCAs) == 0 {
		fmt.Println("No UCAs found.")
		return
	}

	fmt.Printf("Found %d UCAs:\n\n", len(listResp.UCAs))
	fmt.Printf("%-8s %-20s %-15s %-10s %-5s %s\n",
		"ID", "UCA TYPE", "SOURCE", "CONTROL", "COUNT", "CONTENT")
	fmt.Println(strings.Repeat("-", 100))

	for _, u := range listResp.UCAs {
		shortID := u.ID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		ucaTypeFmt := display.FormatUCAType(u.UCAType)
		sourceFmt := display.FormatCategory(u.Source)
		controlFmt := u.ControlCode
		if controlFmt == "" {
			controlFmt = "-"
		}

		content := u.Content
		if len(content) > 40 {
			content = content[:37] + "..."
		}

		fmt.Printf("%-8s %-20s %-15s %-10s %-5d %s\n",
			shortID, ucaTypeFmt, sourceFmt, controlFmt, u.DetectionCount, content)
	}
}
