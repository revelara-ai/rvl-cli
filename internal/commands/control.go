package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/config"
	"github.com/revelara-ai/rvl-cli/internal/display"
)

// Control represents a reliability control from the catalog
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

// ListControlsResponse wraps the controls list response
type ListControlsResponse struct {
	Controls []Control `json:"controls"`
	Total    int       `json:"total"`
}

// CmdControl dispatches control subcommands
func CmdControl(args []string) {
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
	fmt.Println(`rvl control - Query reliability controls catalog

Usage:
  rvl control <subcommand> [options]

Subcommands:
  list              List controls in the catalog
  show              Show control details by code

List Options:
  --category=<cat>  Filter by category (fault_tolerance, monitoring, change_management, etc.)
  --limit=<n>       Maximum results (default 50)

Examples:
  rvl control list
  rvl control list --category=fault_tolerance
  rvl control show RC-018
  rvl control show RC-019`)
}

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
	cfg := api.LoadAndResolveConfig()
	url := cfg.APIURL + "/api/v1/controls?limit=" + fmt.Sprintf("%d", limit)
	if category != "" {
		url += "&category=" + category
	}
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
		typeBadge := display.FormatControlType(c.Type)
		fmt.Printf("%-8s %-14s %d/10 %-12s [%s] %s\n", c.ControlCode, typeBadge, c.Weight, display.FormatWeightTier(c.Weight), display.FormatCategory(c.Category), c.Name)
	}
}

func cmdControlShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: control code required")
		fmt.Fprintln(os.Stderr, "Usage: rvl control show <control-code>")
		os.Exit(1)
	}
	controlCode := args[0]
	if strings.HasPrefix(controlCode, "R-") && !strings.HasPrefix(controlCode, "RC-") {
		fmt.Fprintf(os.Stderr, "Note: \"%s\" is a risk code, not a control code (RC-XXX).\n", controlCode)
		fmt.Fprintf(os.Stderr, "Use \"rvl risk show %s\" to see its mapped controls.\n", controlCode)
		os.Exit(1)
	}
	cfg := api.LoadAndResolveConfig()
	url := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	var control Control
	if err := json.Unmarshal(resp, &control); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Control: %s - %s\n", control.ControlCode, control.Name)
	fmt.Printf("Category: %s\n", display.FormatCategory(control.Category))
	fmt.Printf("Type: %s\n", control.Type)
	fmt.Printf("Weight: %d/10 (%s)\n", control.Weight, display.FormatWeightTier(control.Weight))
	if control.Treatment != "" {
		fmt.Printf("Treatment: %s\n", control.Treatment)
	}
	if control.Description != "" {
		fmt.Println()
		fmt.Printf("Description:\n  %s\n", display.WrapText(control.Description, 78, "  "))
	}
	if control.Objective != "" {
		fmt.Println()
		fmt.Printf("Objective:\n  %s\n", display.WrapText(control.Objective, 78, "  "))
	}
	if control.RiskStatement != "" {
		fmt.Println()
		fmt.Printf("Risk Statement:\n  %s\n", display.WrapText(control.RiskStatement, 78, "  "))
	}
	if control.TestDescription != "" {
		fmt.Println()
		fmt.Printf("Test Description:\n  %s\n", display.WrapText(control.TestDescription, 78, "  "))
	}
	if control.Remediation != "" {
		fmt.Println()
		fmt.Printf("Remediation:\n  %s\n", display.WrapText(control.Remediation, 78, "  "))
	}
	if len(control.ExpectedEvidenceTypes) > 0 {
		fmt.Println()
		fmt.Printf("Expected Evidence: %s\n", strings.Join(control.ExpectedEvidenceTypes, ", "))
	}
	if control.Implementation != "" {
		fmt.Println()
		fmt.Printf("Implementation:\n  %s\n", display.WrapText(control.Implementation, 78, "  "))
	}
	if len(control.RiskCodes) > 0 {
		fmt.Println()
		fmt.Printf("Related Risks: %s\n", strings.Join(control.RiskCodes, ", "))
	}
}

// FindControlIDByCode looks up a control ID by its control code (e.g., "RC-018")
func FindControlIDByCode(cfg *config.Config, controlCode string) (string, error) {
	url := cfg.APIURL + "/api/v1/controls/by-code/" + controlCode
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
