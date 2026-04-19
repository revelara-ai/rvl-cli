package commands

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
	"github.com/relynce/rely-cli/internal/project"
)

// ScanRequest represents the payload sent to the scan endpoint
type ScanRequest struct {
	Service      string        `json:"service"`
	ScanType     string        `json:"scan_type"`
	ScanMode     string        `json:"scan_mode,omitempty"`
	Findings     []interface{} `json:"findings"`
	Metadata     ScanMetadata  `json:"metadata,omitempty"`

	// Service catalog data (optional, populated by detect-risks scans)
	Stack        *ScanStackInfo   `json:"stack,omitempty"`
	Components   []ScanComponent  `json:"components,omitempty"`
	Dependencies []ScanDependency `json:"dependencies,omitempty"`
	CatalogMeta         *ScanCatalogMeta `json:"catalog_meta,omitempty"`
	BusinessCriticality *float64         `json:"business_criticality,omitempty"`
}

// ScanMetadata contains metadata about the scan
type ScanMetadata struct {
	GitCommit string `json:"git_commit,omitempty"`
	GitBranch string `json:"git_branch,omitempty"`
	ScannerID string `json:"scanner_id,omitempty"`
}

// ScanStackInfo holds detected technology stack information.
type ScanStackInfo struct {
	Languages      []string `json:"languages,omitempty"`
	Frameworks     []string `json:"frameworks,omitempty"`
	Databases      []string `json:"databases,omitempty"`
	Infrastructure []string `json:"infrastructure,omitempty"`
	CloudProvider  string   `json:"cloud_provider,omitempty"`
}

// ScanComponent represents a service component from .revelara.yaml or auto-detection.
type ScanComponent struct {
	Name         string   `json:"name"`
	Path         string   `json:"path,omitempty"`
	Type         string   `json:"type,omitempty"`
	Description  string   `json:"description,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// ScanDependency represents an auto-detected dependency.
type ScanDependency struct {
	Target      string `json:"target"`
	Type        string `json:"type,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
}

// ScanCatalogMeta holds optional manual overrides from .revelara.yaml.
type ScanCatalogMeta struct {
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Tier        string `json:"tier,omitempty"`
	TeamName    string `json:"team_name,omitempty"`
	TeamContact string `json:"team_contact,omitempty"`
}

// ScanResponse represents the response from the scan endpoint
type ScanResponse struct {
	ScanID           string                      `json:"scan_id"`
	Service          string                      `json:"service"`
	Summary          ScanSummary                 `json:"summary"`
	Findings         []ScanResult                `json:"findings"`
	ControlStructure *ScanControlStructureResult  `json:"control_structure,omitempty"`
	Warnings         []string                    `json:"warnings,omitempty"`
	Timestamp        string                      `json:"timestamp"`
}

// ScanControlStructureResult is the control structure portion of a scan response.
type ScanControlStructureResult struct {
	SnapshotID   string           `json:"snapshot_id"`
	NodeCount    int              `json:"node_count"`
	EdgeCount    int              `json:"edge_count"`
	ScannedFiles int              `json:"scanned_files"`
	ScannedLines int64            `json:"scanned_lines"`
	UCACoverage  *ScanUCACoverage `json:"uca_coverage,omitempty"`
}

// ScanUCACoverage reports UCA identification results during a scan.
type ScanUCACoverage struct {
	Discovered    int `json:"discovered"`
	Analyzed      int `json:"analyzed"`
	Cap           int `json:"cap"`
	UCAsGenerated int `json:"ucas_generated"`
	UCAsStored    int `json:"ucas_stored"`
}

// ScanSummary provides aggregate statistics about the scan results
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

// ScanResult represents a single risk finding from the scan
type ScanResult struct {
	RiskID   string   `json:"risk_id"`
	RiskCode string   `json:"risk_code"`
	Title    string   `json:"title"`
	Status   string   `json:"status"`
	Score    int      `json:"score"`
	Priority string   `json:"priority"`
	Warnings []string `json:"warnings,omitempty"`
}

// CmdScan handles the scan command
func CmdScan(args []string, version string) {
	var service string
	var inputFile string
	var useStdin bool
	var dryRun bool
	var targetDir string
	var reviewMode bool
	var autoInfer bool
	var ciMode bool

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
		case "--review":
			reviewMode = true
		case "--auto-infer":
			autoInfer = true
		case "--ci":
			ciMode = true
		default:
			if strings.HasPrefix(args[i], "--target=") {
				targetDir = strings.TrimPrefix(args[i], "--target=")
			} else if !strings.HasPrefix(args[i], "-") && service == "" {
				service = args[i]
			}
		}
	}

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

	if targetDir != "" {
		if projectCfg := project.LoadProjectConfigFrom(targetDir); projectCfg != nil && projectCfg.Project != "" {
			if service != "" && service != projectCfg.Project {
				fmt.Fprintf(os.Stderr, "Warning: --service %q overridden by target's .revelara.yaml project: %q\n", service, projectCfg.Project)
			}
			service = projectCfg.Project
		}
	}

	if service == "" {
		fmt.Fprintln(os.Stderr, "Error: --service is required (or use --target with a project that has .revelara.yaml)")
		fmt.Fprintln(os.Stderr, "Usage: rvl scan --service <name> [--stdin|--file <path>] [--target <path>] [--dry-run]")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

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

	var scanReq ScanRequest
	if err := json.Unmarshal(inputData, &scanReq); err != nil {
		var findings []interface{}
		if err2 := json.Unmarshal(inputData, &findings); err2 != nil {
			fmt.Fprintf(os.Stderr, "Error parsing input: %v\n", err)
			os.Exit(1)
		}
		scanReq.Findings = findings
	}

	scanReq.Service = service
	if scanReq.ScanType == "" {
		scanReq.ScanType = "full"
	}
	scanReq.Metadata.ScannerID = "rely-cli-" + version

	if projectCfg := project.LoadProjectConfigFrom(targetDir); projectCfg != nil {
		if len(projectCfg.Components) > 0 {
			project.MapFindingsToComponents(scanReq.Findings, projectCfg)
		}
		if crit := projectCfg.CriticalityScore(); crit > 0 {
			scanReq.BusinessCriticality = &crit
		}
	}

	// Resolve scan mode: --ci > --auto-infer > --review > default (review if TTY)
	scanMode := "review" // default
	if ciMode {
		scanMode = "ci"
	} else if autoInfer {
		scanMode = "auto"
	} else if reviewMode {
		scanMode = "review"
	} else if !isTTY() {
		// No TTY and no explicit flag: fall back to auto (non-interactive)
		scanMode = "auto"
	}

	// Review mode requires a TTY for interactive confirmation
	if scanMode == "review" && useStdin {
		fmt.Fprintln(os.Stderr, "Warning: --review requires a TTY for confirmation. Falling back to --auto-infer because stdin is used for input.")
		scanMode = "auto"
	}

	scanReq.ScanMode = scanMode

	if dryRun {
		fmt.Printf("Dry run - would submit to %s:\n", cfg.APIURL)
		fmt.Printf("  Service: %s\n", scanReq.Service)
		fmt.Printf("  Mode: %s\n", scanMode)
		if targetDir != "" {
			fmt.Printf("  Target: %s\n", targetDir)
		}
		fmt.Printf("  Findings: %d\n", len(scanReq.Findings))
		fmt.Printf("  Scan Type: %s\n", scanReq.ScanType)
		return
	}

	response, err := submitScan(cfg, &scanReq)
	if err != nil {
		if scanMode == "ci" {
			ciError := map[string]any{"error": err.Error(), "service": service}
			jsonOut, _ := json.Marshal(ciError)
			fmt.Println(string(jsonOut))
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// CI mode: output JSON and exit with code based on severity
	if scanMode == "ci" {
		printCIOutput(response)
		return
	}

	// Review mode: show control structure and ask for confirmation
	if scanMode == "review" && response.ControlStructure != nil {
		printControlStructureReview(response.ControlStructure)
		if !promptConfirmation("Accept this control structure and proceed with results?") {
			fmt.Println("Scan results discarded. Use --auto-infer to skip review.")
			return
		}
		fmt.Println()
	}

	// Standard output (review-confirmed or auto mode)
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

	if cs := response.ControlStructure; cs != nil {
		fmt.Printf("  Control Structure: %d nodes, %d edges (%d files scanned)\n",
			cs.NodeCount, cs.EdgeCount, cs.ScannedFiles)
		if uca := cs.UCACoverage; uca != nil {
			fmt.Printf("  STPA Coverage: %d/%d control actions analyzed",
				uca.Analyzed, uca.Discovered)
			if uca.Cap > 0 && uca.Discovered > uca.Cap {
				fmt.Printf(" (capped at %d)", uca.Cap)
			}
			fmt.Printf(" | %d UCAs identified\n", uca.UCAsGenerated)
		}
	}
	fmt.Println()

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

	if len(response.Warnings) > 0 {
		fmt.Fprintf(os.Stderr, "Warnings:\n")
		for _, w := range response.Warnings {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Printf("View results: %s/risks\n", cfg.APIURL)
}

// isTTY returns true if stdout is a terminal (not piped or redirected).
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// printControlStructureReview displays the control structure for interactive review.
func printControlStructureReview(cs *ScanControlStructureResult) {
	fmt.Println("\nControl Structure (Review Mode)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Nodes: %d | Edges: %d\n", cs.NodeCount, cs.EdgeCount)
	fmt.Printf("  Files scanned: %d | Lines scanned: %d\n", cs.ScannedFiles, cs.ScannedLines)
	if uca := cs.UCACoverage; uca != nil {
		fmt.Printf("  Control actions: %d discovered, %d analyzed (cap: %d)\n",
			uca.Discovered, uca.Analyzed, uca.Cap)
		fmt.Printf("  UCAs identified: %d (%d stored)\n", uca.UCAsGenerated, uca.UCAsStored)
	}
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

// promptConfirmation asks a yes/no question and returns the answer.
func promptConfirmation(question string) bool {
	fmt.Printf("%s [Y/n] ", question)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return true // default to yes on read error
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "" || answer == "y" || answer == "yes"
}

// printCIOutput outputs scan results as JSON for CI/CD pipelines.
// Exit codes: 0 = success (no critical/high), 1 = findings with critical/high severity.
func printCIOutput(response *ScanResponse) {
	out, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling CI output: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))

	if response.Summary.Critical > 0 || response.Summary.High > 0 {
		os.Exit(1)
	}
}

// submitScan sends the scan request to the API and returns the response
func submitScan(cfg *config.Config, scanReq *ScanRequest) (*ScanResponse, error) {
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
	if cfg.ResolvedOrgID != "" {
		req.Header.Set("X-Organization-ID", cfg.ResolvedOrgID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed - run 'rvl login' to reconfigure")
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
