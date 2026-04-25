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
	case "submit":
		cmdSTPASubmit(args[1:])
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
  submit            Submit STPA findings from a design review JSON file
  list-ucas         List unsafe control actions identified by STPA analysis

Submit Options:
  --file=<path>         Path to STPA design review JSON output (required)
  --service=<name>      Service name for scoping (optional)

List-UCAs Options:
  --source=<src>        Filter by source (scan, design_review, cast, manual)
  --uca-type=<type>     Filter by UCA type (not_provided, providing_incorrectly, wrong_timing, wrong_duration)
  --control-code=<code> Filter by control code (e.g., RC-018)
  --limit=<n>           Maximum results (default 50)

Examples:
  rvl stpa submit --file=stpa-findings.json
  rvl stpa submit --file=stpa-findings.json --service=payment-api
  rvl stpa list-ucas
  rvl stpa list-ucas --source=design_review
  rvl stpa list-ucas --uca-type=not_provided --limit=20
  rvl stpa list-ucas --control-code=RC-018`)
}

// -- Submit types --

// stpaFindings is the input JSON format produced by the STPA design review skill.
type stpaFindings struct {
	Losses        []stpaLoss         `json:"losses"`
	Findings      []stpaFinding      `json:"findings"`
	LossScenarios []stpaLossScenario `json:"loss_scenarios"`
}

type stpaLoss struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

type stpaFinding struct {
	Content              string   `json:"content"`
	UCAType              string   `json:"uca_type"`
	CausalFactors        []string `json:"causal_factors"`
	LossScenario         string   `json:"loss_scenario"`
	CanonicalForm        string   `json:"canonical_form"`
	Confidence           float64  `json:"confidence"`
	ControlCode          string   `json:"control_code"`
	LossTitle            string   `json:"loss_title"`
	LossCategory         string   `json:"loss_category"`
	EstimatedComplexity  string   `json:"estimated_fix_complexity"`
	ConstraintType       string   `json:"constraint_type"`
}

type stpaLossScenario struct {
	Title        string              `json:"title"`
	Description  string              `json:"description"`
	Level        string              `json:"level"`
	ParentTitle  string              `json:"parent_title"`
	UCARefs      []int               `json:"uca_refs"`
	ControlLinks []stpaControlLink   `json:"control_links"`
}

type stpaControlLink struct {
	ControlCode  string `json:"control_code"`
	Relationship string `json:"relationship"`
}

func cmdSTPASubmit(args []string) {
	var filePath, service string
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--file="):
			filePath = strings.TrimPrefix(arg, "--file=")
		case strings.HasPrefix(arg, "--service="):
			service = strings.TrimPrefix(arg, "--service=")
		}
	}
	if filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --file is required")
		fmt.Fprintln(os.Stderr, "Usage: rvl stpa submit --file=<path>")
		os.Exit(1)
	}
	_ = service // reserved for future repo scoping

	// Read and parse input
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	var findings stpaFindings
	if err := json.Unmarshal(data, &findings); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	var stats submitStats

	// 1. Loss definitions (dedup by title)
	if len(findings.Losses) > 0 {
		submitLossDefinitions(cfg, findings.Losses, &stats)
	}

	// 2. UCAs
	ucaIDs := make(map[int]string) // findings index -> created UCA ID
	if len(findings.Findings) > 0 {
		submitUCAs(cfg, findings.Findings, ucaIDs, &stats)
	}

	// 3. Loss scenarios (top-down by level)
	if len(findings.LossScenarios) > 0 {
		submitLossScenarios(cfg, findings.LossScenarios, ucaIDs, &stats)
	}

	// Summary
	fmt.Println()
	fmt.Printf("Submitted: %d loss definitions (%d new), %d UCAs (%d new), %d loss scenarios\n",
		stats.lossDefsTotal, stats.lossDefsNew,
		stats.ucasTotal, stats.ucasNew,
		stats.scenariosCreated)
	if stats.ucaLinks > 0 || stats.controlLinks > 0 {
		fmt.Printf("Linked: %d UCA associations, %d control associations\n",
			stats.ucaLinks, stats.controlLinks)
	}
	if stats.errors > 0 {
		fmt.Fprintf(os.Stderr, "Warnings: %d items failed (see above)\n", stats.errors)
	}
}

type submitStats struct {
	lossDefsTotal    int
	lossDefsNew      int
	ucasTotal        int
	ucasNew          int
	scenariosCreated int
	ucaLinks         int
	controlLinks     int
	errors           int
}

func submitLossDefinitions(cfg *config.Config, losses []stpaLoss, stats *submitStats) {
	fmt.Println("Submitting loss definitions...")

	// Fetch existing to dedup by title
	existing := make(map[string]bool)
	resp, err := api.MakeAPIRequest(cfg, "GET", cfg.APIURL+"/api/v1/loss-definitions", nil)
	if err == nil {
		var listResp struct {
			LossDefinitions []struct {
				Title string `json:"title"`
			} `json:"loss_definitions"`
		}
		if json.Unmarshal(resp, &listResp) == nil {
			for _, ld := range listResp.LossDefinitions {
				existing[strings.ToLower(ld.Title)] = true
			}
		}
	}

	for _, loss := range losses {
		stats.lossDefsTotal++
		if existing[strings.ToLower(loss.Title)] {
			fmt.Printf("  [skip] %s (already exists)\n", loss.Title)
			continue
		}

		body, _ := json.Marshal(map[string]string{
			"title":       loss.Title,
			"description": loss.Description,
			"category":    loss.Category,
		})
		_, err := api.MakeAPIRequest(cfg, "POST", cfg.APIURL+"/api/v1/loss-definitions", body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [error] %s: %v\n", loss.Title, err)
			stats.errors++
			continue
		}
		fmt.Printf("  [created] %s\n", loss.Title)
		stats.lossDefsNew++
	}
}

func submitUCAs(cfg *config.Config, ucaFindings []stpaFinding, ucaIDs map[int]string, stats *submitStats) {
	fmt.Println("Submitting UCAs...")

	for i, f := range ucaFindings {
		stats.ucasTotal++

		reqBody := map[string]any{
			"content":        f.Content,
			"uca_type":       f.UCAType,
			"causal_factors": f.CausalFactors,
			"loss_scenario":  f.LossScenario,
			"canonical_form": f.CanonicalForm,
			"confidence":     f.Confidence,
			"source":         "design_review",
		}
		if f.ControlCode != "" {
			reqBody["control_code"] = f.ControlCode
		}

		body, _ := json.Marshal(reqBody)
		resp, err := api.MakeAPIRequest(cfg, "POST", cfg.APIURL+"/api/v1/ucas", body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [error] UCA %d: %v\n", i, err)
			stats.errors++
			continue
		}

		var ucaResp struct {
			UCA struct {
				ID string `json:"id"`
			} `json:"uca"`
			IsNew bool `json:"is_new"`
		}
		if err := json.Unmarshal(resp, &ucaResp); err != nil {
			fmt.Fprintf(os.Stderr, "  [error] UCA %d parse: %v\n", i, err)
			stats.errors++
			continue
		}

		ucaIDs[i] = ucaResp.UCA.ID

		content := f.Content
		if len(content) > 50 {
			content = content[:47] + "..."
		}
		if ucaResp.IsNew {
			fmt.Printf("  [created] %s\n", content)
			stats.ucasNew++
		} else {
			fmt.Printf("  [exists]  %s (detection count bumped)\n", content)
		}
	}
}

func submitLossScenarios(cfg *config.Config, scenarios []stpaLossScenario, ucaIDs map[int]string, stats *submitStats) {
	fmt.Println("Submitting loss scenarios...")

	// Sort: top_level first, then intermediate, then immediate
	levelOrder := map[string]int{"top_level": 0, "intermediate": 1, "immediate": 2}
	sorted := make([]stpaLossScenario, len(scenarios))
	copy(sorted, scenarios)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if levelOrder[sorted[i].Level] > levelOrder[sorted[j].Level] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Track title -> created ID for parent resolution
	titleToID := make(map[string]string)

	for _, sc := range sorted {
		reqBody := map[string]any{
			"title":       sc.Title,
			"description": sc.Description,
			"level":       sc.Level,
		}

		// Resolve parent by title
		if sc.ParentTitle != "" {
			parentID, ok := titleToID[sc.ParentTitle]
			if !ok {
				fmt.Fprintf(os.Stderr, "  [warn] parent %q not found for %q, creating without parent\n",
					sc.ParentTitle, sc.Title)
			} else {
				reqBody["parent_id"] = parentID
			}
		}

		body, _ := json.Marshal(reqBody)
		resp, err := api.MakeAPIRequest(cfg, "POST", cfg.APIURL+"/api/v1/loss-scenarios", body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [error] %s: %v\n", sc.Title, err)
			stats.errors++
			continue
		}

		var lsResp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(resp, &lsResp); err != nil {
			fmt.Fprintf(os.Stderr, "  [error] %s parse: %v\n", sc.Title, err)
			stats.errors++
			continue
		}

		titleToID[sc.Title] = lsResp.ID
		stats.scenariosCreated++
		fmt.Printf("  [created] [%s] %s\n", sc.Level, sc.Title)

		// Link UCAs
		for _, ref := range sc.UCARefs {
			ucaID, ok := ucaIDs[ref]
			if !ok {
				fmt.Fprintf(os.Stderr, "    [warn] UCA ref %d not found, skipping link\n", ref)
				continue
			}
			linkBody, _ := json.Marshal(map[string]string{"uca_id": ucaID})
			_, err := api.MakeAPIRequest(cfg, "POST",
				cfg.APIURL+"/api/v1/loss-scenarios/"+lsResp.ID+"/ucas", linkBody)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    [warn] link UCA %d: %v\n", ref, err)
				continue
			}
			stats.ucaLinks++
		}

		// Link controls
		for _, cl := range sc.ControlLinks {
			controlID, err := FindControlIDByCode(cfg, cl.ControlCode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    [warn] resolve %s: %v\n", cl.ControlCode, err)
				continue
			}
			linkBody, _ := json.Marshal(map[string]string{
				"control_id":   controlID,
				"relationship": cl.Relationship,
			})
			_, err = api.MakeAPIRequest(cfg, "POST",
				cfg.APIURL+"/api/v1/loss-scenarios/"+lsResp.ID+"/controls", linkBody)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    [warn] link control %s: %v\n", cl.ControlCode, err)
				continue
			}
			stats.controlLinks++
		}
	}
}

// -- List UCAs --

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
