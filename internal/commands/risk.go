package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
	"github.com/relynce/rely-cli/internal/display"
)

// Risk represents a risk in the system
type Risk struct {
	ID           string   `json:"id"`
	RiskCode     string   `json:"risk_code"`
	Title        string   `json:"title"`
	Category     string   `json:"category"`
	Score        int      `json:"score"`
	Status       string   `json:"status"`
	Services     []string `json:"linked_services"`
	ControlCodes []string `json:"control_codes,omitempty"`
	StaleSince    string   `json:"stale_since,omitempty"`
	LastSeenAt    string   `json:"last_seen_at,omitempty"`
	ResolvedAt    string   `json:"resolved_at,omitempty"`
	UCAType       string   `json:"uca_type,omitempty"`
	CausalFactors []string `json:"causal_factors,omitempty"`
	LossScenario  string   `json:"loss_scenario,omitempty"`
}

// RiskDetail represents detailed risk information
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

// ListRisksResponse represents the response from listing risks
type ListRisksResponse struct {
	Risks []Risk `json:"risks"`
	Total int    `json:"total"`
}

// RiskContextResponse represents the full context for a risk
type RiskContextResponse struct {
	Risk           RiskDetail           `json:"risk"`
	Controls       []ControlContextItem `json:"controls"`
	Knowledge      KnowledgeContextResp `json:"knowledge"`
	ServiceContext *ServiceContextResp  `json:"service_context,omitempty"`
	ScoreBreakdown []ScoreFactorResp    `json:"score_breakdown,omitempty"`
}

// ControlContextItem represents a control with its context
type ControlContextItem struct {
	Control          MappedControl         `json:"control"`
	ExistingEvidence []ContextEvidenceItem `json:"existing_evidence"`
	EvidenceGaps     []string              `json:"evidence_gaps"`
}

// ContextEvidenceItem represents evidence in a context
type ContextEvidenceItem struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	URL         string `json:"url_or_identifier,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
}

// KnowledgeContextResp represents knowledge context
type KnowledgeContextResp struct {
	Patterns   []PatternItem   `json:"patterns"`
	Procedures []ProcedureItem `json:"procedures"`
	Facts      []FactItem      `json:"facts"`
}

// PatternItem represents a pattern in knowledge context
type PatternItem struct {
	Title                string      `json:"title"`
	PatternType          string      `json:"pattern_type"`
	CausalChain          []ChainLink `json:"causal_chain,omitempty"`
	TriggerEvent         string      `json:"trigger_event,omitempty"`
	OccurrenceCount      int         `json:"occurrence_count"`
	TypicalMTTR          string      `json:"typical_mttr,omitempty"`
	TypicalBlastRadius   string      `json:"typical_blast_radius,omitempty"`
	PreventionStrategies []string    `json:"prevention_strategies,omitempty"`
	Score                float64     `json:"score"`
}

// ChainLink represents a link in a causal chain
type ChainLink struct {
	Order        int    `json:"order"`
	Event        string `json:"event"`
	TypicalDelay string `json:"typical_delay,omitempty"`
}

// ProcedureItem represents a procedure in knowledge context
type ProcedureItem struct {
	Title              string   `json:"title"`
	EffectivenessScore float64  `json:"effectiveness_score"`
	AppliedCount       int      `json:"applied_count"`
	SuccessCount       int      `json:"success_count"`
	RelatedControls    []string `json:"related_controls,omitempty"`
	Score              float64  `json:"score"`
}

// FactItem represents a fact in knowledge context
type FactItem struct {
	Content          string  `json:"content"`
	Confidence       float64 `json:"confidence"`
	ValidationStatus string  `json:"validation_status"`
	Score            float64 `json:"score"`
}

// ServiceContextResp represents service context
type ServiceContextResp struct {
	ServiceName string               `json:"service_name"`
	Tier        string               `json:"tier,omitempty"`
	Incidents   *IncidentHistoryResp `json:"incidents,omitempty"`
}

// IncidentHistoryResp represents incident history for a service
type IncidentHistoryResp struct {
	TotalIncidents  int    `json:"total_incidents"`
	Last30Days      int    `json:"last_30_days"`
	Last90Days      int    `json:"last_90_days"`
	CriticalCount   int    `json:"critical_count"`
	HighCount       int    `json:"high_count"`
	MostRecentTitle string `json:"most_recent_title,omitempty"`
	AverageMTTR     *int   `json:"average_mttr,omitempty"`
}

// ScoreFactorResp represents a factor contributing to a risk score
type ScoreFactorResp struct {
	Description string `json:"description"`
	Points      int    `json:"points"`
	Source      string `json:"source"`
}

// CmdRisk is the main dispatcher for risk commands
func CmdRisk(args []string) {
	if len(args) == 0 {
		printRiskUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		CmdRiskList(args[1:])
	case "show":
		CmdRiskShow(args[1:])
	case "context":
		CmdRiskContext(args[1:])
	case "stale":
		CmdRiskStale(args[1:])
	case "resolve":
		CmdRiskResolve(args[1:])
	case "accept":
		CmdRiskAccept(args[1:])
	case "ready":
		CmdRiskReady(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown risk command: %s\n", args[0])
		printRiskUsage()
		os.Exit(1)
	}
}

func printRiskUsage() {
	fmt.Println(`Usage: rvl risk <command> [options]

Commands:
  list                    List all risks in the register
  ready                   Top unresolved risks ranked by score (highest value first)
  show <risk-code>        Show detailed information about a specific risk
  context <risk-code>     Show full context (controls, knowledge, service history)
  stale                   List risks marked as stale
  resolve <risk-code>     Mark a risk as resolved
  accept <risk-code>      Accept a risk (intentional decision to retain)

Options:
  --org-id <id>          Override organization ID
  --format <json|table>  Output format (default: table)
  --status <status>      Filter by status (for list command)
  --category <category>  Filter by category (for list/ready commands)
  --service <name>       Filter by linked service (for list/ready commands)
  --limit <n>            Number of results (for ready command, default: 10)

Examples:
  rvl risk list
  rvl risk list --status detected --service polaris
  rvl risk ready
  rvl risk ready --limit 20 --category change_management
  rvl risk show R-001
  rvl risk context R-001
  rvl risk resolve R-001`)
}

// CmdRiskList lists all risks in the register
func CmdRiskList(args []string) {
	cfg := api.LoadAndResolveConfig()

	var statusFilter, categoryFilter, serviceFilter, format string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--status":
			if i+1 < len(args) {
				statusFilter = args[i+1]
				i++
			}
		case "--category":
			if i+1 < len(args) {
				categoryFilter = args[i+1]
				i++
			}
		case "--service":
			if i+1 < len(args) {
				serviceFilter = args[i+1]
				i++
			}
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		}
	}

	endpoint := cfg.APIURL + "/api/v1/risks"
	queryParams := []string{"limit=1000"}
	if statusFilter != "" {
		queryParams = append(queryParams, fmt.Sprintf("status=%s", statusFilter))
	}
	if categoryFilter != "" {
		queryParams = append(queryParams, fmt.Sprintf("category=%s", categoryFilter))
	}
	if serviceFilter != "" {
		queryParams = append(queryParams, fmt.Sprintf("service=%s", serviceFilter))
	}
	endpoint += "?" + strings.Join(queryParams, "&")

	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risks: %v\n", err)
		os.Exit(1)
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		fmt.Println(string(body))
		return
	}

	if len(resp.Risks) == 0 {
		fmt.Println("No risks found.")
		return
	}

	fmt.Printf("Total Risks: %d\n\n", resp.Total)
	fmt.Printf("%-10s %-12s %-8s %-20s %-50s\n", "CODE", "STATUS", "SCORE", "CATEGORY", "TITLE")
	fmt.Println(strings.Repeat("-", 110))

	for _, r := range resp.Risks {
		statusStr := display.FormatStatus(r.Status)
		title := r.Title
		if len(title) > 47 {
			title = title[:47] + "..."
		}
		fmt.Printf("%-10s %-12s %-8d %-20s %-50s\n",
			r.RiskCode, statusStr, r.Score, r.Category, title)
	}
}

// CmdRiskReady shows the top unresolved risks ranked by score (highest value first).
// "Ready" means the risk has status "detected" (the only open status)
// and is sorted by score descending so the highest-impact items surface first.
func CmdRiskReady(args []string) {
	cfg := api.LoadAndResolveConfig()

	var categoryFilter, serviceFilter, format string
	limit := 10
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--category":
			if i+1 < len(args) {
				categoryFilter = args[i+1]
				i++
			}
		case "--service":
			if i+1 < len(args) {
				serviceFilter = args[i+1]
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				if n := parseInt(args[i+1]); n > 0 {
					limit = n
				}
				i++
			}
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		}
	}

	// Fetch risks sorted by score descending
	endpoint := cfg.APIURL + "/api/v1/risks"
	queryParams := []string{"limit=1000", "sort_by=score", "sort_order=desc"}
	if categoryFilter != "" {
		queryParams = append(queryParams, fmt.Sprintf("category=%s", categoryFilter))
	}
	if serviceFilter != "" {
		queryParams = append(queryParams, fmt.Sprintf("service=%s", serviceFilter))
	}
	endpoint += "?" + strings.Join(queryParams, "&")

	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risks: %v\n", err)
		os.Exit(1)
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// Filter to open statuses only (detected)
	var ready []Risk
	for _, r := range resp.Risks {
		if r.Status == "detected" {
			ready = append(ready, r)
		}
	}

	if format == "json" {
		out := ready
		if len(out) > limit {
			out = out[:limit]
		}
		jsonBytes, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(jsonBytes))
		return
	}

	if len(ready) == 0 {
		fmt.Println("No unresolved risks ready for remediation.")
		return
	}

	showing := len(ready)
	if showing > limit {
		showing = limit
	}

	fmt.Printf("Ready Risks: showing top %d of %d unresolved\n\n", showing, len(ready))
	fmt.Printf("%-6s %-10s %-5s %-14s %-18s %s\n",
		"#", "CODE", "SCORE", "PRIORITY", "CATEGORY", "TITLE")
	fmt.Println(strings.Repeat("-", 100))

	for i, r := range ready {
		if i >= limit {
			break
		}
		priority := classifyPriority(r.Score)
		title := r.Title
		if len(title) > 42 {
			title = title[:42] + "..."
		}
		cat := display.FormatCategory(r.Category)
		if len(cat) > 18 {
			cat = cat[:18]
		}
		fmt.Printf("%-6d %-10s %-5d %-14s %-18s %s\n",
			i+1, r.RiskCode, r.Score, priority, cat, title)
	}

	if len(ready) > limit {
		fmt.Printf("\n  ... %d more unresolved risks (use --limit to see more)\n", len(ready)-limit)
	}
}

func classifyPriority(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return 0
		}
	}
	return n
}

// CmdRiskShow shows detailed information about a specific risk
func CmdRiskShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk show <risk-code>")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	riskCode := args[0]
	riskID, err := FindRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding risk: %v\n", err)
		os.Exit(1)
	}

	endpoint := cfg.APIURL + "/api/v1/risks/" + riskID
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risk: %v\n", err)
		os.Exit(1)
	}

	var risk RiskDetail
	if err := json.Unmarshal(body, &risk); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nRisk: %s\n", risk.RiskCode)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Title:    %s\n", risk.Title)
	fmt.Printf("Status:   %s\n", display.FormatStatus(risk.Status))
	fmt.Printf("Category: %s\n", risk.Category)
	fmt.Printf("Score:    %d\n", risk.Score)

	if len(risk.Services) > 0 {
		fmt.Printf("Services: %s\n", strings.Join(risk.Services, ", "))
	}

	if risk.LastSeenAt != "" {
		fmt.Printf("Last Seen: %s\n", risk.LastSeenAt)
	}
	if risk.StaleSince != "" {
		fmt.Printf("Stale Since: %s\n", risk.StaleSince)
	}
	if risk.ResolvedAt != "" {
		fmt.Printf("Resolved At: %s\n", risk.ResolvedAt)
	}

	// Prefer structured STPA fields from API JSON; fall back to narrative parsing
	hasStructuredSTPA := risk.UCAType != "" || len(risk.CausalFactors) > 0 || risk.LossScenario != ""
	if hasStructuredSTPA {
		fmt.Println("\nSTPA Causal Analysis:")
		fmt.Println(strings.Repeat("-", 80))
		if risk.UCAType != "" {
			fmt.Printf("  Unsafe Control Action: %s", display.FormatUCAType(risk.UCAType))
			if cat := display.FormatUCACategory(risk.UCAType); cat != "" {
				fmt.Printf("  (%s)", cat)
			}
			fmt.Println()
		}
		if risk.LossScenario != "" {
			fmt.Printf("  Loss Scenario: %s\n", risk.LossScenario)
		}
		if len(risk.CausalFactors) > 0 {
			fmt.Println("  Causal Factors:")
			for _, f := range risk.CausalFactors {
				wrapped := display.WrapText(f, 74, "      ")
				fmt.Printf("    > %s\n", wrapped)
			}
		}
	}

	if risk.Narrative != "" {
		// Strip STPA markers from narrative if we already showed structured fields
		narrativeText := risk.Narrative
		if hasStructuredSTPA {
			if stpa := display.ParseSTPAContext(risk.Narrative); stpa != nil && stpa.CleanNarrative != "" {
				narrativeText = stpa.CleanNarrative
			}
		}
		fmt.Println("\nNarrative:")
		fmt.Println(strings.Repeat("-", 80))
		wrapped := display.WrapText(narrativeText, 80, "")
		fmt.Println(wrapped)
	}

	if len(risk.MappedControls) > 0 {
		fmt.Println("\nMapped Controls:")
		fmt.Println(strings.Repeat("-", 80))
		for _, ctrl := range risk.MappedControls {
			fmt.Printf("  [%s] %s\n", ctrl.ControlCode, ctrl.Name)
			fmt.Printf("    Category: %s | Type: %s\n", ctrl.Category, display.FormatControlType(ctrl.Type))
			if ctrl.Description != "" {
				wrapped := display.WrapText(ctrl.Description, 76, "")
				lines := strings.Split(wrapped, "\n")
				for _, line := range lines {
					fmt.Printf("    %s\n", line)
				}
			}
			fmt.Println()
		}
	}
}

// CmdRiskContext shows full context for a risk
func CmdRiskContext(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk context <risk-code>")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	riskCode := args[0]
	riskID, err := FindRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding risk: %v\n", err)
		os.Exit(1)
	}

	endpoint := cfg.APIURL + "/api/v1/risks/" + riskID + "/context"
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching risk context: %v\n", err)
		os.Exit(1)
	}

	var ctx RiskContextResponse
	if err := json.Unmarshal(body, &ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	printRiskContext(ctx)
}

func printRiskContext(ctx RiskContextResponse) {
	fmt.Printf("\nRisk Context: %s\n", ctx.Risk.RiskCode)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Title:    %s\n", ctx.Risk.Title)
	fmt.Printf("Status:   %s\n", display.FormatStatus(ctx.Risk.Status))
	fmt.Printf("Category: %s\n", ctx.Risk.Category)
	fmt.Printf("Score:    %d\n", ctx.Risk.Score)

	// Prefer structured STPA fields from API JSON; fall back to narrative parsing
	hasStructuredSTPA := ctx.Risk.UCAType != "" || len(ctx.Risk.CausalFactors) > 0 || ctx.Risk.LossScenario != ""
	if hasStructuredSTPA {
		fmt.Println("\nSTPA Causal Analysis:")
		fmt.Println(strings.Repeat("-", 80))
		if ctx.Risk.UCAType != "" {
			fmt.Printf("  Unsafe Control Action: %s", display.FormatUCAType(ctx.Risk.UCAType))
			if cat := display.FormatUCACategory(ctx.Risk.UCAType); cat != "" {
				fmt.Printf("  (%s)", cat)
			}
			fmt.Println()
		}
		if ctx.Risk.LossScenario != "" {
			fmt.Printf("  Loss Scenario: %s\n", ctx.Risk.LossScenario)
		}
		if len(ctx.Risk.CausalFactors) > 0 {
			fmt.Println("  Causal Factors:")
			for _, f := range ctx.Risk.CausalFactors {
				wrapped := display.WrapText(f, 74, "      ")
				fmt.Printf("    > %s\n", wrapped)
			}
		}
	} else if stpa := display.ParseSTPAContext(ctx.Risk.Narrative); stpa != nil {
		fmt.Println("\nSTPA Causal Analysis:")
		fmt.Println(strings.Repeat("-", 80))
		if stpa.UCAType != "" {
			fmt.Printf("  Unsafe Control Action: %s", display.FormatUCAType(stpa.UCAType))
			if cat := display.FormatUCACategory(stpa.UCAType); cat != "" {
				fmt.Printf("  (%s)", cat)
			}
			fmt.Println()
		}
		if stpa.LossScenario != "" {
			fmt.Printf("  Loss Scenario: %s\n", stpa.LossScenario)
		}
		if len(stpa.CausalFactors) > 0 {
			fmt.Println("  Causal Factors:")
			for _, f := range stpa.CausalFactors {
				wrapped := display.WrapText(f, 74, "      ")
				fmt.Printf("    > %s\n", wrapped)
			}
		}
	}

	if len(ctx.ScoreBreakdown) > 0 {
		fmt.Println("\nScore Breakdown:")
		fmt.Println(strings.Repeat("-", 80))
		for _, factor := range ctx.ScoreBreakdown {
			fmt.Printf("  [%+3d] %s (Source: %s)\n", factor.Points, factor.Description, factor.Source)
		}
	}

	if ctx.ServiceContext != nil {
		fmt.Println("\nService Context:")
		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("Service: %s", ctx.ServiceContext.ServiceName)
		if ctx.ServiceContext.Tier != "" {
			fmt.Printf(" (Tier: %s)", ctx.ServiceContext.Tier)
		}
		fmt.Println()

		if ctx.ServiceContext.Incidents != nil {
			inc := ctx.ServiceContext.Incidents
			fmt.Printf("  Incidents: %d total (%d in last 30d, %d in last 90d)\n",
				inc.TotalIncidents, inc.Last30Days, inc.Last90Days)
			fmt.Printf("  Severity: %d critical, %d high\n", inc.CriticalCount, inc.HighCount)
			if inc.AverageMTTR != nil {
				fmt.Printf("  Average MTTR: %d minutes\n", *inc.AverageMTTR)
			}
			if inc.MostRecentTitle != "" {
				fmt.Printf("  Most Recent: %s\n", inc.MostRecentTitle)
			}
		}
	}

	if len(ctx.Controls) > 0 {
		fmt.Println("\nControl Coverage:")
		fmt.Println(strings.Repeat("-", 80))
		for _, ctrlCtx := range ctx.Controls {
			ctrl := ctrlCtx.Control
			fmt.Printf("\n[%s] %s\n", ctrl.ControlCode, ctrl.Name)
			fmt.Printf("  Category: %s | Type: %s\n", ctrl.Category, display.FormatControlType(ctrl.Type))

			if len(ctrlCtx.ExistingEvidence) > 0 {
				fmt.Println("  Existing Evidence:")
				for _, ev := range ctrlCtx.ExistingEvidence {
					fmt.Printf("    - [%s] %s", ev.Type, ev.Name)
					if ev.Status != "" {
						fmt.Printf(" (Status: %s)", ev.Status)
					}
					fmt.Println()
					if ev.Description != "" {
						wrapped := display.WrapText(ev.Description, 76, "")
						lines := strings.Split(wrapped, "\n")
						for _, line := range lines {
							fmt.Printf("      %s\n", line)
						}
					}
				}
			}

			if len(ctrlCtx.EvidenceGaps) > 0 {
				fmt.Println("  Evidence Gaps:")
				for _, gap := range ctrlCtx.EvidenceGaps {
					fmt.Printf("    - %s\n", gap)
				}
			}
		}
	}

	if len(ctx.Knowledge.Patterns) > 0 {
		fmt.Println("\nRelevant Incident Patterns:")
		fmt.Println(strings.Repeat("-", 80))

		patterns := ctx.Knowledge.Patterns
		sort.Slice(patterns, func(i, j int) bool {
			return patterns[i].Score > patterns[j].Score
		})

		for _, pat := range patterns {
			fmt.Printf("\n%s (Type: %s)\n", pat.Title, pat.PatternType)
			fmt.Printf("  Occurrences: %d | Relevance: %.2f\n", pat.OccurrenceCount, pat.Score)
			if pat.TypicalMTTR != "" {
				fmt.Printf("  Typical MTTR: %s\n", pat.TypicalMTTR)
			}
			if pat.TypicalBlastRadius != "" {
				fmt.Printf("  Typical Blast Radius: %s\n", pat.TypicalBlastRadius)
			}

			if len(pat.CausalChain) > 0 {
				fmt.Println("  Causal Chain:")
				sort.Slice(pat.CausalChain, func(i, j int) bool {
					return pat.CausalChain[i].Order < pat.CausalChain[j].Order
				})
				for _, link := range pat.CausalChain {
					fmt.Printf("    %d. %s", link.Order, link.Event)
					if link.TypicalDelay != "" {
						fmt.Printf(" (delay: %s)", link.TypicalDelay)
					}
					fmt.Println()
				}
			}

			if pat.TriggerEvent != "" {
				fmt.Printf("  Trigger: %s\n", pat.TriggerEvent)
			}

			if len(pat.PreventionStrategies) > 0 {
				fmt.Println("  Prevention Strategies:")
				for _, strat := range pat.PreventionStrategies {
					wrapped := display.WrapText(strat, 76, "")
					lines := strings.Split(wrapped, "\n")
					for _, line := range lines {
						fmt.Printf("    - %s\n", line)
					}
				}
			}
		}
	}

	if len(ctx.Knowledge.Procedures) > 0 {
		fmt.Println("\nRelevant Procedures:")
		fmt.Println(strings.Repeat("-", 80))

		procedures := ctx.Knowledge.Procedures
		sort.Slice(procedures, func(i, j int) bool {
			return procedures[i].Score > procedures[j].Score
		})

		for _, proc := range procedures {
			fmt.Printf("\n%s\n", proc.Title)
			fmt.Printf("  Effectiveness: %.2f | Applied: %d times (%d successful)\n",
				proc.EffectivenessScore, proc.AppliedCount, proc.SuccessCount)
			fmt.Printf("  Relevance: %.2f\n", proc.Score)
			if len(proc.RelatedControls) > 0 {
				fmt.Printf("  Related Controls: %s\n", strings.Join(proc.RelatedControls, ", "))
			}
		}
	}

	if len(ctx.Knowledge.Facts) > 0 {
		fmt.Println("\nRelevant Facts:")
		fmt.Println(strings.Repeat("-", 80))

		facts := ctx.Knowledge.Facts
		sort.Slice(facts, func(i, j int) bool {
			return facts[i].Score > facts[j].Score
		})

		for _, fact := range facts {
			wrapped := display.WrapText(fact.Content, 76, "")
			fmt.Printf("\n- %s\n", wrapped)
			fmt.Printf("  Confidence: %.2f | Validation: %s | Relevance: %.2f\n",
				fact.Confidence, fact.ValidationStatus, fact.Score)
		}
	}
}

// CmdRiskStale lists risks marked as stale
func CmdRiskStale(args []string) {
	cfg := api.LoadAndResolveConfig()

	endpoint := cfg.APIURL + "/api/v1/risks/stale"
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching stale risks: %v\n", err)
		os.Exit(1)
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(resp.Risks) == 0 {
		fmt.Println("No stale risks found.")
		return
	}

	fmt.Printf("Stale Risks: %d\n\n", len(resp.Risks))
	fmt.Printf("%-10s %-20s %-20s %-50s\n", "CODE", "CATEGORY", "STALE SINCE", "TITLE")
	fmt.Println(strings.Repeat("-", 110))

	for _, r := range resp.Risks {
		title := r.Title
		if len(title) > 47 {
			title = title[:47] + "..."
		}
		staleSince := r.StaleSince
		if staleSince == "" {
			staleSince = "N/A"
		}
		fmt.Printf("%-10s %-20s %-20s %-50s\n", r.RiskCode, r.Category, staleSince, title)
	}
}

// CmdRiskResolve marks a risk as resolved
func CmdRiskResolve(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk resolve <risk-code> [--reason \"...\"]")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	riskCode := args[0]
	reason := "Resolved"
	for i := 1; i < len(args); i++ {
		if args[i] == "--reason" && i+1 < len(args) {
			reason = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--reason=") {
			reason = strings.TrimPrefix(args[i], "--reason=")
		}
	}

	riskID, err := FindRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding risk: %v\n", err)
		os.Exit(1)
	}

	endpoint := cfg.APIURL + "/api/v1/risks/" + riskID + "/resolve"
	body, _ := json.Marshal(map[string]string{"reason": reason})
	_, err = api.MakeAPIRequest(cfg, "POST", endpoint, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving risk: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Risk %s resolved successfully.\n", riskCode)
}

// CmdRiskAccept accepts a risk (intentional decision to retain)
func CmdRiskAccept(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: rvl risk accept <risk-code> [--reason \"...\"]")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	riskCode := args[0]
	reason := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--reason" && i+1 < len(args) {
			reason = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--reason=") {
			reason = strings.TrimPrefix(args[i], "--reason=")
		}
	}

	riskID, err := FindRiskIDByCode(cfg, riskCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding risk: %v\n", err)
		os.Exit(1)
	}

	endpoint := cfg.APIURL + "/api/v1/risks/" + riskID + "/status"
	statusBody, _ := json.Marshal(map[string]string{"status": "accepted", "reason": reason})
	_, err = api.MakeAPIRequest(cfg, "PATCH", endpoint, statusBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accepting risk: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Risk %s accepted successfully.\n", riskCode)
}

// FindRiskIDByCode finds a risk ID by its risk code
func FindRiskIDByCode(cfg *config.Config, riskCode string) (string, error) {
	endpoint := cfg.APIURL + "/api/v1/risks?limit=1000"
	body, err := api.MakeAPIRequest(cfg, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	var resp ListRisksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	for _, r := range resp.Risks {
		if r.RiskCode == riskCode {
			return r.ID, nil
		}
	}

	return "", fmt.Errorf("risk not found: %s", riskCode)
}
