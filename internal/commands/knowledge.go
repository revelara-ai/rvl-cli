package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/display"
)

// KnowledgeSearchResult represents a search result from the knowledge API
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

// ForesightImpactNode represents a single entity in an impact path.
type ForesightImpactNode struct {
	EntityType   string  `json:"entity_type"`
	EntityID     string  `json:"entity_id"`
	Label        string  `json:"label"`
	RelationType string  `json:"relation_type"`
	DelaySeconds *int    `json:"delay_seconds,omitempty"`
	Strength     float64 `json:"strength"`
	Depth        int     `json:"depth"`
}

// ForesightMitigation represents a control or procedure that mitigates a node.
type ForesightMitigation struct {
	ControlCode    string  `json:"control_code,omitempty"`
	ControlName    string  `json:"control_name,omitempty"`
	ProcedureID    string  `json:"procedure_id,omitempty"`
	ProcedureTitle string  `json:"procedure_title,omitempty"`
	EntityType     string  `json:"entity_type"`
	EntityID       string  `json:"entity_id"`
	EntityLabel    string  `json:"entity_label"`
	EdgeStrength   float64 `json:"edge_strength"`
	ForNodeID      string  `json:"for_node_id"`
}

// ForesightImpactPath represents a single causal chain from the starting entity.
type ForesightImpactPath struct {
	Chain         []ForesightImpactNode  `json:"chain"`
	TotalStrength float64                `json:"total_strength"`
	Mitigations   []ForesightMitigation  `json:"mitigations,omitempty"`
}

// ForesightMetadata contains performance and diagnostic information.
type ForesightMetadata struct {
	TraversalDepth int     `json:"traversal_depth"`
	EdgesExamined  int     `json:"edges_examined"`
	QueryTimeMs    float64 `json:"query_time_ms"`
}

// ForesightResponse contains the impact paths and metadata from a foresight query.
type ForesightResponse struct {
	ImpactPaths []ForesightImpactPath `json:"impact_paths"`
	Metadata    ForesightMetadata     `json:"metadata"`
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

// CmdKnowledge handles the knowledge command
func CmdKnowledge(args []string) {
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
	case "foresight":
		cmdKnowledgeForesight(args[1:])
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
	fmt.Println(`rvl knowledge - Query organizational knowledge base

Usage:
  rvl knowledge <subcommand> [options]

Subcommands:
  enrich              Fetch patterns, procedures, and health in one call
  search              Semantic search across all knowledge types
  graph-search        Graph-expanded semantic search (search + graph neighbors)
  facts               List or search facts
  procedures          List or search procedures (with control mappings)
  patterns            List or search failure patterns
  relationships       List relationships for a knowledge entity
  graph               Traverse the knowledge graph from an entity
  foresight           Explore causal impact chains with mitigations
  health              Show knowledge base health statistics

Enrich Options:
  --vertical=<v>      Filter by SRE vertical (default: fault-tolerance)
  --control=<RC-XXX>  Include procedures for a specific control
  --technology=<t>    Include facts for a specific technology
  --query=<q>         Include semantic search results for a query
  --limit=<n>         Maximum results per section (default 10)

Search Options:
  rvl knowledge search <query> [--limit=N]

Graph-Search Options:
  rvl knowledge graph-search <query> [--limit=N] [--depth=N] [--types=causes,mitigates]

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
  rvl knowledge relationships <entity_type> <entity_id>
  Entity types: fact, procedure, pattern, service, technology, control

Graph Options:
  rvl knowledge graph <entity_type> <entity_id> [--depth=N] [--min-strength=0.3] [--type=causes,mitigates]

Foresight Options:
  rvl knowledge foresight --entity-type=<type> --entity-id=<id> [--depth=N] [--min-strength=0.3]
                           [--include-mitigations] [--relation-types=causes,depends_on] [--format=table|json]

Examples:
  rvl knowledge enrich --vertical=fault-tolerance
  rvl knowledge enrich --control=RC-018 --query="timeout failure"
  rvl knowledge search "circuit breaker timeout patterns"
  rvl knowledge graph-search "timeout failures" --depth=2
  rvl knowledge facts --vertical=fault-tolerance --technology=go
  rvl knowledge procedures --control=RC-018
  rvl knowledge patterns --type=failure_mode --min-occurrences=3
  rvl knowledge relationships fact fact_abc12
  rvl knowledge graph fact fact_abc12 --depth=2 --type=causes,mitigates
  rvl knowledge foresight --entity-type=service --entity-id=checkout-api --include-mitigations
  rvl knowledge foresight --entity-type=pattern --entity-id=pattern_abc12 --depth=5 --format=json
  rvl knowledge health`)
}

// cmdKnowledgeSearch performs a semantic search across all knowledge types
func cmdKnowledgeSearch(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		fmt.Fprintln(os.Stderr, "Usage: rvl knowledge search <query> [--limit=N]")
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

	cfg := api.LoadAndResolveConfig()

	// POST /api/knowledge/search
	body := map[string]interface{}{
		"query": query,
		"limit": limit,
	}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/knowledge/search"
	resp, err := api.MakeAPIRequest(cfg, "POST", url, bodyBytes)
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
			title = display.TruncateText(r.Content, 80)
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

	cfg := api.LoadAndResolveConfig()

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

	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
		validBadge := display.FormatValidationStatus(f.ValidationStatus)
		content := display.TruncateText(f.Content, 80)
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

	cfg := api.LoadAndResolveConfig()

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

	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
			fmt.Printf("    %s\n", display.TruncateText(p.Description, 78))
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

	cfg := api.LoadAndResolveConfig()

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

	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
			fmt.Printf("    %s\n", display.TruncateText(p.Description, 78))
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
	cfg := api.LoadAndResolveConfig()

	url := cfg.APIURL + "/api/knowledge/health"
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
		fmt.Fprintln(os.Stderr, "Usage: rvl knowledge relationships <type> <id>")
		fmt.Fprintln(os.Stderr, "Types: fact, procedure, pattern, service, technology, control")
		os.Exit(1)
	}

	entityType := args[0]
	entityID := args[1]

	cfg := api.LoadAndResolveConfig()

	url := cfg.APIURL + "/api/knowledge/entities/" + entityType + "/" + entityID + "/relationships"
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
		fmt.Fprintln(os.Stderr, "Usage: rvl knowledge graph <type> <id> [--depth=N] [--min-strength=0.3] [--type=causes,mitigates]")
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

	cfg := api.LoadAndResolveConfig()

	url := fmt.Sprintf("%s/api/knowledge/entities/%s/%s/graph?max_depth=%d&min_strength=%s",
		cfg.APIURL, entityType, entityID, depth, minStrength)
	if relationType != "" {
		url += "&relation_type=" + relationType
	}

	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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

// cmdKnowledgeForesight explores causal impact chains with mitigations
func cmdKnowledgeForesight(args []string) {
	var entityType, entityID, format string
	var relationTypes string
	depth := 3
	minStrength := 0.3
	includeMitigations := false

	for _, arg := range args {
		if strings.HasPrefix(arg, "--entity-type=") {
			entityType = strings.TrimPrefix(arg, "--entity-type=")
		} else if strings.HasPrefix(arg, "--entity-id=") {
			entityID = strings.TrimPrefix(arg, "--entity-id=")
		} else if strings.HasPrefix(arg, "--depth=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--depth="), "%d", &depth)
		} else if strings.HasPrefix(arg, "--min-strength=") {
			fmt.Sscanf(strings.TrimPrefix(arg, "--min-strength="), "%f", &minStrength)
		} else if strings.HasPrefix(arg, "--include-mitigations") {
			includeMitigations = true
		} else if strings.HasPrefix(arg, "--relation-types=") {
			relationTypes = strings.TrimPrefix(arg, "--relation-types=")
		} else if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		}
	}

	if entityType == "" || entityID == "" {
		fmt.Fprintln(os.Stderr, "Error: --entity-type and --entity-id are required")
		fmt.Fprintln(os.Stderr, "Usage: rvl knowledge foresight --entity-type=<type> --entity-id=<id> [options]")
		fmt.Fprintln(os.Stderr, "Entity types: service, fact, procedure, pattern, technology, control, incident, risk")
		os.Exit(1)
	}

	cfg := api.LoadAndResolveConfig()

	body := map[string]interface{}{
		"entity_type":          entityType,
		"entity_id":            entityID,
		"depth":                depth,
		"min_strength":         minStrength,
		"include_mitigations":  includeMitigations,
	}
	if relationTypes != "" {
		body["relation_types"] = strings.Split(relationTypes, ",")
	}
	bodyBytes, _ := json.Marshal(body)

	url := cfg.APIURL + "/api/knowledge/foresight"
	resp, err := api.MakeAPIRequest(cfg, "POST", url, bodyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// JSON output mode
	if format == "json" {
		fmt.Println(string(resp))
		return
	}

	var foresightResp ForesightResponse
	if err := json.Unmarshal(resp, &foresightResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(foresightResp.ImpactPaths) == 0 {
		fmt.Printf("No impact paths found from %s %s\n", entityType, entityID)
		return
	}

	fmt.Printf("Foresight: %s %s (depth %d, %d edges examined, %.0fms)\n\n",
		entityType, entityID,
		foresightResp.Metadata.TraversalDepth,
		foresightResp.Metadata.EdgesExamined,
		foresightResp.Metadata.QueryTimeMs,
	)

	// Group paths by depth for table-like output
	for i, path := range foresightResp.ImpactPaths {
		for _, node := range path.Chain {
			indent := strings.Repeat("  ", node.Depth)
			delay := ""
			if node.DelaySeconds != nil {
				delay = " (" + formatForesightDelay(*node.DelaySeconds) + ")"
			}
			fmt.Printf("  %s-[%s]-> %s [%s] (strength: %.0f%%)%s\n",
				indent, node.RelationType, node.Label, node.EntityType,
				node.Strength*100, delay)
		}

		// Show mitigations for this path
		if len(path.Mitigations) > 0 {
			fmt.Printf("    Mitigations:\n")
			for _, mit := range path.Mitigations {
				label := mit.EntityLabel
				if mit.ControlCode != "" {
					label = mit.ControlCode + ": " + mit.ControlName
				} else if mit.ProcedureTitle != "" {
					label = mit.ProcedureTitle
				}
				fmt.Printf("      [%s] %s (strength: %.0f%%)\n",
					mit.EntityType, label, mit.EdgeStrength*100)
			}
		}

		if i < len(foresightResp.ImpactPaths)-1 {
			fmt.Println()
		}
	}
}

// formatForesightDelay converts seconds to human-readable delay.
func formatForesightDelay(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	return fmt.Sprintf("%dh", seconds/3600)
}

// cmdKnowledgeGraphSearch performs a graph-expanded semantic search
func cmdKnowledgeGraphSearch(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: search query required")
		fmt.Fprintln(os.Stderr, "Usage: rvl knowledge graph-search <query> [--limit=N] [--depth=N] [--types=causes,mitigates]")
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

	cfg := api.LoadAndResolveConfig()

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
	resp, err := api.MakeAPIRequest(cfg, "POST", url, bodyBytes)
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
			title = display.TruncateText(r.Content, 80)
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

	cfg := api.LoadAndResolveConfig()

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
		resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
		resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
		resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
			resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
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
			resp, err := api.MakeAPIRequest(cfg, "POST", url, bodyBytes)
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
			fmt.Printf("    %s\n", display.TruncateText(p.Description, 78))
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
			fmt.Printf("    %s\n", display.TruncateText(p.Description, 78))
		}
		if len(p.RelatedControls) > 0 {
			fmt.Printf("    Controls: %s\n", strings.Join(p.RelatedControls, ", "))
		}
	}

	// --- Facts (optional) ---
	if technology != "" {
		fmt.Printf("\n=== Facts for %s (%d) ===\n\n", technology, factsResp.Total)
		for _, f := range factsResp.Facts {
			validBadge := display.FormatValidationStatus(f.ValidationStatus)
			content := display.TruncateText(f.Content, 80)
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
				title = display.TruncateText(r.Content, 80)
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
