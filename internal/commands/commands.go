package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/relynce/rely-cli/internal/api"
	"github.com/relynce/rely-cli/internal/config"
)

// SkillsResponse matches the API response for GET /api/v1/skills
type SkillsResponse struct {
	Version string  `json:"version"`
	Skills  []Skill `json:"skills"`
}

// Skill represents a single skill from the API
type Skill struct {
	Name     string `json:"name"`
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Checksum string `json:"checksum"`
}

// AgentsResponse matches the API response for GET /api/v1/agents
type AgentsResponse struct {
	Version string  `json:"version"`
	Agents  []Agent `json:"agents"`
}

// Agent represents a single agent from the API
type Agent struct {
	Name     string `json:"name"`
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Checksum string `json:"checksum"`
}

// CmdCommands lists available skills and agents from the API
func CmdCommands(args []string) {
	cfg := api.LoadAndResolveConfig()

	showSkills := true
	showAgents := true
	for _, arg := range args {
		switch arg {
		case "--skills":
			showAgents = false
		case "--agents":
			showSkills = false
		case "help", "--help", "-h":
			printCommandsUsage()
			return
		}
	}

	if showSkills {
		printSkills(cfg)
	}
	if showAgents {
		if showSkills {
			fmt.Println()
		}
		printAgents(cfg)
	}
}

func printSkills(cfg *config.Config) {
	url := cfg.APIURL + "/api/v1/skills"
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching skills: %v\n", err)
		os.Exit(1)
	}

	var skillsResp SkillsResponse
	if err := json.Unmarshal(resp, &skillsResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing skills: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Skills (v%s):\n", skillsResp.Version)
	if len(skillsResp.Skills) == 0 {
		fmt.Println("  (none)")
		return
	}

	for _, s := range skillsResp.Skills {
		desc := extractSkillDescription(s.Content)
		fmt.Printf("  /rely:%-22s %s\n", s.Name, desc)
	}
}

func printAgents(cfg *config.Config) {
	url := cfg.APIURL + "/api/v1/agents"
	resp, err := api.MakeAPIRequest(cfg, "GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching agents: %v\n", err)
		os.Exit(1)
	}

	var agentsResp AgentsResponse
	if err := json.Unmarshal(resp, &agentsResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing agents: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Agents (v%s):\n", agentsResp.Version)
	if len(agentsResp.Agents) == 0 {
		fmt.Println("  (none)")
		return
	}

	for _, a := range agentsResp.Agents {
		desc := extractAgentDescription(a.Content)
		fmt.Printf("  rely:%-23s %s\n", a.Name, desc)
	}
}

// extractSkillDescription pulls the first non-heading, non-empty line from skill markdown.
func extractSkillDescription(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 80 {
			return line[:77] + "..."
		}
		return line
	}
	return ""
}

// extractAgentDescription pulls the description from YAML frontmatter.
func extractAgentDescription(content string) string {
	if !strings.HasPrefix(content, "---") {
		return extractSkillDescription(content)
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			break
		}
		if strings.HasPrefix(line, "description:") {
			desc := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			if len(desc) > 80 {
				return desc[:77] + "..."
			}
			return desc
		}
	}
	return ""
}

func printCommandsUsage() {
	fmt.Println(`rely commands - List available skills and agents

Usage:
  rely commands [options]

Options:
  --skills    Show only skills
  --agents    Show only agents

Examples:
  rely commands
  rely commands --skills`)
}
