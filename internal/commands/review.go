package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/display"
	"github.com/revelara-ai/rvl-cli/internal/project"
)

// ReviewRequest represents the payload sent to the review endpoint
type ReviewRequest struct {
	Project      string            `json:"project"`
	Service      string            `json:"service"`
	CommitSHA    string            `json:"commit_sha"`
	ChangedFiles []string          `json:"changed_files"`
	Environment  string            `json:"environment,omitempty"`
	Emergency    *EmergencyOverride `json:"emergency,omitempty"`
}

// EmergencyOverride represents an emergency override tag from commit message
type EmergencyOverride struct {
	Active bool   `json:"active"`
	Reason string `json:"reason"`
}

// ReviewResponse represents the response from the review endpoint
type ReviewResponse struct {
	Decision       string         `json:"decision"` // "pass" or "hold"
	Message        string         `json:"message,omitempty"`
	BlockingRisks  []ReviewRisk   `json:"blocking_risks,omitempty"`
	RiskSummary    *RiskSummary   `json:"risk_summary,omitempty"`
	DeepLink       string         `json:"deep_link,omitempty"`
	EmergencyUsed  bool           `json:"emergency_used,omitempty"`
	EmergencyNote  string         `json:"emergency_note,omitempty"`
}

// ReviewRisk represents a risk in the review response
type ReviewRisk struct {
	RiskCode    string `json:"risk_code"`
	Title       string `json:"title"`
	Score       int    `json:"score"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
}

// RiskSummary provides aggregate risk statistics
type RiskSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// CmdReview handles the review command
func CmdReview(args []string) {
	var commitSHA, baseRef, environment, format, projectName string
	var enforce, failClosed, verbose bool

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--commit":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --commit requires a value")
				os.Exit(1)
			}
			i++
			commitSHA = args[i]
		case strings.HasPrefix(args[i], "--commit="):
			commitSHA = strings.TrimPrefix(args[i], "--commit=")
		case args[i] == "--base":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --base requires a value")
				os.Exit(1)
			}
			i++
			baseRef = args[i]
		case strings.HasPrefix(args[i], "--base="):
			baseRef = strings.TrimPrefix(args[i], "--base=")
		case args[i] == "--env":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --env requires a value")
				os.Exit(1)
			}
			i++
			environment = args[i]
		case strings.HasPrefix(args[i], "--env="):
			environment = strings.TrimPrefix(args[i], "--env=")
		case args[i] == "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --format requires a value")
				os.Exit(1)
			}
			i++
			format = args[i]
		case strings.HasPrefix(args[i], "--format="):
			format = strings.TrimPrefix(args[i], "--format=")
		case args[i] == "--project":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --project requires a value")
				os.Exit(1)
			}
			i++
			projectName = args[i]
		case strings.HasPrefix(args[i], "--project="):
			projectName = strings.TrimPrefix(args[i], "--project=")
		case args[i] == "--enforce":
			enforce = true
		case args[i] == "--fail-closed":
			failClosed = true
		case args[i] == "--verbose":
			verbose = true
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
			printReviewUsage()
			os.Exit(1)
		}
	}

	// Defaults
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(os.Stderr, "Error: --format must be text or json\n")
		os.Exit(1)
	}

	// Auto-detect base ref from CI environment if not specified
	if baseRef == "" {
		baseRef = detectBaseRef()
	}
	if baseRef == "" {
		baseRef = "origin/main"
	}

	// Auto-detect environment from CI if not specified
	if environment == "" {
		environment = detectEnvironment()
	}

	// Resolve commit SHA (default to HEAD)
	if commitSHA == "" {
		commitSHA = "HEAD"
	}
	resolvedSHA := resolveCommitSHA(commitSHA)
	if resolvedSHA == "" {
		fmt.Fprintf(os.Stderr, "Error: could not resolve commit %s\n", commitSHA)
		os.Exit(1)
	}

	// Get changed files
	changedFiles := getChangedFiles(baseRef, resolvedSHA)
	if len(changedFiles) == 0 && verbose {
		fmt.Fprintf(os.Stderr, "Warning: no changed files detected between %s and %s\n", baseRef, resolvedSHA)
	}

	// Load project config
	if projectName == "" {
		if cfg := project.LoadProjectConfig(); cfg != nil && cfg.Project != "" {
			projectName = cfg.Project
		} else {
			// Auto-detect from git root
			gitRoot := project.DetectGitRoot()
			if gitRoot != "" {
				projectName = project.DetectProjectName(gitRoot)
			}
		}
	}
	if projectName == "" {
		fmt.Fprintln(os.Stderr, "Error: could not determine project name. Use --project or create .revelara.yaml")
		os.Exit(1)
	}

	// Parse emergency override from commit message
	var emergency *EmergencyOverride
	commitMsg := getCommitMessage(resolvedSHA)
	if tag := parseEmergencyTag(commitMsg); tag != nil {
		emergency = tag
	}

	// Build review request
	req := ReviewRequest{
		Project:      projectName,
		Service:      projectName, // Service defaults to project
		CommitSHA:    resolvedSHA,
		ChangedFiles: changedFiles,
		Environment:  environment,
		Emergency:    emergency,
	}

	// Load config and make API request
	cfg := api.LoadAndResolveConfig()
	endpoint := cfg.APIURL + "/api/v1/review"

	body, err := json.Marshal(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not marshal request: %v\n", err)
		os.Exit(1)
	}

	respBody, err := api.MakeAPIRequest(cfg, "POST", endpoint, body)
	if err != nil {
		// API unreachable
		if verbose {
			fmt.Fprintf(os.Stderr, "Error: API request failed: %v\n", err)
		}
		if failClosed {
			fmt.Fprintf(os.Stderr, "Review FAILED: API unreachable (fail-closed mode)\n")
			os.Exit(1)
		}
		// Fail open (default)
		if format == "json" {
			failOpenJSON := map[string]interface{}{
				"decision": "pass",
				"message":  "API unreachable (fail-open mode)",
				"error":    err.Error(),
			}
			jsonBytes, _ := json.MarshalIndent(failOpenJSON, "", "  ")
			fmt.Println(string(jsonBytes))
		} else {
			fmt.Println("Review PASS: API unreachable (fail-open mode)")
		}
		os.Exit(0)
	}

	var resp ReviewResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not parse response: %v\n", err)
		os.Exit(1)
	}

	// Render output
	if format == "json" {
		fmt.Println(string(respBody))
	} else {
		renderTextOutput(resp, verbose)
	}

	// Append to GitHub Actions step summary if available
	if ghSummary := os.Getenv("GITHUB_STEP_SUMMARY"); ghSummary != "" {
		appendGitHubSummary(ghSummary, resp)
	}

	// Exit code logic
	if enforce && resp.Decision == "hold" {
		os.Exit(1)
	}
	os.Exit(0)
}

func printReviewUsage() {
	fmt.Println(`Usage: rvl review [options]

Flags:
  --commit <sha>         Commit to review (default: HEAD)
  --base <ref>           Base ref for diff (auto-detect from CI, fallback: origin/main)
  --env <environment>    Environment name (auto-detect from CI)
  --format <text|json>   Output format (default: text)
  --enforce              Exit 1 on hold (default: advisory mode, always exit 0)
  --fail-closed          Exit 1 if API unreachable (default: fail open)
  --verbose              Show full details
  --project <name>       Project name (auto-resolved from .revelara.yaml or git)

Examples:
  rvl review
  rvl review --commit abc123 --env production --enforce
  rvl review --format json`)
}

// detectBaseRef attempts to detect the base ref from CI environment variables
func detectBaseRef() string {
	// GitHub Actions
	if base := os.Getenv("GITHUB_BASE_REF"); base != "" {
		return "origin/" + base
	}

	// CircleCI
	if base := os.Getenv("CIRCLE_BRANCH"); base != "" {
		return "origin/" + base
	}

	// GitLab CI
	if base := os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_SHA"); base != "" {
		return base
	}

	return ""
}

// detectEnvironment attempts to detect the environment from CI variables
func detectEnvironment() string {
	// GitHub Actions
	if ref := os.Getenv("GITHUB_REF"); ref != "" {
		// Extract environment from ref (e.g., refs/heads/production -> production)
		parts := strings.Split(ref, "/")
		if len(parts) > 2 {
			return parts[len(parts)-1]
		}
	}

	// CircleCI
	if stage := os.Getenv("CIRCLE_STAGE"); stage != "" {
		return stage
	}

	// GitLab CI
	if env := os.Getenv("CI_ENVIRONMENT_NAME"); env != "" {
		return env
	}

	return ""
}

// resolveCommitSHA resolves a commit ref to a full SHA
func resolveCommitSHA(ref string) string {
	cmd := exec.Command("git", "rev-parse", ref)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getChangedFiles returns the list of changed files between base and commit
func getChangedFiles(base, commit string) []string {
	cmd := exec.Command("git", "diff", "--name-only", base, commit)
	out, err := cmd.Output()
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var files []string
	for _, line := range lines {
		if line != "" {
			files = append(files, line)
		}
	}
	return files
}

// getCommitMessage returns the commit message for a given SHA
func getCommitMessage(sha string) string {
	cmd := exec.Command("git", "log", "-1", "--format=%B", sha)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// parseEmergencyTag extracts [emergency: reason] from a commit message
func parseEmergencyTag(message string) *EmergencyOverride {
	re := regexp.MustCompile(`\[emergency:\s*([^\]]+)\]`)
	matches := re.FindStringSubmatch(message)
	if len(matches) >= 2 {
		return &EmergencyOverride{
			Active: true,
			Reason: strings.TrimSpace(matches[1]),
		}
	}
	return nil
}

// renderTextOutput renders the review response in text format
func renderTextOutput(resp ReviewResponse, verbose bool) {
	if resp.Decision == "pass" {
		if resp.EmergencyUsed {
			// Yellow box for emergency override
			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Println("║ ⚠ Review PASS (Emergency Override)                          ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
			if resp.EmergencyNote != "" {
				fmt.Println()
				fmt.Println("Emergency Note:")
				fmt.Println(display.WrapText(resp.EmergencyNote, 80, "  "))
			}
		} else {
			// Green box for normal pass
			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Println("║ ✓ Review PASS                                                ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		}
		if resp.Message != "" {
			fmt.Println()
			fmt.Println(resp.Message)
		}
	} else {
		// Red box for hold
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║ ✗ Review HOLD                                                ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		if resp.Message != "" {
			fmt.Println()
			fmt.Println(resp.Message)
		}

		if len(resp.BlockingRisks) > 0 {
			fmt.Println()
			fmt.Println("Blocking Risks:")
			fmt.Println(strings.Repeat("-", 80))
			for _, risk := range resp.BlockingRisks {
				priority := classifyPriority(risk.Score)
				cat := display.FormatCategory(risk.Category)
				fmt.Printf("  [%s] %s (Score: %d, %s)\n", risk.RiskCode, risk.Title, risk.Score, priority)
				fmt.Printf("    Category: %s\n", cat)
				if verbose && risk.Description != "" {
					wrapped := display.WrapText(risk.Description, 76, "    ")
					fmt.Printf("    %s\n", wrapped)
				}
				fmt.Println()
			}
		}

		fmt.Println()
		fmt.Println("To override in an emergency, add to your commit message:")
		fmt.Println("  [emergency: reason for override]")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  git commit --amend -m \"Fix critical prod bug [emergency: customer-impacting outage]\"")
	}

	// Risk summary
	if resp.RiskSummary != nil && resp.RiskSummary.Total > 0 {
		fmt.Println()
		fmt.Println("Risk Summary:")
		fmt.Printf("  Total: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
			resp.RiskSummary.Total, resp.RiskSummary.Critical, resp.RiskSummary.High,
			resp.RiskSummary.Medium, resp.RiskSummary.Low)
	}

	// Deep link
	if resp.DeepLink != "" {
		fmt.Println()
		fmt.Printf("View details: %s\n", resp.DeepLink)
	}
}

// appendGitHubSummary appends markdown summary to GitHub Actions step summary
func appendGitHubSummary(summaryFile string, resp ReviewResponse) {
	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	var buf bytes.Buffer
	buf.WriteString("\n## Reliability Review\n\n")

	if resp.Decision == "pass" {
		if resp.EmergencyUsed {
			buf.WriteString("⚠️ **PASS (Emergency Override)**\n\n")
			if resp.EmergencyNote != "" {
				buf.WriteString("**Emergency Note:** " + resp.EmergencyNote + "\n\n")
			}
		} else {
			buf.WriteString("✅ **PASS**\n\n")
		}
		if resp.Message != "" {
			buf.WriteString(resp.Message + "\n\n")
		}
	} else {
		buf.WriteString("❌ **HOLD**\n\n")
		if resp.Message != "" {
			buf.WriteString(resp.Message + "\n\n")
		}

		if len(resp.BlockingRisks) > 0 {
			buf.WriteString("### Blocking Risks\n\n")
			for _, risk := range resp.BlockingRisks {
				priority := classifyPriority(risk.Score)
				buf.WriteString(fmt.Sprintf("- **[%s]** %s (Score: %d, %s)\n", risk.RiskCode, risk.Title, risk.Score, priority))
				if risk.Description != "" {
					buf.WriteString(fmt.Sprintf("  - %s\n", risk.Description))
				}
			}
			buf.WriteString("\n")
		}

		buf.WriteString("**To override in an emergency:**\n")
		buf.WriteString("```\n")
		buf.WriteString("git commit --amend -m \"Fix critical bug [emergency: reason]\"\n")
		buf.WriteString("```\n\n")
	}

	if resp.RiskSummary != nil && resp.RiskSummary.Total > 0 {
		buf.WriteString("### Risk Summary\n\n")
		buf.WriteString(fmt.Sprintf("Total: %d | Critical: %d | High: %d | Medium: %d | Low: %d\n\n",
			resp.RiskSummary.Total, resp.RiskSummary.Critical, resp.RiskSummary.High,
			resp.RiskSummary.Medium, resp.RiskSummary.Low))
	}

	if resp.DeepLink != "" {
		buf.WriteString(fmt.Sprintf("[View Full Report](%s)\n", resp.DeepLink))
	}

	f.Write(buf.Bytes())
}
