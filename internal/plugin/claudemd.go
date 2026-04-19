package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	claudeMdBlockStart    = "<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->"
	claudeMdBlockEnd      = "<!-- END REVELARA MANAGED BLOCK -->"
	claudeMdBlockStartOld = "<!-- BEGIN RELYNCE MANAGED BLOCK - DO NOT EDIT -->"
	claudeMdBlockEndOld   = "<!-- END RELYNCE MANAGED BLOCK -->"
)

// EnsureClaudeMd creates or updates the project CLAUDE.md with a managed Revelara block.
// templatePath is the path to the CLAUDE.md template from the installed plugin.
// If yesAll is true, all prompts are auto-accepted.
//
// Returns the action taken: "created", "appended", "updated", or "skipped".
func EnsureClaudeMd(gitRoot, templatePath string, yesAll bool) (string, error) {
	template, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("read CLAUDE.md template: %w", err)
	}

	managedBlock := claudeMdBlockStart + "\n" + strings.TrimSpace(string(template)) + "\n" + claudeMdBlockEnd + "\n"

	claudeMdPath := filepath.Join(gitRoot, "CLAUDE.md")
	content, err := os.ReadFile(claudeMdPath)

	if os.IsNotExist(err) {
		// No CLAUDE.md — create with just the managed block
		if err := os.WriteFile(claudeMdPath, []byte(managedBlock), 0644); err != nil {
			return "", err
		}
		return "created", nil
	}

	if err != nil {
		return "", err
	}

	contentStr := string(content)

	// Detect start marker: try new name first, then old name
	hasStartMarker := strings.Contains(contentStr, claudeMdBlockStart)
	hasEndMarker := strings.Contains(contentStr, claudeMdBlockEnd)
	hasOldStartMarker := strings.Contains(contentStr, claudeMdBlockStartOld)
	hasOldEndMarker := strings.Contains(contentStr, claudeMdBlockEndOld)

	// If old markers are present but new ones aren't, migrate them
	if !hasStartMarker && hasOldStartMarker {
		hasStartMarker = true
		hasEndMarker = hasOldEndMarker
		// Replace old markers with new ones in content before processing
		contentStr = strings.Replace(contentStr, claudeMdBlockStartOld, claudeMdBlockStart, 1)
		contentStr = strings.Replace(contentStr, claudeMdBlockEndOld, claudeMdBlockEnd, 1)
	}

	if !hasStartMarker {
		// CLAUDE.md exists but no managed block — append
		if !yesAll {
			// In non-interactive mode from plugin install, skip prompting
			return "skipped", nil
		}

		updatedContent := contentStr
		if !strings.HasSuffix(contentStr, "\n") {
			updatedContent += "\n"
		}
		updatedContent += "\n" + managedBlock
		if err := os.WriteFile(claudeMdPath, []byte(updatedContent), 0644); err != nil {
			return "", err
		}
		return "appended", nil
	}

	// Has start marker — replace the managed block
	if !hasEndMarker {
		// Malformed: has start but no end. Append end marker after the block.
		return "skipped", fmt.Errorf("CLAUDE.md has start marker but no end marker — manual fix needed")
	}

	// Replace content between markers
	startIdx := strings.Index(contentStr, claudeMdBlockStart)
	endIdx := strings.Index(contentStr, claudeMdBlockEnd) + len(claudeMdBlockEnd)

	// Include trailing newline if present
	if endIdx < len(contentStr) && contentStr[endIdx] == '\n' {
		endIdx++
	}

	updatedContent := contentStr[:startIdx] + managedBlock + contentStr[endIdx:]
	if err := os.WriteFile(claudeMdPath, []byte(updatedContent), 0644); err != nil {
		return "", err
	}
	return "updated", nil
}
