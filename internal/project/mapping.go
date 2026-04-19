package project

import "strings"

// MapFindingsToComponents sets linked_services on each finding based on
// evidence paths matched against .revelara.yaml components. Uses longest-prefix
// matching so nested paths (e.g. services/x/frontend/) beat parent paths.
func MapFindingsToComponents(findings []interface{}, projectCfg *ProjectConfig) {
	if projectCfg == nil || len(projectCfg.Components) == 0 {
		return
	}

	// Sort components by path length descending for longest-prefix-first matching
	type comp struct {
		name string
		path string
	}
	sorted := make([]comp, len(projectCfg.Components))
	for i, c := range projectCfg.Components {
		sorted[i] = comp{name: c.Name, path: c.Path}
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[j].path) > len(sorted[i].path) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	project := projectCfg.Project

	for _, f := range findings {
		finding, ok := f.(map[string]interface{})
		if !ok {
			continue
		}

		// Skip if finding already has linked_services set
		if existing, ok := finding["linked_services"]; ok {
			if arr, ok := existing.([]interface{}); ok && len(arr) > 0 {
				continue
			}
		}

		// Use explicit component field if present (set by skills)
		if compName, ok := finding["component"].(string); ok && compName != "" {
			finding["linked_services"] = []interface{}{project + "/" + compName}
			continue
		}

		// Collect evidence paths
		evidence, ok := finding["evidence"].([]interface{})
		if !ok || len(evidence) == 0 {
			continue
		}

		matched := make(map[string]bool)
		for _, ev := range evidence {
			evMap, ok := ev.(map[string]interface{})
			if !ok {
				continue
			}
			path, _ := evMap["path"].(string)
			if path == "" {
				continue
			}

			// Find best (longest prefix) component match
			for _, c := range sorted {
				if strings.HasPrefix(path, c.path) {
					matched[project+"/"+c.name] = true
					break // longest prefix wins
				}
			}
		}

		if len(matched) > 0 {
			services := make([]interface{}, 0, len(matched))
			for svc := range matched {
				services = append(services, svc)
			}
			finding["linked_services"] = services
		}
	}
}
