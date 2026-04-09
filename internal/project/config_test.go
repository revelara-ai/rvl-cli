package project

import "testing"

func TestCriticalityScore(t *testing.T) {
	tests := []struct {
		label    string
		expected float64
	}{
		{"hobby", 0.0},
		{"internal", 0.25},
		{"customer-facing", 0.6},
		{"critical", 1.0},
		{"", 0.0},       // empty defaults to no boost
		{"unknown", 0.0}, // unrecognized defaults to no boost
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			cfg := &ProjectConfig{Criticality: tt.label}
			score := cfg.CriticalityScore()
			if score != tt.expected {
				t.Errorf("CriticalityScore(%q) = %f, want %f", tt.label, score, tt.expected)
			}
		})
	}
}
