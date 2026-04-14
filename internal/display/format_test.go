package display

import "testing"

func TestParseSTPAContext_WithAllMarkers(t *testing.T) {
	narrative := `This service lacks circuit breakers on external API calls.
**Unsafe Control Action:** not_provided
**Loss Scenario:** Cascading failure when payment provider is unavailable
**Causal Factors:**
- inadequate feedback: no monitoring on retry rates
- incorrect process model: assumes external services are always available`

	ctx := ParseSTPAContext(narrative)
	if ctx == nil {
		t.Fatal("expected non-nil STPAContext")
	}
	if ctx.UCAType != "not_provided" {
		t.Errorf("UCAType = %q, want %q", ctx.UCAType, "not_provided")
	}
	if ctx.LossScenario != "Cascading failure when payment provider is unavailable" {
		t.Errorf("LossScenario = %q", ctx.LossScenario)
	}
	if len(ctx.CausalFactors) != 2 {
		t.Fatalf("CausalFactors len = %d, want 2", len(ctx.CausalFactors))
	}
	if ctx.CausalFactors[0] != "inadequate feedback: no monitoring on retry rates" {
		t.Errorf("CausalFactors[0] = %q", ctx.CausalFactors[0])
	}
	if ctx.CleanNarrative == "" {
		t.Error("CleanNarrative should not be empty")
	}
}

func TestParseSTPAContext_NoMarkers(t *testing.T) {
	ctx := ParseSTPAContext("A plain narrative with no STPA markers.")
	if ctx != nil {
		t.Error("expected nil for narrative without STPA markers")
	}
}

func TestParseSTPAContext_Empty(t *testing.T) {
	ctx := ParseSTPAContext("")
	if ctx != nil {
		t.Error("expected nil for empty narrative")
	}
}

func TestFormatUCACategory(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"not_provided", "What control is missing?"},
		{"providing_incorrectly", "What assumption is wrong?"},
		{"wrong_timing", "What feedback is delayed?"},
		{"wrong_duration", "What enforcement is bypassed?"},
		{"unknown_type", ""},
	}
	for _, tt := range tests {
		got := FormatUCACategory(tt.input)
		if got != tt.want {
			t.Errorf("FormatUCACategory(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatUCAType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"not_provided", "Not Provided"},
		{"providing_incorrectly", "Providing Incorrectly"},
		{"wrong_timing", "Wrong Timing"},
	}
	for _, tt := range tests {
		got := FormatUCAType(tt.input)
		if got != tt.want {
			t.Errorf("FormatUCAType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
