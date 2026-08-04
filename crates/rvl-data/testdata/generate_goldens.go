// Golden fixture generator for the rvl-data crate (po-av01j.17).
//
// Mirrors the EXACT structs and marshal calls rvl-cli uses on its
// re-marshal JSON paths, so the Rust port can be tested byte-for-byte
// against what the Go CLI would print. Run with:
//
//	env -u GOROOT go run main.go <outdir>
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// --- structs copied verbatim (fields+tags) from rvl-cli internal/commands ---

type Risk struct {
	ID            string   `json:"id"`
	RiskCode      string   `json:"risk_code"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	Score         int      `json:"score"`
	Status        string   `json:"status"`
	Services      []string `json:"linked_services"`
	ControlCodes  []string `json:"control_codes,omitempty"`
	StaleSince    string   `json:"stale_since,omitempty"`
	LastSeenAt    string   `json:"last_seen_at,omitempty"`
	ResolvedAt    string   `json:"resolved_at,omitempty"`
	UCAType       string   `json:"uca_type,omitempty"`
	CausalFactors []string `json:"causal_factors,omitempty"`
	LossScenario  string   `json:"loss_scenario,omitempty"`
}

type ListRisksResponse struct {
	Risks []Risk `json:"risks"`
	Total int    `json:"total"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
}

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

type KnowledgeProceduresResponse struct {
	Procedures []KnowledgeProcedure `json:"procedures"`
	Total      int                  `json:"total"`
}

type RiskStatsResponse struct {
	Coverage *CoverageStats `json:"coverage,omitempty"`
}

type CoverageStats struct {
	TotalControls      int                `json:"total_controls"`
	AssessedControls   int                `json:"assessed_controls"`
	CoveragePercentage float64            `json:"coverage_percentage"`
	ByCategory         []CategoryCoverage `json:"by_category,omitempty"`
}

type CategoryCoverage struct {
	Category string `json:"category"`
	Total    int    `json:"total"`
	Assessed int    `json:"assessed"`
}

// --- rvl-cli logic copied verbatim ---

func coverageFrom(body []byte) *CoverageStats {
	if len(body) == 0 {
		return nil
	}
	var s RiskStatsResponse
	if json.Unmarshal(body, &s) != nil {
		return nil
	}
	return s.Coverage
}

func composeRiskContextJSON(contextBody, detailBody []byte, coverage *CoverageStats) ([]byte, error) {
	var merged map[string]any
	if len(contextBody) > 0 {
		if err := json.Unmarshal(contextBody, &merged); err != nil {
			return nil, err
		}
	} else {
		merged = map[string]any{}
	}
	if len(detailBody) > 0 {
		var detail any
		if json.Unmarshal(detailBody, &detail) == nil {
			merged["detail"] = detail
		}
	}
	if coverage != nil {
		merged["coverage_gap"] = coverage
	}
	return json.MarshalIndent(merged, "", "  ")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(dir, name string, data []byte) {
	must(os.WriteFile(filepath.Join(dir, name), data, 0644))
	fmt.Println("wrote", name)
}

func main() {
	dir := os.Args[1]
	must(os.MkdirAll(dir, 0755))

	// ---- 1. risk ready: input list body -> wrapped MarshalIndent + "\n" ----
	// Input deliberately includes: unknown fields (dropped), HTML-escaping
	// bait (& < >), a non-applicable risk (filtered), missing linked_services
	// (null), unicode, and more applicable risks than --limit=2.
	readyInput := []byte(`{"risks":[
	  {"id":"11111111-1111-1111-1111-111111111111","risk_code":"R-001","title":"DB <primary> & replica lag","category":"data_management","score":88,"status":"applicable","linked_services":["checkout-api","billing"],"control_codes":["RC-018"],"last_seen_at":"2026-08-01T10:00:00Z","narrative":"dropped-by-cli","uca_type":"not_provided"},
	  {"id":"22222222-2222-2222-2222-222222222222","risk_code":"R-002","title":"Retry storm étude","category":"fault_tolerance","score":70,"status":"accepted","linked_services":["api"]},
	  {"id":"33333333-3333-3333-3333-333333333333","risk_code":"R-003","title":"No timeout","category":"fault_tolerance","score":65,"status":"applicable"},
	  {"id":"44444444-4444-4444-4444-444444444444","risk_code":"R-004","title":"Low priority","category":"monitoring","score":10,"status":"applicable","linked_services":[]}
	],"total":4,"page":1,"limit":1000}`)
	var resp ListRisksResponse
	must(json.Unmarshal(readyInput, &resp))
	var ready []Risk
	for _, r := range resp.Risks {
		if r.Status == "applicable" {
			ready = append(ready, r)
		}
	}
	limit := 2
	out := ready
	if len(out) > limit {
		out = out[:limit]
	}
	wrapped := ListRisksResponse{Risks: out, Total: len(ready), Page: 1, Limit: limit}
	jsonBytes, err := json.MarshalIndent(wrapped, "", "  ")
	must(err)
	write(dir, "ready_input.json", readyInput)
	write(dir, "ready_golden.txt", append(jsonBytes, '\n')) // fmt.Println adds \n

	// Empty ready set: nil slice marshals as null.
	emptyIn := []byte(`{"risks":[{"id":"a","risk_code":"R-9","title":"t","category":"c","score":1,"status":"accepted","linked_services":null}],"total":1,"page":1,"limit":1000}`)
	var resp2 ListRisksResponse
	must(json.Unmarshal(emptyIn, &resp2))
	var ready2 []Risk
	for _, r := range resp2.Risks {
		if r.Status == "applicable" {
			ready2 = append(ready2, r)
		}
	}
	wrapped2 := ListRisksResponse{Risks: ready2, Total: len(ready2), Page: 1, Limit: 10}
	jb2, err := json.MarshalIndent(wrapped2, "", "  ")
	must(err)
	write(dir, "ready_empty_input.json", emptyIn)
	write(dir, "ready_empty_golden.txt", append(jb2, '\n'))

	// ---- 2. risk context compose ----
	ctxBody := []byte(`{"risk":{"id":"x","risk_code":"R-001","title":"DB <primary> & replica","category":"data_management","score":88,"status":"applicable","linked_services":["a"]},"controls":[{"control":{"control_code":"RC-018","name":"Timeouts & retries","category":"fault_tolerance","type":"preventive"},"existing_evidence":[],"evidence_gaps":["code"]}],"knowledge":{"patterns":[],"procedures":[],"facts":[]},"score_factors":[{"description":"seen in 3 incidents","points":30,"source":"incidents"}],"graph_multiplier":{"value":1.25},"zeta":true}`)
	detailBody := []byte(`{"id":"x","risk_code":"R-001","title":"DB <primary> & replica","score":88,"narrative":"a > b","mapped_controls":[{"control_code":"RC-018","name":"Timeouts & retries","category":"fault_tolerance","type":"preventive"}]}`)
	statsBody := []byte(`{"coverage":{"total_controls":48,"assessed_controls":12,"coverage_percentage":25.0,"by_category":[{"category":"fault_tolerance","total":10,"assessed":4}]}}`)
	composed, err := composeRiskContextJSON(ctxBody, detailBody, coverageFrom(statsBody))
	must(err)
	write(dir, "context_ctx_input.json", ctxBody)
	write(dir, "context_detail_input.json", detailBody)
	write(dir, "context_stats_input.json", statsBody)
	write(dir, "context_composed_golden.txt", append(composed, '\n'))

	// Compose with no detail and no coverage (both fetches failed / empty).
	composed2, err := composeRiskContextJSON(ctxBody, nil, nil)
	must(err)
	write(dir, "context_composed_noextras_golden.txt", append(composed2, '\n'))

	// ---- 3. knowledge procedures --control filtered re-marshal ----
	procsIn := []byte(`{"procedures":[
	  {"id":"proc_1","title":"Add circuit breaker","vertical":"fault-tolerance","procedure_type":"runbook","related_controls":["RC-018","RC-012"],"technologies":["go"],"effectiveness_score":0.9,"applied_count":4,"success_count":3,"confidence":0.8,"score":1.5},
	  {"id":"proc_2","title":"Rotate keys < & >","vertical":"security","procedure_type":"best_practice","related_controls":["RC-043"],"effectiveness_score":0.5,"applied_count":0,"success_count":0,"confidence":0.6}
	],"total":2}`)
	var procs KnowledgeProceduresResponse
	must(json.Unmarshal(procsIn, &procs))
	var filtered []KnowledgeProcedure
	for _, p := range procs.Procedures {
		for _, rc := range p.RelatedControls {
			if rc == "RC-018" {
				filtered = append(filtered, p)
				break
			}
		}
	}
	procs.Procedures = filtered
	procs.Total = len(filtered)
	pj, err := json.MarshalIndent(procs, "", "  ")
	must(err)
	write(dir, "procedures_input.json", procsIn)
	write(dir, "procedures_filtered_golden.txt", append(pj, '\n'))

	// ---- 4. url.Values.Encode parity samples ----
	var buf []byte
	add := func(pairs [][2]string) {
		q := url.Values{}
		for _, p := range pairs {
			q.Set(p[0], p[1])
		}
		buf = append(buf, []byte(q.Encode()+"\n")...)
	}
	add([][2]string{{"limit", "1000"}, {"status", "applicable"}, {"service", "a&b=c %"}, {"category", "fault_tolerance"}})
	add([][2]string{{"limit", "1000"}, {"sort_by", "score"}, {"sort_order", "desc"}})
	add([][2]string{{"limit", "20"}, {"vertical", "fault-tolerance"}, {"technology", "go+redis"}})
	add([][2]string{{"limit", "200"}})
	add([][2]string{{"q", "RC-018"}, {"limit", "20"}, {"type", "runbook"}})
	add([][2]string{{"query", "café ~tilde-_.x"}})
	write(dir, "query_encode_golden.txt", buf)

	// ---- 5. knowledge search POST body (json.Marshal of map[string]interface{}) ----
	body := map[string]interface{}{"query": "circuit breaker & <timeouts>", "limit": 20, "offset": 0}
	bb, err := json.Marshal(body)
	must(err)
	write(dir, "search_body_golden.txt", bb)
}
