// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/onsi/ginkgo/v2"
)

// weaverAdminURL is where the weaver live-check container exposes its admin
// /stop endpoint (published to the test host by the OATS group compose that
// wires weaver). weaverReport is the host path its report is written to.
const (
	weaverAdminURL = "http://localhost:4320/stop"
	weaverReport   = "/tmp/obi-weaver-out/live_check.json"
)

// weaverStatistics is the subset of the weaver report we surface. The full
// report (all_advice, per-signal detail) is on disk at weaverReport for anyone
// who wants to group it differently.
type weaverStatistics struct {
	TotalAdvisories   int            `json:"total_advisories"`
	AdviceLevelCounts map[string]int `json:"advice_level_counts"`
	AdviceTypeCounts  map[string]int `json:"advice_type_counts"`
	RegistryCoverage  float64        `json:"registry_coverage"`
}

type weaverReportDoc struct {
	Statistics weaverStatistics `json:"statistics"`
}

// validateWeaverObserve stops the weaver live-check container (if a group wired
// one) and logs what it found. It is OBSERVE-only: it never fails the test —
// the OATS suites are brought under weaver validation without gating on the
// (still-being-declared) OBI registry. Groups that do not wire weaver are
// detected by the admin port being unreachable and skipped silently.
func validateWeaverObserve() {
	req, err := http.NewRequest(http.MethodPost, weaverAdminURL, nil)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// No weaver wired for this group (connection refused) — skip.
		return
	}
	resp.Body.Close()

	// Weaver writes its report on /stop; poll until it lands.
	raw, err := waitForWeaverReport(30 * time.Second)
	if err != nil {
		fmt.Fprintf(ginkgo.GinkgoWriter, "weaver: could not read report: %v\n", err)
		return
	}

	var doc weaverReportDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(ginkgo.GinkgoWriter, "weaver: could not parse report: %v\n", err)
		return
	}
	s := doc.Statistics
	fmt.Fprintf(ginkgo.GinkgoWriter, "weaver (OBSERVE): %d advisories, registry coverage %.1f%%\n",
		s.TotalAdvisories, s.RegistryCoverage*100)
	fmt.Fprintf(ginkgo.GinkgoWriter, "  by level: %s\n", sortedCounts(s.AdviceLevelCounts))
	fmt.Fprintf(ginkgo.GinkgoWriter, "  by type:  %s\n", sortedCounts(s.AdviceTypeCounts))
	fmt.Fprintf(ginkgo.GinkgoWriter, "  full report: %s\n", weaverReport)
}

func waitForWeaverReport(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(weaverReport)
		if err == nil && len(raw) > 0 {
			return raw, nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("weaver report %s was empty after %s", weaverReport, timeout)
}

func sortedCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	if out == "" {
		return "(none)"
	}
	return out
}
