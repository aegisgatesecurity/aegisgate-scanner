package detectors

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

type CorpusEntry struct {
	ID          string `json:"id"`
	Prompt      string `json:"prompt"`
	Category    string `json:"category"`
	Label       string `json:"label"`
	ContentType string `json:"content_type"`
}

func Test10KScannerSupplement(t *testing.T) {
	data, err := os.ReadFile("/home/chaos/Desktop/AegisGate/testing/chat-ui/corpus-10k-scanner-supplement.json")
	if err != nil {
		t.Skip("Scanner supplement corpus not found")
	}
	var corpus []CorpusEntry
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("Failed to parse corpus: %v", err)
	}

	type catStats struct {
		Total, Blocked, Passed, Errors int
	}
	stats := map[string]*catStats{}
	var tp, fn, tn, fp int

	for _, entry := range corpus {
		s, ok := stats[entry.Category]
		if !ok {
			s = &catStats{}
			stats[entry.Category] = s
		}
		s.Total++

		_, results := DetectAllWithResults(entry.Prompt)
		blocked := len(results) > 0

		if blocked {
			s.Blocked++
			if entry.Label == "attack" {
				tp++
			} else {
				fp++
			}
		} else {
			s.Passed++
			if entry.Label == "benign" {
				tn++
			} else {
				fn++
			}
		}
	}

	catchRate := float64(tp) / float64(tp+fn) * 100
	fpRate := float64(fp) / float64(fp+tn) * 100

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  Scanner 10K Supplement Results")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Catch Rate: %.1f%% (%d/%d attacks blocked)\n", catchRate, tp, tp+fn)
	fmt.Printf("  FP Rate:    %.2f%% (%d/%d benign blocked)\n", fpRate, fp, fp+tn)
	fmt.Printf("  TP=%d  FN=%d  TN=%d  FP=%d\n", tp, fn, tn, fp)

	fmt.Println("\n  Per-Category Breakdown:")
	fmt.Printf("  %-30s %5s %7s %7s %7s\n", "Category", "Total", "Block", "Pass", "Catch%")
	fmt.Println("  " + strings.Repeat("-", 60))

	cats := make([]string, 0, len(stats))
	for k := range stats {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		s := stats[cat]
		catch := float64(s.Blocked) / float64(s.Total) * 100
		fmt.Printf("  %-30s %5d %7d %7d %6.1f%%\n", cat, s.Total, s.Blocked, s.Passed, catch)
	}
	fmt.Println(strings.Repeat("=", 60))

	// Fail if catch rate < 90% or FP rate > 5%
	if catchRate < 90 {
		t.Errorf("Catch rate %.1f%% < 90%% threshold", catchRate)
	}
	if fpRate > 5 {
		t.Errorf("FP rate %.2f%% > 5%% threshold", fpRate)
	}
}
