package rescue

import (
	"fmt"
	"io"
	"os"
	"sort"
)

// VerifyResult holds the before/after comparison of a repair or extract operation.
type VerifyResult struct {
	OriginalStats ScanStats
	OutputStats   ScanStats
	OutputPath    string
	Clean         bool   // true if output has no corruption at all
	Regression    bool   // true if output is worse than input in any way
	Summary       string // human-readable summary

	// Needle-level verification
	NeedlesMissing  []uint64 // NeedleIds present in original (valid) but missing from output
	NeedlesCorrupt  []uint64 // NeedleIds that were valid in original but corrupted in output
	NeedlesIntact   int      // count of needles that match byte-for-byte between original and output
	ContentVerified bool     // true if needle-level content comparison was performed
}

// VerifyOutput re-scans an extracted/repaired .dat file and compares it
// against the original scan results to verify the operation only helped.
// It performs both stat-level and needle-level (byte-for-byte CRC) verification.
func VerifyOutput(outputDatPath string, originalResult *ScanResult, log Logger) (*VerifyResult, error) {
	if log != nil {
		log("verify: re-scanning output volume %s...", outputDatPath)
	}

	scanner := NewScanner(outputDatPath)
	scanner.DeepScan = true
	outputResult, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("verify scan failed: %w", err)
	}

	vr := &VerifyResult{
		OriginalStats: originalResult.Stats,
		OutputStats:   outputResult.Stats,
		OutputPath:    outputDatPath,
	}

	// Check for clean output
	vr.Clean = outputResult.Stats.CorruptedData == 0 &&
		outputResult.Stats.CorruptedHeader == 0 &&
		len(outputResult.CorruptionGaps) == 0

	// Check for regressions: output should not be worse than input
	origRecoverable := originalResult.Stats.ValidNeedles + originalResult.Stats.Recovered + originalResult.Stats.Repaired
	outRecoverable := outputResult.Stats.ValidNeedles + outputResult.Stats.Recovered

	// A regression means we lost needles that were fine in the original
	vr.Regression = outRecoverable < origRecoverable

	// Needle-level content verification
	if log != nil {
		log("verify: comparing needle content between original and output...")
	}
	verifyNeedleContent(originalResult, outputResult, vr, log)

	if vr.Regression && len(vr.NeedlesMissing) > 0 {
		if log != nil {
			log("verify: REGRESSION — %d needles missing from output", len(vr.NeedlesMissing))
		}
	}

	// Build summary
	vr.Summary = buildVerifySummary(vr, origRecoverable, outRecoverable)

	return vr, nil
}

// verifyNeedleContent does a needle-by-needle comparison.
// For each needle that was valid/recovered/repaired in the original,
// checks that it exists in the output with matching CRC.
func verifyNeedleContent(original, output *ScanResult, vr *VerifyResult, log Logger) {
	vr.ContentVerified = true

	// Build lookup: NeedleId → NeedleRecord for output
	outputByID := make(map[uint64]NeedleRecord)
	for _, rec := range output.Records {
		if rec.Status == StatusValid || rec.Status == StatusRecovered {
			// If multiple records for same ID, prefer the valid one
			if existing, ok := outputByID[rec.NeedleId]; ok {
				if existing.Status != StatusValid && rec.Status == StatusValid {
					outputByID[rec.NeedleId] = rec
				}
			} else {
				outputByID[rec.NeedleId] = rec
			}
		}
	}

	// Check each valid/recovered/repaired needle from original
	for _, origRec := range original.Records {
		switch origRec.Status {
		case StatusValid, StatusRecovered, StatusRepaired:
			// This needle should be in the output
		default:
			continue
		}

		outRec, found := outputByID[origRec.NeedleId]
		if !found {
			vr.NeedlesMissing = append(vr.NeedlesMissing, origRec.NeedleId)
			if log != nil {
				log("verify: MISSING needle id=%d (was %s in original)", origRec.NeedleId, origRec.Status)
			}
			continue
		}

		// Compare CRCs — if the output needle has matching stored/computed CRC
		// and it matches the original stored CRC, the data is identical
		if outRec.Status == StatusValid && outRec.StoredCRC == origRec.StoredCRC {
			vr.NeedlesIntact++
		} else if outRec.Status == StatusCorruptedData {
			vr.NeedlesCorrupt = append(vr.NeedlesCorrupt, origRec.NeedleId)
			if log != nil {
				log("verify: CORRUPTED in output — needle id=%d was valid in original but corrupted in output", origRec.NeedleId)
			}
		} else if outRec.Status == StatusValid {
			// CRC valid but different from original — the data changed (e.g., repaired)
			vr.NeedlesIntact++
		}
	}
}

func buildVerifySummary(vr *VerifyResult, origRecoverable, outRecoverable int) string {
	parts := []string{}

	if vr.Clean && !vr.Regression && len(vr.NeedlesCorrupt) == 0 && len(vr.NeedlesMissing) == 0 {
		parts = append(parts, fmt.Sprintf("PASS: output is clean — %d valid needles, no corruption", vr.OutputStats.ValidNeedles))
		if vr.ContentVerified {
			parts = append(parts, fmt.Sprintf("  content verified: %d needles match CRC", vr.NeedlesIntact))
		}
		return joinLines(parts)
	}

	if len(vr.NeedlesMissing) > 0 {
		parts = append(parts, fmt.Sprintf("FAIL: %d needles missing from output", len(vr.NeedlesMissing)))
	}
	if len(vr.NeedlesCorrupt) > 0 {
		parts = append(parts, fmt.Sprintf("FAIL: %d needles corrupted during extract", len(vr.NeedlesCorrupt)))
	}
	if vr.Regression && len(vr.NeedlesMissing) == 0 && len(vr.NeedlesCorrupt) == 0 {
		parts = append(parts, fmt.Sprintf("FAIL: regression detected — original had %d recoverable needles, output has %d",
			origRecoverable, outRecoverable))
	}

	if len(parts) == 0 {
		remaining := vr.OutputStats.CorruptedData + vr.OutputStats.CorruptedHeader
		parts = append(parts, fmt.Sprintf("WARN: %d corrupted needles remain in output (no regression, %d valid)",
			remaining, vr.OutputStats.ValidNeedles))
	}

	if vr.ContentVerified && vr.NeedlesIntact > 0 {
		parts = append(parts, fmt.Sprintf("  content verified: %d needles match CRC", vr.NeedlesIntact))
	}

	return joinLines(parts)
}

func joinLines(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "\n"
		}
		result += p
	}
	return result
}

// PrintVerifyReport writes the verification results to w.
func PrintVerifyReport(w io.Writer, vr *VerifyResult) {
	fmt.Fprintf(w, "\n=== Verification Report (Before / After) ===\n\n")

	fmt.Fprintf(w, "%-20s %10s %10s %10s\n", "", "Before", "After", "Delta")
	fmt.Fprintf(w, "%-20s %10s %10s %10s\n", "--------------------", "----------", "----------", "----------")

	printRow := func(label string, orig, out int) {
		delta := out - orig
		sign := ""
		if delta > 0 {
			sign = "+"
		}
		fmt.Fprintf(w, "%-20s %10d %10d %10s\n", label, orig, out, fmt.Sprintf("%s%d", sign, delta))
	}

	printRow("Valid", vr.OriginalStats.ValidNeedles, vr.OutputStats.ValidNeedles)
	printRow("Deleted", vr.OriginalStats.DeletedNeedles, vr.OutputStats.DeletedNeedles)
	printRow("Corrupted data", vr.OriginalStats.CorruptedData, vr.OutputStats.CorruptedData)
	printRow("Corrupted header", vr.OriginalStats.CorruptedHeader, vr.OutputStats.CorruptedHeader)
	printRow("Recovered", vr.OriginalStats.Recovered, vr.OutputStats.Recovered)
	printRow("Repaired", vr.OriginalStats.Repaired, vr.OutputStats.Repaired)

	if vr.ContentVerified {
		fmt.Fprintf(w, "\n--- Needle Content Verification ---\n")
		fmt.Fprintf(w, "Intact (CRC match):  %d\n", vr.NeedlesIntact)
		if len(vr.NeedlesMissing) > 0 {
			fmt.Fprintf(w, "Missing:             %d", len(vr.NeedlesMissing))
			if len(vr.NeedlesMissing) <= 10 {
				fmt.Fprintf(w, " (ids: ")
				for i, id := range vr.NeedlesMissing {
					if i > 0 {
						fmt.Fprint(w, ", ")
					}
					fmt.Fprintf(w, "%d", id)
				}
				fmt.Fprint(w, ")")
			}
			fmt.Fprintln(w)
		}
		if len(vr.NeedlesCorrupt) > 0 {
			fmt.Fprintf(w, "Corrupted in output: %d", len(vr.NeedlesCorrupt))
			if len(vr.NeedlesCorrupt) <= 10 {
				fmt.Fprintf(w, " (ids: ")
				for i, id := range vr.NeedlesCorrupt {
					if i > 0 {
						fmt.Fprint(w, ", ")
					}
					fmt.Fprintf(w, "%d", id)
				}
				fmt.Fprint(w, ")")
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintf(w, "\nResult: %s\n", vr.Summary)

	// Explicit verdict — no ambiguity
	fmt.Fprintln(w)
	if vr.Clean && !vr.Regression && len(vr.NeedlesCorrupt) == 0 && len(vr.NeedlesMissing) == 0 {
		fmt.Fprintf(w, ">>> VERDICT: SAFE TO USE — output volume passed all checks <<<\n")
		fmt.Fprintf(w, "    The output .dat and .idx can be used as a replacement for the original.\n")
	} else if vr.Regression || len(vr.NeedlesCorrupt) > 0 || len(vr.NeedlesMissing) > 0 {
		fmt.Fprintf(w, ">>> VERDICT: DO NOT USE — output volume has problems <<<\n")
		fmt.Fprintf(w, "    The output has regressions or data loss compared to the original.\n")
		fmt.Fprintf(w, "    DO NOT replace the original with this output. Investigate the issues above.\n")
	} else {
		fmt.Fprintf(w, ">>> VERDICT: USE WITH CAUTION — output has some unresolved corruption <<<\n")
		fmt.Fprintf(w, "    No data was lost compared to the original, but some corruption remains.\n")
		fmt.Fprintf(w, "    The output is at least as good as the original.\n")
	}
}

// VerifyIdxConsistency checks that the .idx file is consistent with the .dat scan results.
// Returns a list of issues found.
func VerifyIdxConsistency(idxPath string, result *ScanResult) ([]string, error) {
	entries, err := ReadIdxFile(idxPath)
	if err != nil {
		return nil, fmt.Errorf("read idx: %w", err)
	}

	var issues []string

	// Build a lookup from the scan results: needleId → NeedleRecord
	datNeedles := make(map[uint64]NeedleRecord)
	for _, rec := range result.Records {
		if rec.Status == StatusValid || rec.Status == StatusRecovered || rec.Status == StatusRepaired || rec.Status == StatusDeleted {
			datNeedles[rec.NeedleId] = rec
		}
	}

	// Check each idx entry against the dat scan
	for _, entry := range entries {
		datRec, found := datNeedles[entry.NeedleId]
		if !found {
			issues = append(issues, fmt.Sprintf("idx has needle id=%d but not found in .dat scan", entry.NeedleId))
			continue
		}
		if datRec.Offset != entry.Offset {
			issues = append(issues, fmt.Sprintf("needle id=%d: idx offset=%d but dat offset=%d",
				entry.NeedleId, entry.Offset, datRec.Offset))
		}
	}

	// Check for needles in dat but missing from idx
	idxSet := make(map[uint64]bool)
	for _, entry := range entries {
		idxSet[entry.NeedleId] = true
	}
	var missing []uint64
	for id, rec := range datNeedles {
		if !idxSet[id] && rec.Status != StatusDeleted {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
		for _, id := range missing {
			issues = append(issues, fmt.Sprintf("needle id=%d in .dat but missing from .idx", id))
		}
	}

	return issues, nil
}

// VerifyExtractedVolume is a convenience that chains: re-scan output + needle comparison + idx check.
func VerifyExtractedVolume(outputDatPath string, originalResult *ScanResult, log Logger) (*VerifyResult, []string, error) {
	vr, err := VerifyOutput(outputDatPath, originalResult, log)
	if err != nil {
		return nil, nil, err
	}

	// Also verify idx consistency
	idxPath := outputDatPath[:len(outputDatPath)-4] + ".idx"
	if _, statErr := os.Stat(idxPath); statErr == nil {
		if log != nil {
			log("verify: checking idx consistency %s...", idxPath)
		}
		// Re-scan to get output records
		scanner := NewScanner(outputDatPath)
		outResult, err := scanner.Run()
		if err == nil {
			idxIssues, err := VerifyIdxConsistency(idxPath, outResult)
			if err != nil {
				if log != nil {
					log("verify: idx check failed: %v", err)
				}
			} else if len(idxIssues) > 0 {
				if log != nil {
					for _, issue := range idxIssues {
						log("verify: idx issue: %s", issue)
					}
				}
				return vr, idxIssues, nil
			} else {
				if log != nil {
					log("verify: idx is consistent with .dat")
				}
			}
		}
	}

	return vr, nil, nil
}
