package rescue

import (
	"fmt"
	"io"
)

// VerifyResult holds the before/after comparison of a repair or extract operation.
type VerifyResult struct {
	OriginalStats ScanStats
	OutputStats   ScanStats
	OutputPath    string
	Clean         bool   // true if output has no corruption at all
	Regression    bool   // true if output is worse than input in any way
	Summary       string // human-readable summary
}

// VerifyOutput re-scans an extracted/repaired .dat file and compares it
// against the original scan results to verify the operation only helped.
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

	// Build summary
	vr.Summary = buildVerifySummary(vr, origRecoverable, outRecoverable)

	return vr, nil
}

func buildVerifySummary(vr *VerifyResult, origRecoverable, outRecoverable int) string {
	if vr.Clean && !vr.Regression {
		return fmt.Sprintf("PASS: output is clean — %d valid needles, no corruption", vr.OutputStats.ValidNeedles)
	}
	if vr.Regression {
		return fmt.Sprintf("FAIL: regression detected — original had %d recoverable needles, output has %d",
			origRecoverable, outRecoverable)
	}
	// Not clean but no regression — some corruption persists
	remaining := vr.OutputStats.CorruptedData + vr.OutputStats.CorruptedHeader
	return fmt.Sprintf("WARN: %d corrupted needles remain in output (no regression, %d valid)",
		remaining, vr.OutputStats.ValidNeedles)
}

// PrintVerifyReport writes the verification results to w.
func PrintVerifyReport(w io.Writer, vr *VerifyResult) {
	fmt.Fprintf(w, "\n=== Verification Report ===\n\n")

	fmt.Fprintf(w, "%-20s %10s %10s %10s\n", "", "Original", "Output", "Delta")
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

	fmt.Fprintf(w, "\nResult: %s\n", vr.Summary)
}
