package rescue

import (
	"encoding/json"
	"fmt"
	"io"
)

func PrintReport(w io.Writer, result *ScanResult, verbose bool) {
	fmt.Fprintf(w, "=== SeaweedFS Volume Rescue Report ===\n\n")
	fmt.Fprintf(w, "File size:       %s (%d bytes)\n", humanSize(result.DatFileSize), result.DatFileSize)
	fmt.Fprintf(w, "Needle version:  %d\n", result.Version)
	fmt.Fprintf(w, "\n--- Statistics ---\n")
	fmt.Fprintf(w, "Total needles:   %d\n", result.Stats.TotalNeedles)
	fmt.Fprintf(w, "  Valid:          %d\n", result.Stats.ValidNeedles)
	fmt.Fprintf(w, "  Deleted:        %d\n", result.Stats.DeletedNeedles)
	fmt.Fprintf(w, "  Corrupted data: %d\n", result.Stats.CorruptedData)
	fmt.Fprintf(w, "  Corrupted hdr:  %d\n", result.Stats.CorruptedHeader)
	fmt.Fprintf(w, "  Recovered:      %d\n", result.Stats.Recovered)

	if result.Stats.IdxEntries > 0 {
		fmt.Fprintf(w, "\n--- IDX Cross-Reference ---\n")
		fmt.Fprintf(w, "IDX entries:     %d\n", result.Stats.IdxEntries)
		fmt.Fprintf(w, "  Matches:       %d\n", result.Stats.IdxMatches)
		fmt.Fprintf(w, "  Mismatches:    %d\n", result.Stats.IdxMismatches)
	}

	// List corrupted needles by ID (always, not just verbose)
	if result.Stats.CorruptedData > 0 {
		fmt.Fprintf(w, "\n--- Corrupted Needles (data damaged, header intact) ---\n")
		for _, rec := range result.Records {
			if rec.Status == StatusCorruptedData {
				fmt.Fprintf(w, "  needle id=%-10d offset=%-10d dataSize=%-8d crc_stored=%08x crc_computed=%08x\n",
					rec.NeedleId, rec.Offset, rec.DataSize, rec.StoredCRC, rec.ComputedCRC)
			}
		}
	}

	if len(result.CorruptionGaps) > 0 {
		fmt.Fprintf(w, "\n--- Corruption Gaps (header destroyed, data unreadable) ---\n")
		for i, gap := range result.CorruptionGaps {
			fmt.Fprintf(w, "  Gap %d: offset %d - %d (%s)\n", i+1, gap.StartOffset, gap.EndOffset, humanSize(gap.Size()))
		}
		fmt.Fprintf(w, "Total corrupted: %s\n", humanSize(result.Stats.BytesCorrupted))
	}

	if result.Stats.CorruptedData == 0 && len(result.CorruptionGaps) == 0 {
		fmt.Fprintf(w, "\nNo corruption detected.\n")
	}

	if verbose && len(result.Records) > 0 {
		fmt.Fprintf(w, "\n--- Needle Details ---\n")
		for _, rec := range result.Records {
			fmt.Fprintf(w, "  offset=%-10d id=%-10d cookie=%08x size=%-8d status=%-16s source=%s",
				rec.Offset, rec.NeedleId, rec.Cookie, rec.Size, rec.Status, rec.Source)
			if rec.IdxMatch {
				fmt.Fprintf(w, " [idx-match]")
			}
			if rec.Status == StatusCorruptedData {
				fmt.Fprintf(w, " crc_stored=%08x crc_computed=%08x", rec.StoredCRC, rec.ComputedCRC)
			}
			fmt.Fprintln(w)
		}
	}

	// Summary
	fmt.Fprintf(w, "\n--- Summary ---\n")
	recoverable := result.Stats.ValidNeedles + result.Stats.Recovered
	lost := result.Stats.CorruptedData + result.Stats.CorruptedHeader
	totalUseful := recoverable + result.Stats.DeletedNeedles

	if lost == 0 && len(result.CorruptionGaps) == 0 {
		fmt.Fprintf(w, "Volume is healthy: %d needles (%d active, %d deleted), no corruption.\n",
			result.Stats.TotalNeedles, result.Stats.ValidNeedles, result.Stats.DeletedNeedles)
	} else {
		fmt.Fprintf(w, "Recoverable:     %d needles (%d valid + %d deep-scan recovered)\n", recoverable, result.Stats.ValidNeedles, result.Stats.Recovered)
		if result.Stats.Recovered > 0 {
			fmt.Fprintf(w, "Recovered bytes: %s\n", humanSize(result.Stats.BytesRecovered))
		}
		fmt.Fprintf(w, "Lost:            %d needles (%d corrupted data, %d corrupted header)\n", lost, result.Stats.CorruptedData, result.Stats.CorruptedHeader)
		if result.Stats.TotalNeedles > 0 {
			pct := float64(recoverable) / float64(recoverable+lost) * 100
			fmt.Fprintf(w, "Recovery rate:   %.1f%%\n", pct)
		}
		fmt.Fprintf(w, "\nRecommended actions:\n")
		if len(result.CorruptionGaps) > 0 || result.Stats.CorruptedData > 0 {
			fmt.Fprintf(w, "  weed-rescue --extract recovered.dat %s\n", result.datPath)
			fmt.Fprintf(w, "  # Extract %d valid needles to a clean .dat + .idx\n", recoverable)
		}
		if result.Stats.CorruptedData > 0 {
			fmt.Fprintf(w, "  weed-rescue --extract recovered.dat --include-corrupted %s\n", result.datPath)
			fmt.Fprintf(w, "  # Same but also include %d corrupted needles (data may be partially damaged)\n", result.Stats.CorruptedData)
		}
		fmt.Fprintf(w, "  weed-rescue --rebuildIdx %s\n", result.datPath)
		fmt.Fprintf(w, "  # Rebuild .idx from %d entries found in the .dat\n", totalUseful)
	}
}

func PrintJSON(w io.Writer, result *ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
