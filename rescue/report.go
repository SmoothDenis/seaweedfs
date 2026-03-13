package rescue

import (
	"encoding/json"
	"fmt"
	"io"
)

func PrintReport(w io.Writer, result *ScanResult, verbose bool, signatures ...[]GapSignature) {
	fmt.Fprintf(w, "=== SeaweedFS Volume Rescue Report ===\n\n")
	fmt.Fprintf(w, "File size:       %s (%d bytes)\n", humanSize(result.DatFileSize), result.DatFileSize)
	fmt.Fprintf(w, "Needle version:  %d\n", result.Version)
	fmt.Fprintf(w, "\n--- Statistics ---\n")
	fmt.Fprintf(w, "Total needles:   %d\n", result.Stats.TotalNeedles)
	fmt.Fprintf(w, "  Valid:          %d\n", result.Stats.ValidNeedles)
	fmt.Fprintf(w, "  Deleted:        %d\n", result.Stats.DeletedNeedles)
	fmt.Fprintf(w, "  Deletion markers: %d\n", result.Stats.DeletionMarkers)
	fmt.Fprintf(w, "  Corrupted data: %d\n", result.Stats.CorruptedData)
	fmt.Fprintf(w, "  Corrupted hdr:  %d\n", result.Stats.CorruptedHeader)
	fmt.Fprintf(w, "  Recovered:      %d\n", result.Stats.Recovered)
	if result.Stats.Repaired > 0 {
		fmt.Fprintf(w, "  Repaired:       %d\n", result.Stats.Repaired)
	}

	if result.Stats.IdxActive > 0 || result.Stats.IdxTombstoned > 0 {
		fmt.Fprintf(w, "\n--- IDX Cross-Reference ---\n")
		fmt.Fprintf(w, "IDX entries:      %d active + %d tombstoned\n", result.Stats.IdxActive, result.Stats.IdxTombstoned)
		fmt.Fprintf(w, "Confirmed in dat: %d active needles matched\n", result.Stats.IdxConfirmed)
		fmt.Fprintf(w, "Orphaned in idx:  %d (idx points to missing data)\n", result.Stats.IdxOrphaned)

		// Warn about .dat/.idx size mismatch: needles in .dat not tracked by .idx
		datNeedleCount := result.Stats.ValidNeedles + result.Stats.DeletedNeedles
		idxTotal := result.Stats.IdxActive + result.Stats.IdxTombstoned
		if datNeedleCount > idxTotal {
			untracked := datNeedleCount - idxTotal
			fmt.Fprintf(w, "\nWARNING: .dat contains %d data-bearing needles but .idx only has %d entries.\n", datNeedleCount, idxTotal)
			fmt.Fprintf(w, "         %d needles in .dat are NOT tracked by .idx.\n", untracked)
			fmt.Fprintf(w, "         The volume server will report a file size mismatch (volumeDataIntegrityChecking).\n")
			fmt.Fprintf(w, "         This typically happens when .dat and .idx have different compact_revision.\n")
			fmt.Fprintf(w, "         Fix: rebuild .idx from .dat with: weed-rescue --rebuildIdx %s\n", result.datPath)
		}
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

		// Show file signatures found in gaps (if provided)
		if len(signatures) > 0 && len(signatures[0]) > 0 {
			fmt.Fprintf(w, "\n--- File Signatures in Gaps (what was lost) ---\n")
			for _, sig := range signatures[0] {
				fmt.Fprintf(w, "  Gap %d, offset %d: %s\n", sig.GapIndex+1, sig.Offset, sig.FileType)
			}
		}
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
	// Data-bearing needles exclude deletion markers (Size=0)
	dataBearing := recoverable + result.Stats.DeletedNeedles + lost
	totalUseful := recoverable + result.Stats.DeletedNeedles

	hasIdxStats := result.Stats.IdxActive > 0 || result.Stats.IdxTombstoned > 0

	if lost == 0 && len(result.CorruptionGaps) == 0 {
		if hasIdxStats {
			fmt.Fprintf(w, "Active data: %d needles, %d deletion markers (Size=0), %d corrupted\n",
				result.Stats.ValidNeedles, result.Stats.DeletionMarkers, result.Stats.CorruptedData)
		} else {
			fmt.Fprintf(w, "Volume is healthy: %d data-bearing needles (%d active, %d deleted), %d deletion markers (Size=0), no corruption.\n",
				dataBearing, result.Stats.ValidNeedles, result.Stats.DeletedNeedles, result.Stats.DeletionMarkers)
		}
		idxDatMismatch := hasIdxStats && (result.Stats.ValidNeedles+result.Stats.DeletedNeedles) > (result.Stats.IdxActive+result.Stats.IdxTombstoned)
		if hasIdxStats && result.Stats.IdxOrphaned == 0 && !idxDatMismatch {
			fmt.Fprintf(w, "\nVolume is healthy. IDX cross-reference shows no orphaned entries and no corruption.\n")
		} else if idxDatMismatch {
			fmt.Fprintf(w, "\nVolume data is intact but .idx is incomplete — volume server will reject this volume.\n")
			fmt.Fprintf(w, "Run: weed-rescue --rebuildIdx %s\n", result.datPath)
		}
	} else {
		if hasIdxStats {
			fmt.Fprintf(w, "Active data: %d needles, %d deletion markers (Size=0), %d corrupted\n",
				result.Stats.ValidNeedles, result.Stats.DeletionMarkers, result.Stats.CorruptedData+result.Stats.CorruptedHeader)
		}
		fmt.Fprintf(w, "Recoverable:     %d needles (%d valid + %d deep-scan recovered)\n", recoverable, result.Stats.ValidNeedles, result.Stats.Recovered)
		if result.Stats.Recovered > 0 {
			fmt.Fprintf(w, "Recovered bytes: %s\n", humanSize(result.Stats.BytesRecovered))
		}
		fmt.Fprintf(w, "Lost:            %d needles (%d corrupted data, %d corrupted header)\n", lost, result.Stats.CorruptedData, result.Stats.CorruptedHeader)
		if dataBearing > 0 {
			pct := float64(recoverable) / float64(dataBearing) * 100
			fmt.Fprintf(w, "Recovery rate:   %.1f%%\n", pct)
		}
		fmt.Fprintf(w, "\nRecommended next step (single command runs the full pipeline):\n")
		if result.Stats.CorruptedData > 0 {
			fmt.Fprintf(w, "\n  # Preview repairs first (no files written):\n")
			fmt.Fprintf(w, "  weed-rescue --repair --dry-run %s\n", result.datPath)
		}
		fmt.Fprintf(w, "\n  # Full recovery pipeline — scan + repair + extract + verify:\n")
		fmt.Fprintf(w, "  weed-rescue \\\n")
		fmt.Fprintf(w, "    --backup-dir /backup \\\n")
		fmt.Fprintf(w, "    --deep \\\n")
		if result.Stats.CorruptedData > 0 {
			fmt.Fprintf(w, "    --repair \\\n")
		}
		fmt.Fprintf(w, "    --extract recovered.dat \\\n")
		fmt.Fprintf(w, "    --verify \\\n")
		fmt.Fprintf(w, "    %s\n", result.datPath)
		fmt.Fprintf(w, "\n  # Or rebuild .idx only (%d entries):\n", totalUseful)
		fmt.Fprintf(w, "  weed-rescue --rebuildIdx %s\n", result.datPath)
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
