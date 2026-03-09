package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/seaweedfs/seaweedfs/rescue"
)

func main() {
	idxPath := flag.String("idx", "", "path to .idx file (improves recovery)")
	version := flag.Int("version", 0, "needle version (2 or 3, default: auto-detect)")
	rebuildIdx := flag.Bool("rebuildIdx", false, "rebuild .idx from scan results")
	extractPath := flag.String("extract", "", "extract valid needles to a new clean .dat + .idx")
	deep := flag.Bool("deep", false, "enable deep scan for maximum recovery (slower)")
	verbose := flag.Bool("verbose", false, "show detailed per-needle output")
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	quiet := flag.Bool("quiet", false, "suppress progress logging (only output report)")
	includeCorrupted := flag.Bool("include-corrupted", false, "include corrupted-data needles in extract (data may be partially damaged)")
	repair := flag.Bool("repair", false, "attempt single-byte CRC repair on corrupted needles and extract repaired data")
	verify := flag.Bool("verify", false, "re-scan output after extract/repair and show before/after comparison")
	dryRun := flag.Bool("dry-run", false, "with --repair: show what would be fixed without writing files")

	replace := flag.Bool("replace", false, "after successful --verify, replace original volume with recovered one (prompts for confirmation)")
	force := flag.Bool("force", false, "skip confirmation prompts and overwrite existing output files")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: weed-rescue [flags] <path-to-dat-file>\n\n")
		fmt.Fprintf(os.Stderr, "Scans a SeaweedFS volume .dat file for valid and corrupted needles.\n")
		fmt.Fprintf(os.Stderr, "Can recover data from corrupted volumes using CRC32 validation.\n\n")
		fmt.Fprintf(os.Stderr, "SAFETY: The source .dat file is NEVER modified. All write operations\n")
		fmt.Fprintf(os.Stderr, "produce new files. Writes use atomic temp+fsync+rename to prevent\n")
		fmt.Fprintf(os.Stderr, "partial files on crash. A file lock prevents concurrent runs.\n\n")
		fmt.Fprintf(os.Stderr, "Exit codes:\n")
		fmt.Fprintf(os.Stderr, "  0  Volume is healthy, no corruption found\n")
		fmt.Fprintf(os.Stderr, "  1  Usage error, invalid flags, pre-flight failure\n")
		fmt.Fprintf(os.Stderr, "  2  Corruption detected in source volume\n")
		fmt.Fprintf(os.Stderr, "  3  Verification failed: output has regressions (DO NOT USE)\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	datPath := flag.Arg(0)

	// --- Flag validation ---
	var errors []string

	// Path validation
	if len(datPath) < 5 || datPath[len(datPath)-4:] != ".dat" {
		errors = append(errors, fmt.Sprintf("input path must end with .dat: %q", datPath))
	}
	if _, err := os.Stat(datPath); os.IsNotExist(err) {
		errors = append(errors, fmt.Sprintf("input file does not exist: %s", datPath))
	}
	if *extractPath != "" {
		if len(*extractPath) < 5 || (*extractPath)[len(*extractPath)-4:] != ".dat" {
			errors = append(errors, fmt.Sprintf("--extract path must end with .dat: %q", *extractPath))
		}
		absExtract, _ := filepath.Abs(*extractPath)
		absDat, _ := filepath.Abs(datPath)
		if absExtract == absDat {
			errors = append(errors, "cannot --extract to the same file as input (would overwrite source)")
		}
	}

	// Version validation
	if *version != 0 && (*version < 2 || *version > 3) {
		errors = append(errors, fmt.Sprintf("--version must be 2 or 3, got %d", *version))
	}

	// Flag combination validation
	if *verify && *extractPath == "" {
		errors = append(errors, "--verify requires --extract <path.dat>")
	}
	if *dryRun && !*repair {
		errors = append(errors, "--dry-run requires --repair")
	}
	if *includeCorrupted && *repair {
		errors = append(errors, "--include-corrupted and --repair are mutually exclusive (use one or the other)")
	}
	if *repair && *extractPath == "" && !*dryRun {
		errors = append(errors, "--repair requires --extract <path.dat> or --dry-run")
	}
	if *replace && !*verify {
		errors = append(errors, "--replace requires --verify (must verify before replacing)")
	}
	if *replace && *extractPath == "" {
		errors = append(errors, "--replace requires --extract <path.dat>")
	}

	if len(errors) > 0 {
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		}
		os.Exit(1)
	}

	// --- Pre-flight checks ---
	preflightIssues := rescue.PreFlightChecks(datPath, *extractPath, *force)
	if len(preflightIssues) > 0 {
		fmt.Fprintf(os.Stderr, "Pre-flight check failed:\n")
		for _, issue := range preflightIssues {
			fmt.Fprintf(os.Stderr, "  ERROR: %s\n", issue)
		}
		os.Exit(1)
	}

	// --- Acquire exclusive lock on source volume ---
	lockFile, err := rescue.LockFile(datPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer rescue.UnlockFile(lockFile)

	var logger rescue.Logger
	if !*quiet {
		logger = func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	scanner := rescue.NewScanner(datPath)
	scanner.IdxPath = *idxPath
	scanner.Version = *version
	scanner.DeepScan = *deep
	scanner.Verbose = *verbose
	scanner.Log = logger

	result, err := scanner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Detect file signatures in corruption gaps
	var gapSigs []rescue.GapSignature
	if len(result.CorruptionGaps) > 0 {
		datFile, err := os.Open(datPath)
		if err == nil {
			gapSigs = rescue.DetectSignaturesInGaps(datFile, result.CorruptionGaps)
			datFile.Close()
		}
	}

	if *jsonOutput {
		if err := rescue.PrintJSON(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		rescue.PrintReport(os.Stdout, result, *verbose, gapSigs)
	}

	// Rebuild .idx if requested
	if *rebuildIdx {
		idxOutPath := datPath[:len(datPath)-4] + ".idx"
		count, err := rescue.RebuildIdx(datPath, result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error rebuilding idx: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Rebuilt %s with %d entries\n", idxOutPath, count)
	}

	// Extract valid data if requested
	if *extractPath != "" && !*repair {
		count, err := rescue.ExtractValidNeedles(datPath, result, *extractPath, *includeCorrupted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting: %v\n", err)
			os.Exit(1)
		}
		idxOutPath := (*extractPath)[:len(*extractPath)-4] + ".idx"
		fmt.Fprintf(os.Stderr, "\nExtracted %d valid needles to %s (idx: %s)\n", count, *extractPath, idxOutPath)
	}

	// Repair: dry-run or actual
	if *repair && *dryRun {
		repairs, err := rescue.DryRunRepair(datPath, result, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during dry-run: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\nDry-run complete: %d of %d corrupted needles are repairable\n",
			repairs.Repairable, repairs.Total)
		for _, rr := range repairs.Results {
			if rr.Repaired {
				fmt.Fprintf(os.Stderr, "  needle id=%-10d byte %d: 0x%02X -> 0x%02X (fixable)\n",
					rr.NeedleId, rr.ByteOffset, rr.OrigByte, rr.FixedByte)
			} else if rr.MultiErrors {
				fmt.Fprintf(os.Stderr, "  needle id=%-10d multi-byte corruption (not fixable)\n", rr.NeedleId)
			}
		}
	} else if *repair && *extractPath != "" {
		extracted, repaired, err := rescue.RepairAndExtract(datPath, result, *extractPath, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during repair+extract: %v\n", err)
			os.Exit(1)
		}
		idxOutPath := (*extractPath)[:len(*extractPath)-4] + ".idx"
		fmt.Fprintf(os.Stderr, "\nRepaired %d needles, extracted %d total to %s (idx: %s)\n", repaired, extracted, *extractPath, idxOutPath)
	}

	// Verify output if requested
	if *verify && *extractPath != "" {
		vr, idxIssues, err := rescue.VerifyExtractedVolume(*extractPath, result, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during verification: %v\n", err)
			os.Exit(1)
		}
		rescue.PrintVerifyReport(os.Stdout, vr)
		if len(idxIssues) > 0 {
			fmt.Fprintf(os.Stdout, "\n--- IDX Consistency Issues ---\n")
			for _, issue := range idxIssues {
				fmt.Fprintf(os.Stdout, "  %s\n", issue)
			}
		}
		if vr.Regression || len(vr.NeedlesCorrupt) > 0 {
			os.Exit(3)
		}

		// Replace original with recovered if requested and verification passed
		if *replace && vr.Clean && !vr.Regression && len(vr.NeedlesCorrupt) == 0 && len(vr.NeedlesMissing) == 0 {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "=== Replace Original Volume ===\n")
			fmt.Fprintf(os.Stderr, "This will:\n")
			fmt.Fprintf(os.Stderr, "  1. Back up original files with .bak extension\n")
			fmt.Fprintf(os.Stderr, "  2. Replace %s with %s\n", datPath, *extractPath)
			idxOrig := datPath[:len(datPath)-4] + ".idx"
			idxRecov := (*extractPath)[:len(*extractPath)-4] + ".idx"
			fmt.Fprintf(os.Stderr, "  3. Replace %s with %s\n", idxOrig, idxRecov)
			fmt.Fprintf(os.Stderr, "\n")

			if *force {
				fmt.Fprintf(os.Stderr, "Proceeding (--force)...\n")
			} else {
				fmt.Fprintf(os.Stderr, "Type 'yes' to confirm replacement: ")
				reader := bufio.NewReader(os.Stdin)
				answer, _ := reader.ReadString('\n')
				answer = strings.TrimSpace(answer)
				if answer != "yes" {
					fmt.Fprintf(os.Stderr, "Aborted. Original files unchanged.\n")
					os.Exit(0)
				}
			}

			if err := rescue.ReplaceOriginal(datPath, *extractPath, logger); err != nil {
				fmt.Fprintf(os.Stderr, "Error during replacement: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\nReplacement complete. Original volume has been replaced with the recovered version.\n")
			fmt.Fprintf(os.Stderr, "Backups: %s.bak, %s.bak\n", datPath, idxOrig)
		} else if *replace && !(vr.Clean && !vr.Regression && len(vr.NeedlesCorrupt) == 0 && len(vr.NeedlesMissing) == 0) {
			fmt.Fprintf(os.Stderr, "\nSkipping replacement: verification did not pass with SAFE TO USE verdict.\n")
			fmt.Fprintf(os.Stderr, "The recovered files are still available at: %s\n", *extractPath)
		}
	}

	// Exit with non-zero if corruption was found
	if result.Stats.CorruptedData > 0 || result.Stats.CorruptedHeader > 0 || len(result.CorruptionGaps) > 0 {
		os.Exit(2)
	}
}
