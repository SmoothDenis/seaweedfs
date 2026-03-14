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

const version = "1.0.0"

func main() {
	// --- Flags ---
	idxPath := flag.String("idx", "", "path to .idx file for cross-referencing (default: auto-detect next to .dat)")
	noIdx := flag.Bool("no-idx", false, "disable automatic .idx detection (scan .dat only, no cross-reference)")
	needleVersion := flag.Int("version", 0, "needle version: 2 or 3 (default: auto-detect from superblock)")
	rebuildIdx := flag.Bool("rebuildIdx", false, "rebuild .idx file from scan results (overwrites existing .idx)")
	extractPath := flag.String("extract", "", "extract valid needles to a new clean .dat + .idx at this path")
	deep := flag.Bool("deep", false, "enable deep scan + tail-pattern recovery for maximum data recovery (slower)")
	verbose := flag.Bool("verbose", false, "show detailed per-needle output in the report")
	jsonOutput := flag.Bool("json", false, "output scan results as JSON instead of human-readable report")
	quiet := flag.Bool("quiet", false, "suppress progress logging (only output the final report)")
	includeCorrupted := flag.Bool("include-corrupted", false, "include corrupted-data needles in --extract (data may be partially damaged)")
	repair := flag.Bool("repair", false, "attempt single-byte CRC repair on corrupted needles before extracting")
	verify := flag.Bool("verify", false, "re-scan output after --extract and show before/after comparison with verdict")
	dryRun := flag.Bool("dry-run", false, "with --repair: preview which needles can be fixed without writing files")
	replace := flag.Bool("replace", false, "after --verify passes, replace original volume with the recovered one")
	recoverReplace := flag.Bool("recover-replace", false, "recover from an interrupted --replace operation (complete or roll back)")
	force := flag.Bool("force", false, "skip confirmation prompts and overwrite existing output files")
	backupDir := flag.String("backup-dir", "", "copy original .dat and .idx to this directory before any modifications")
	showVersion := flag.Bool("V", false, "print version and exit")

	flag.Usage = func() {
		w := os.Stderr
		fmt.Fprintf(w, `weed-rescue v%s — SeaweedFS Volume Recovery Tool

USAGE
  weed-rescue [flags] <volume.dat>

DESCRIPTION
  Scans a SeaweedFS volume .dat file and recovers data from corrupted volumes.
  Supports needle versions 2 and 3 with CRC32-C validation. The source .dat
  file is NEVER modified — all operations produce new files.

SAFETY GUARANTEES
  • Source .dat is opened read-only and never written to
  • All output files use atomic writes (temp + fsync + rename)
  • Exclusive file lock prevents concurrent rescue operations
  • --backup-dir creates a full copy + SHA-256 verification before proceeding
  • --verify re-scans the output and compares it needle-by-needle
  • --replace requires --verify to pass before touching originals

SCAN MODES
  Basic scan (default):
    Sequential scan of the .dat file, validating each needle header and CRC.
    Reports valid, deleted, and corrupted needles with corruption gaps.

  Deep scan (--deep):
    After basic scan, re-scans corruption gaps byte-by-byte looking for
    valid needles with corrupted/overwritten headers. Also performs V3
    tail-pattern recovery using timestamp heuristics.

  With .idx cross-reference (--idx):
    Uses the .idx file as a guide for phase 1 validation, improving
    accuracy and detecting offset mismatches.

RECOVERY PIPELINE
  The recommended full recovery pipeline is:

    1. BACKUP     --backup-dir /safe/path (copy + SHA-256 verify)
    2. SCAN       (automatic, always runs first)
    3. REPAIR     --repair (attempts single-byte CRC fix)
    4. EXTRACT    --extract recovered.dat (writes clean volume)
    5. VERIFY     --verify (re-scans output, compares before/after)
    6. REPLACE    --replace (swaps original with recovered)

  All steps can be combined in a single command:
    weed-rescue --backup-dir /backup --deep --repair \
      --extract /tmp/recovered.dat --verify --replace volume.dat

FLAGS
`, version)
		flag.PrintDefaults()
		fmt.Fprintf(w, `
EXIT CODES
  0   Volume is healthy, no corruption found
  1   Usage error, invalid flags, or pre-flight failure
  2   Corruption detected in source volume
  3   Verification failed: output has regressions (DO NOT USE output)

EXAMPLES
  # Quick health check — just scan and report
  weed-rescue /data/volumes/42.dat

  # Scan with .idx cross-reference for better accuracy
  weed-rescue --idx /data/volumes/42.idx /data/volumes/42.dat

  # Full recovery: backup + deep scan + repair + extract + verify
  weed-rescue --backup-dir /backup/vol42 --deep --repair \
    --extract /tmp/42_recovered.dat --verify /data/volumes/42.dat

  # Preview repairs without writing anything
  weed-rescue --repair --dry-run /data/volumes/42.dat

  # Full automated recovery with replacement (no prompts)
  weed-rescue --backup-dir /backup/vol42 --deep --repair \
    --extract /tmp/42_recovered.dat --verify --replace --force \
    /data/volumes/42.dat

  # Extract only valid needles (skip corrupted), verify output
  weed-rescue --extract /tmp/clean.dat --verify /data/volumes/42.dat

  # Include corrupted needles in extract (partial data, no repair)
  weed-rescue --extract /tmp/all.dat --include-corrupted /data/volumes/42.dat

  # Rebuild .idx from what's found in the .dat
  weed-rescue --rebuildIdx /data/volumes/42.dat

  # JSON output for scripting
  weed-rescue --json /data/volumes/42.dat

BUILD
  # Linux (amd64)
  GOOS=linux GOARCH=amd64 go build -o weed-rescue ./cmd/rescue

  # Linux (arm64)
  GOOS=linux GOARCH=arm64 go build -o weed-rescue ./cmd/rescue

  # macOS (Apple Silicon)
  GOOS=darwin GOARCH=arm64 go build -o weed-rescue ./cmd/rescue

  # macOS (Intel)
  GOOS=darwin GOARCH=amd64 go build -o weed-rescue ./cmd/rescue

  # Windows
  GOOS=windows GOARCH=amd64 go build -o weed-rescue.exe ./cmd/rescue

  # FreeBSD
  GOOS=freebsd GOARCH=amd64 go build -o weed-rescue ./cmd/rescue

`)
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("weed-rescue v%s\n", version)
		os.Exit(0)
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	datPath := flag.Arg(0)

	// --- Auto-detect .idx file ---
	if *idxPath == "" && !*noIdx && len(datPath) > 4 && datPath[len(datPath)-4:] == ".dat" {
		candidate := datPath[:len(datPath)-4] + ".idx"
		if _, err := os.Stat(candidate); err == nil {
			*idxPath = candidate
			if !*quiet {
				fmt.Fprintf(os.Stderr, "Auto-detected .idx: %s (use --no-idx to disable)\n", candidate)
			}
		}
	}

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
	if *needleVersion != 0 && (*needleVersion < 2 || *needleVersion > 3) {
		errors = append(errors, fmt.Sprintf("--version must be 2 or 3, got %d", *needleVersion))
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

	// --- Recover interrupted replace if requested ---
	if *recoverReplace {
		warning := rescue.CheckInterruptedReplace(datPath)
		if warning == "" {
			fmt.Fprintf(os.Stderr, "No interrupted replace found for %s\n", datPath)
			os.Exit(0)
		}
		if err := rescue.RecoverInterruptedReplace(datPath, logger); err != nil {
			fmt.Fprintf(os.Stderr, "Error recovering interrupted replace: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Interrupted replace recovered successfully.\n")
		os.Exit(0)
	}

	// Check for interrupted replace and warn
	if warning := rescue.CheckInterruptedReplace(datPath); warning != "" {
		fmt.Fprintf(os.Stderr, "%s\n", warning)
		os.Exit(1)
	}

	// --- Step 1: Backup original if --backup-dir specified ---
	if *backupDir != "" {
		if logger != nil {
			logger("=== Step 1/6: Backup ===")
		}
		bakDat, bakIdx, err := rescue.BackupVolume(datPath, *backupDir, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating backup: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Backup complete:\n")
		fmt.Fprintf(os.Stderr, "  .dat: %s\n", bakDat)
		if bakIdx != "" {
			fmt.Fprintf(os.Stderr, "  .idx: %s\n", bakIdx)
		}

		// Verify backup integrity via SHA-256
		if logger != nil {
			logger("backup: verifying SHA-256 checksums...")
		}
		if err := rescue.VerifyBackup(datPath, bakDat, logger); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: backup verification failed for .dat: %v\n", err)
			fmt.Fprintf(os.Stderr, "Aborting — backup is not a faithful copy. Will not proceed.\n")
			os.Exit(1)
		}
		if bakIdx != "" {
			idxPath := datPath[:len(datPath)-4] + ".idx"
			if err := rescue.VerifyBackup(idxPath, bakIdx, logger); err != nil {
				fmt.Fprintf(os.Stderr, "FATAL: backup verification failed for .idx: %v\n", err)
				fmt.Fprintf(os.Stderr, "Aborting — backup is not a faithful copy. Will not proceed.\n")
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Backup verified: SHA-256 checksums match.\n\n")
	}

	// --- Step 2: Scan ---
	if logger != nil {
		logger("=== Step 2/6: Scan ===")
	}

	scanner := rescue.NewScanner(datPath)
	scanner.IdxPath = *idxPath
	scanner.Version = *needleVersion
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

	// --- Step 3: Rebuild .idx if requested ---
	if *rebuildIdx {
		idxOutPath := datPath[:len(datPath)-4] + ".idx"
		count, err := rescue.RebuildIdx(datPath, result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error rebuilding idx: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Rebuilt %s with %d entries\n", idxOutPath, count)
	}

	// --- Step 4: Repair + Extract ---
	if *extractPath != "" && !*repair {
		if logger != nil {
			logger("=== Step 4/6: Extract ===")
		}
		count, err := rescue.ExtractValidNeedles(datPath, result, *extractPath, *includeCorrupted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting: %v\n", err)
			os.Exit(1)
		}
		idxOutPath := (*extractPath)[:len(*extractPath)-4] + ".idx"
		fmt.Fprintf(os.Stderr, "\nExtracted %d valid needles to %s (idx: %s)\n", count, *extractPath, idxOutPath)
	}

	if *repair && *dryRun {
		if logger != nil {
			logger("=== Step 4/6: Repair (dry-run) ===")
		}
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
			} else if rr.Ambiguous {
				fmt.Fprintf(os.Stderr, "  needle id=%-10d %d possible fixes (CRC collision, unsafe)\n", rr.NeedleId, rr.AmbiguousCount)
			} else if rr.MultiErrors {
				fmt.Fprintf(os.Stderr, "  needle id=%-10d multi-byte corruption (not fixable)\n", rr.NeedleId)
			}
		}
	} else if *repair && *extractPath != "" {
		if logger != nil {
			logger("=== Step 4/6: Repair + Extract ===")
		}
		extracted, repaired, err := rescue.RepairAndExtract(datPath, result, *extractPath, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during repair+extract: %v\n", err)
			os.Exit(1)
		}
		idxOutPath := (*extractPath)[:len(*extractPath)-4] + ".idx"
		fmt.Fprintf(os.Stderr, "\nRepaired %d needles, extracted %d total to %s (idx: %s)\n", repaired, extracted, *extractPath, idxOutPath)
	}

	// --- Step 5: Verify ---
	if *verify && *extractPath != "" {
		if logger != nil {
			logger("=== Step 5/6: Verify ===")
		}
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

		// --- Step 6: Replace ---
		if *replace && vr.Clean && !vr.Regression && len(vr.NeedlesCorrupt) == 0 && len(vr.NeedlesMissing) == 0 {
			if logger != nil {
				logger("=== Step 6/6: Replace ===")
			}
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "=== Replace Original Volume ===\n")
			fmt.Fprintf(os.Stderr, "This will:\n")
			fmt.Fprintf(os.Stderr, "  1. Back up original files with .bak extension\n")
			fmt.Fprintf(os.Stderr, "  2. Replace %s with %s\n", datPath, *extractPath)
			idxOrig := datPath[:len(datPath)-4] + ".idx"
			idxRecov := (*extractPath)[:len(*extractPath)-4] + ".idx"
			fmt.Fprintf(os.Stderr, "  3. Replace %s with %s\n", idxOrig, idxRecov)
			if *backupDir != "" {
				fmt.Fprintf(os.Stderr, "\n  (Full backup already saved to %s)\n", *backupDir)
			}
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
