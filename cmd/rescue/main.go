package main

import (
	"flag"
	"fmt"
	"os"

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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: weed-rescue [flags] <path-to-dat-file>\n\n")
		fmt.Fprintf(os.Stderr, "Scans a SeaweedFS volume .dat file for valid and corrupted needles.\n")
		fmt.Fprintf(os.Stderr, "Can recover data from corrupted volumes using CRC32 validation.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	datPath := flag.Arg(0)

	scanner := rescue.NewScanner(datPath)
	scanner.IdxPath = *idxPath
	scanner.Version = *version
	scanner.DeepScan = *deep
	scanner.Verbose = *verbose

	result, err := scanner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		if err := rescue.PrintJSON(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		rescue.PrintReport(os.Stdout, result, *verbose)
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
	if *extractPath != "" {
		count, err := rescue.ExtractValidNeedles(datPath, result, *extractPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting: %v\n", err)
			os.Exit(1)
		}
		idxOutPath := (*extractPath)[:len(*extractPath)-4] + ".idx"
		fmt.Fprintf(os.Stderr, "\nExtracted %d valid needles to %s (idx: %s)\n", count, *extractPath, idxOutPath)
	}

	// Exit with non-zero if corruption was found
	if result.Stats.CorruptedData > 0 || result.Stats.CorruptedHeader > 0 || len(result.CorruptionGaps) > 0 {
		os.Exit(2)
	}
}
