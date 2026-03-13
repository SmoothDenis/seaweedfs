# weed-rescue — SeaweedFS Volume Recovery Tool

Standalone tool for scanning, diagnosing, and recovering corrupted SeaweedFS volume `.dat` files.

## Features

- **Non-destructive scan** — source `.dat` is opened read-only, never modified
- **Deep scan** — recovers needles from corruption gaps via byte-by-byte scanning and V3 tail-pattern heuristics
- **CRC repair** — fixes single-byte bit-rot corruption by brute-forcing the correct byte value
- **Atomic writes** — all output uses temp + fsync + rename to prevent partial files on crash
- **Backup before modify** — `--backup-dir` copies originals before any operation
- **Verification** — re-scans output and compares needle-by-needle with the original
- **Safe replacement** — `--replace` only works after `--verify` passes all checks
- **IDX auto-detection** — automatically finds `.idx` next to `.dat` (use `--no-idx` to disable)
- **IDX cross-reference** — uses `.idx` to show active vs tombstoned needles, confirm data integrity
- **Deletion marker detection** — correctly identifies Size=0 entries as deletion markers (not active data)
- **IDX rebuild** — reconstructs `.idx` from needles found in `.dat`
- **JSON output** — machine-readable output for scripting and monitoring
- **File lock** — prevents concurrent rescue operations on the same volume

## Build

From the repository root:

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o weed-rescue ./cmd/rescue

# Linux (arm64, e.g. AWS Graviton, Raspberry Pi 4)
GOOS=linux GOARCH=arm64 go build -o weed-rescue ./cmd/rescue

# macOS (Apple Silicon — M1/M2/M3/M4)
GOOS=darwin GOARCH=arm64 go build -o weed-rescue ./cmd/rescue

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o weed-rescue ./cmd/rescue

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o weed-rescue.exe ./cmd/rescue

# FreeBSD (amd64)
GOOS=freebsd GOARCH=amd64 go build -o weed-rescue ./cmd/rescue
```

### Build all platforms at once

```bash
for os_arch in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 freebsd/amd64; do
  IFS='/' read -r GOOS GOARCH <<< "$os_arch"
  ext="" && [ "$GOOS" = "windows" ] && ext=".exe"
  GOOS=$GOOS GOARCH=$GOARCH go build -o "weed-rescue-${GOOS}-${GOARCH}${ext}" ./cmd/rescue
done
```

## Quick Start

### 1. Health check (scan only)

```bash
weed-rescue /data/volumes/42.dat
```

Reports volume status: needle counts, corruption gaps, CRC mismatches.

### 2. Full recovery pipeline

```bash
weed-rescue \
  --backup-dir /backup/vol42 \
  --deep \
  --repair \
  --extract /tmp/42_recovered.dat \
  --verify \
  /data/volumes/42.dat
```

This runs all steps in order:
1. **Backup** — copies `42.dat` and `42.idx` to `/backup/vol42/`, then verifies SHA-256 checksums match
2. **Scan** — sequential + deep scan + tail recovery
3. **Repair** — fixes single-byte CRC corruption
4. **Extract** — writes valid + repaired needles to clean `.dat` + `.idx`
5. **Verify** — re-scans output, shows before/after comparison table with verdict

### 3. Preview repairs (no files written)

```bash
weed-rescue --repair --dry-run /data/volumes/42.dat
```

Shows which corrupted needles can be fixed and the exact byte changes.

### 4. Full automated recovery with replacement

```bash
weed-rescue \
  --backup-dir /backup/vol42 \
  --deep \
  --repair \
  --extract /tmp/42_recovered.dat \
  --verify \
  --replace \
  --force \
  /data/volumes/42.dat
```

Same as #2, but also replaces the original files if verification passes. `--force` skips the confirmation prompt.

## Understanding the Output

### Needle types in the report

| Type | Size field | Meaning |
|------|-----------|---------|
| **Valid** | > 0 | Active needle with intact data and valid CRC |
| **Deletion marker** | = 0 | Written when SeaweedFS deletes a needle (no data, just a marker) |
| **Deleted** | < 0 | Tombstone entry (Size=-1) — rare in `.dat`, more common in `.idx` |
| **Corrupted data** | > 0 | Header readable but CRC mismatch (data damaged) |
| **Recovered** | > 0 | Found via deep scan in a corruption gap |

### Why scanner counts differ from master

The SeaweedFS master reports `file_count` (unique active NeedleIds) and `delete_count` (tombstoned NeedleIds). The scanner counts **all physical entries** in the `.dat` file, which includes:

- **Original data** for deleted needles (still intact in `.dat`, Size > 0)
- **Deletion markers** (Size=0 entries appended when needles are deleted)
- **Old versions** of updated needles (superseded but still physically present)

When `--idx` is provided (or auto-detected), the report shows an **IDX Cross-Reference** section that maps scanner results to the master's view:

```
--- IDX Cross-Reference ---
IDX entries:      379,945 active + 47 tombstoned
Confirmed in dat: 379,945 active needles matched
Orphaned in idx:  0 (idx points to missing data)
```

### IDX auto-detection

The tool automatically uses the `.idx` file next to the `.dat` file if it exists. For example, `weed-rescue /data/vol_5580.dat` will auto-detect `/data/vol_5580.idx`. Use `--no-idx` to disable this.

## Usage Reference

```
weed-rescue [flags] <volume.dat>
```

### Flags

| Flag | Description |
|---|---|
| `--idx <path>` | Path to `.idx` file for cross-referencing (default: auto-detected next to `.dat`) |
| `--no-idx` | Disable automatic `.idx` detection (scan `.dat` only) |
| `--version <2\|3>` | Force needle version (default: auto-detect from superblock) |
| `--deep` | Enable deep scan + tail-pattern recovery (slower, better recovery) |
| `--repair` | Attempt single-byte CRC repair on corrupted needles |
| `--dry-run` | With `--repair`: preview fixes without writing files |
| `--extract <path.dat>` | Extract valid needles to a new clean `.dat` + `.idx` |
| `--include-corrupted` | Include corrupted-data needles in `--extract` (partial data) |
| `--verify` | Re-scan output after `--extract` and compare with original |
| `--replace` | After `--verify` passes, replace original with recovered volume |
| `--backup-dir <dir>` | Copy original `.dat` and `.idx` here before any modifications |
| `--rebuildIdx` | Rebuild `.idx` from needles found in `.dat` |
| `--force` | Skip confirmation prompts, overwrite existing output files |
| `--verbose` | Show detailed per-needle output |
| `--json` | Output results as JSON |
| `--quiet` | Suppress progress logging |
| `-V` | Print version and exit |

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Volume is healthy, no corruption found |
| 1 | Usage error, invalid flags, or pre-flight failure |
| 2 | Corruption detected in source volume |
| 3 | Verification failed: output has regressions (DO NOT USE output) |

## Recovery Pipeline Detail

```
┌─────────────┐
│  --backup-dir│  Step 1: Copy originals + SHA-256 verify
└──────┬──────┘
       ▼
┌─────────────┐
│    SCAN      │  Step 2: Sequential scan → deep scan → tail recovery
└──────┬──────┘
       ▼
┌─────────────┐
│   --repair   │  Step 3: Single-byte CRC repair (brute-force 256 values)
└──────┬──────┘
       ▼
┌─────────────┐
│  --extract   │  Step 4: Write valid + repaired needles to new .dat + .idx
└──────┬──────┘
       ▼
┌─────────────┐
│  --verify    │  Step 5: Re-scan output, before/after comparison
└──────┬──────┘
       ▼
┌─────────────┐
│  --replace   │  Step 6: Swap original with recovered (if verify passed)
└─────────────┘
```

## How CRC Repair Works

When bit rot corrupts a single byte in a needle's data:

1. The stored CRC32-C no longer matches the computed CRC
2. `--repair` tries each byte position (0..DataSize) × each value (0..255)
3. For each candidate, it computes CRC32-C and checks against the stored value
4. If exactly one single-byte change fixes the CRC, the needle is repaired
5. Multi-byte corruption is detected and reported as "not auto-repairable"

Performance: ~2.5 billion CRC ops for a 10 MB needle (a few seconds). Needles larger than 10 MB are skipped.

## Safety Model

- **Source is never modified** — all reads are via `ReadAt` on a read-only file descriptor
- **Atomic output** — writes go to a temp file, then `fsync` + `rename`
- **File lock** — `flock(LOCK_EX|LOCK_NB)` prevents concurrent runs on the same volume
- **Pre-flight checks** — validates disk space, permissions, and existing files before starting
- **Verification** — `--verify` re-scans the output from scratch and checks every needle's CRC
- **Rollback on failure** — `--replace` rolls back all changes if any step fails mid-operation
- **Backup** — `--backup-dir` creates a byte-for-byte copy + SHA-256 verification before proceeding
