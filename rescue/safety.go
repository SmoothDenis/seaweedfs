package rescue

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// SafeWriter implements atomic file writes via temp file + fsync + rename.
// If the process crashes mid-write, the target file is never corrupted —
// either the old file remains intact, or the new complete file replaces it.
type SafeWriter struct {
	targetPath string
	tempPath   string
	tempFile   *os.File
}

// NewSafeWriter creates a temp file in the same directory as targetPath.
// Writes go to the temp file; call Commit() to atomically replace target.
func NewSafeWriter(targetPath string) (*SafeWriter, error) {
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)

	// Create temp file in same dir (required for atomic rename on same filesystem)
	tempFile, err := os.CreateTemp(dir, ".rescue-"+base+"-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temp file in %s: %w", dir, err)
	}

	return &SafeWriter{
		targetPath: targetPath,
		tempPath:   tempFile.Name(),
		tempFile:   tempFile,
	}, nil
}

// File returns the underlying *os.File for writing.
func (sw *SafeWriter) File() *os.File {
	return sw.tempFile
}

// Commit flushes all data to disk (fsync), closes the temp file,
// and atomically renames it to the target path.
// If any step fails, the temp file is cleaned up and the target is untouched.
func (sw *SafeWriter) Commit() error {
	// Fsync to ensure data is on disk, not just in page cache
	if err := sw.tempFile.Sync(); err != nil {
		sw.Abort()
		return fmt.Errorf("fsync temp file: %w", err)
	}

	if err := sw.tempFile.Close(); err != nil {
		sw.cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic rename: either fully replaces target or fails
	if err := os.Rename(sw.tempPath, sw.targetPath); err != nil {
		sw.cleanup()
		return fmt.Errorf("rename %s -> %s: %w", sw.tempPath, sw.targetPath, err)
	}

	return nil
}

// Abort closes and removes the temp file without touching the target.
func (sw *SafeWriter) Abort() {
	sw.tempFile.Close()
	sw.cleanup()
}

func (sw *SafeWriter) cleanup() {
	os.Remove(sw.tempPath)
}

// LockFile acquires an exclusive advisory lock (flock) on a file.
// Returns the lock file handle — caller must defer Unlock().
// This prevents two rescue processes from operating on the same volume simultaneously.
func LockFile(datPath string) (*os.File, error) {
	lockPath := datPath + ".rescue-lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("create lock file %s: %w", lockPath, err)
	}

	// Try non-blocking exclusive lock
	err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("another weed-rescue process is already running on %s (lock file: %s)", datPath, lockPath)
	}

	// Write PID for debugging
	lockFile.Truncate(0)
	lockFile.Seek(0, 0)
	fmt.Fprintf(lockFile, "%d\n", os.Getpid())
	lockFile.Sync()

	return lockFile, nil
}

// UnlockFile releases the lock and removes the lock file.
func UnlockFile(lockFile *os.File) {
	if lockFile == nil {
		return
	}
	lockPath := lockFile.Name()
	syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	lockFile.Close()
	os.Remove(lockPath)
}

// BackupVolume copies the original .dat and .idx files to the specified backup directory.
// The backup directory is created if it doesn't exist.
// Returns paths to the backed-up files.
func BackupVolume(datPath string, backupDir string, log Logger) (bakDat string, bakIdx string, err error) {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", "", fmt.Errorf("create backup directory %s: %w", backupDir, err)
	}

	baseDat := filepath.Base(datPath)
	baseIdx := baseDat[:len(baseDat)-4] + ".idx"
	idxPath := datPath[:len(datPath)-4] + ".idx"

	bakDat = filepath.Join(backupDir, baseDat)
	bakIdx = filepath.Join(backupDir, baseIdx)

	// Check backup files don't already exist
	if _, err := os.Stat(bakDat); err == nil {
		return "", "", fmt.Errorf("backup already exists: %s (remove it first)", bakDat)
	}
	if _, err := os.Stat(bakIdx); err == nil {
		return "", "", fmt.Errorf("backup already exists: %s (remove it first)", bakIdx)
	}

	// Copy .dat
	if log != nil {
		log("backup: copying %s -> %s", datPath, bakDat)
	}
	if err := copyFile(datPath, bakDat); err != nil {
		return "", "", fmt.Errorf("backup .dat: %w", err)
	}

	// Copy .idx if it exists
	if _, statErr := os.Stat(idxPath); statErr == nil {
		if log != nil {
			log("backup: copying %s -> %s", idxPath, bakIdx)
		}
		if err := copyFile(idxPath, bakIdx); err != nil {
			os.Remove(bakDat) // rollback
			return "", "", fmt.Errorf("backup .idx: %w", err)
		}
	} else {
		bakIdx = "" // no idx to backup
	}

	if log != nil {
		log("backup: done")
	}
	return bakDat, bakIdx, nil
}

// copyFile copies src to dst using atomic write (temp + fsync + rename).
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	sw, err := NewSafeWriter(dst)
	if err != nil {
		return err
	}

	if _, err := io.Copy(sw.File(), srcFile); err != nil {
		sw.Abort()
		return err
	}

	return sw.Commit()
}

// VerifyBackup compares SHA-256 checksums of the original and backup files.
// Returns nil if they match, or an error describing the mismatch.
func VerifyBackup(originalPath, backupPath string, log Logger) error {
	if log != nil {
		log("verify-backup: computing SHA-256 of %s", originalPath)
	}
	origHash, err := sha256File(originalPath)
	if err != nil {
		return fmt.Errorf("hash original %s: %w", originalPath, err)
	}

	if log != nil {
		log("verify-backup: computing SHA-256 of %s", backupPath)
	}
	bakHash, err := sha256File(backupPath)
	if err != nil {
		return fmt.Errorf("hash backup %s: %w", backupPath, err)
	}

	if origHash != bakHash {
		return fmt.Errorf("SHA-256 mismatch: original=%s backup=%s — backup is corrupted", origHash, bakHash)
	}

	if log != nil {
		log("verify-backup: OK — SHA-256 match: %s", origHash)
	}
	return nil
}

// sha256File computes the SHA-256 hash of a file and returns it as a hex string.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ReplaceOriginal backs up the original .dat and .idx, then atomically replaces them
// with the recovered versions. Backup files get a .bak extension.
// If any step fails, all changes are rolled back.
func ReplaceOriginal(originalDatPath, recoveredDatPath string, log Logger) error {
	originalIdxPath := originalDatPath[:len(originalDatPath)-4] + ".idx"
	recoveredIdxPath := recoveredDatPath[:len(recoveredDatPath)-4] + ".idx"

	bakDatPath := originalDatPath + ".bak"
	bakIdxPath := originalIdxPath + ".bak"

	// Verify recovered files exist
	if _, err := os.Stat(recoveredDatPath); err != nil {
		return fmt.Errorf("recovered .dat not found: %s", recoveredDatPath)
	}
	if _, err := os.Stat(recoveredIdxPath); err != nil {
		return fmt.Errorf("recovered .idx not found: %s", recoveredIdxPath)
	}

	// Check backup paths don't already exist (don't overwrite previous backups)
	if _, err := os.Stat(bakDatPath); err == nil {
		return fmt.Errorf("backup already exists: %s (remove it first or use a different path)", bakDatPath)
	}
	if _, err := os.Stat(bakIdxPath); err == nil {
		return fmt.Errorf("backup already exists: %s (remove it first or use a different path)", bakIdxPath)
	}

	// Write marker file so a crashed replace can be diagnosed/recovered
	markerPath := originalDatPath + ".rescue-replace-in-progress"
	markerContent := fmt.Sprintf("original_dat=%s\noriginal_idx=%s\nrecovered_dat=%s\nrecovered_idx=%s\nbak_dat=%s\nbak_idx=%s\n",
		originalDatPath, originalIdxPath, recoveredDatPath, recoveredIdxPath, bakDatPath, bakIdxPath)
	if err := os.WriteFile(markerPath, []byte(markerContent), 0644); err != nil {
		return fmt.Errorf("write replace marker: %w", err)
	}

	if log != nil {
		log("replace: backing up %s -> %s", originalDatPath, bakDatPath)
	}

	// Step 1: Rename original .dat to .bak
	if err := os.Rename(originalDatPath, bakDatPath); err != nil {
		os.Remove(markerPath)
		return fmt.Errorf("backup original .dat: %w", err)
	}

	// Step 2: Rename original .idx to .bak
	if _, err := os.Stat(originalIdxPath); err == nil {
		if log != nil {
			log("replace: backing up %s -> %s", originalIdxPath, bakIdxPath)
		}
		if err := os.Rename(originalIdxPath, bakIdxPath); err != nil {
			// Rollback: restore .dat
			os.Rename(bakDatPath, originalDatPath)
			os.Remove(markerPath)
			return fmt.Errorf("backup original .idx (dat restored): %w", err)
		}
	}

	if log != nil {
		log("replace: moving recovered files into place")
	}

	// Step 3: Rename recovered .dat to original path
	if err := os.Rename(recoveredDatPath, originalDatPath); err != nil {
		// Rollback: restore both originals
		os.Rename(bakDatPath, originalDatPath)
		os.Rename(bakIdxPath, originalIdxPath)
		os.Remove(markerPath)
		return fmt.Errorf("move recovered .dat into place (originals restored): %w", err)
	}

	// Step 4: Rename recovered .idx to original path
	if err := os.Rename(recoveredIdxPath, originalIdxPath); err != nil {
		// Rollback: restore .dat from backup, move recovered .dat back
		os.Rename(originalDatPath, recoveredDatPath)
		os.Rename(bakDatPath, originalDatPath)
		os.Rename(bakIdxPath, originalIdxPath)
		os.Remove(markerPath)
		return fmt.Errorf("move recovered .idx into place (originals restored): %w", err)
	}

	// Success — remove marker
	os.Remove(markerPath)

	if log != nil {
		log("replace: done — originals backed up as .bak")
		log("replace:   %s", bakDatPath)
		log("replace:   %s", bakIdxPath)
	}

	return nil
}

// CheckInterruptedReplace checks if a previous replace operation was interrupted.
// Returns a description of the state if found, or empty string if clean.
func CheckInterruptedReplace(datPath string) string {
	markerPath := datPath + ".rescue-replace-in-progress"
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return "" // no marker = clean
	}
	return fmt.Sprintf("WARNING: interrupted replace detected (marker: %s)\nContents:\n%s\n"+
		"The previous rescue --replace was interrupted.\n"+
		"Use --recover-replace to automatically complete or roll back the operation.\n"+
		"Or remove %s after resolving manually.", markerPath, string(data), markerPath)
}

// parseMarkerFile parses the .rescue-replace-in-progress marker file into a map.
func parseMarkerFile(data []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

// RecoverInterruptedReplace detects the state of an interrupted replace operation
// and either completes it or rolls it back, depending on which steps had finished.
//
// The replace operation has 4 steps (see ReplaceOriginal):
//  1. Rename original .dat → .bak
//  2. Rename original .idx → .bak
//  3. Rename recovered .dat → original path
//  4. Rename recovered .idx → original path
//
// This function inspects which files exist to determine how far the operation got,
// then either completes the remaining steps or rolls back the completed ones.
func RecoverInterruptedReplace(datPath string, log Logger) error {
	markerPath := datPath + ".rescue-replace-in-progress"
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return fmt.Errorf("no interrupted replace found (no marker at %s)", markerPath)
	}

	paths := parseMarkerFile(data)
	origDat := paths["original_dat"]
	origIdx := paths["original_idx"]
	recDat := paths["recovered_dat"]
	recIdx := paths["recovered_idx"]
	bakDat := paths["bak_dat"]
	bakIdx := paths["bak_idx"]

	if origDat == "" || origIdx == "" || bakDat == "" || bakIdx == "" {
		return fmt.Errorf("marker file is incomplete, cannot auto-recover: %s", markerPath)
	}

	// Check which files exist to determine state
	origDatExists := fileExists(origDat)
	origIdxExists := fileExists(origIdx)
	bakDatExists := fileExists(bakDat)
	bakIdxExists := fileExists(bakIdx)
	recDatExists := fileExists(recDat)
	recIdxExists := fileExists(recIdx)

	if log != nil {
		log("recover-replace: analyzing state...")
		log("  original .dat (%s): exists=%v", origDat, origDatExists)
		log("  original .idx (%s): exists=%v", origIdx, origIdxExists)
		log("  backup .dat   (%s): exists=%v", bakDat, bakDatExists)
		log("  backup .idx   (%s): exists=%v", bakIdx, bakIdxExists)
		log("  recovered .dat (%s): exists=%v", recDat, recDatExists)
		log("  recovered .idx (%s): exists=%v", recIdx, recIdxExists)
	}

	switch {
	case origDatExists && origIdxExists && !bakDatExists && !bakIdxExists:
		// State: replacement never started. Just remove the marker.
		if log != nil {
			log("recover-replace: replacement never started, removing stale marker")
		}

	case !origDatExists && bakDatExists && origIdxExists && !bakIdxExists:
		// State: only step 1 completed (dat renamed to bak). Roll back.
		if log != nil {
			log("recover-replace: step 1 completed, rolling back .dat rename")
		}
		if err := os.Rename(bakDat, origDat); err != nil {
			return fmt.Errorf("rollback: rename %s -> %s: %w", bakDat, origDat, err)
		}

	case !origDatExists && !origIdxExists && bakDatExists && bakIdxExists && recDatExists && recIdxExists:
		// State: steps 1-2 completed (both originals backed up, recovered files exist).
		// Complete steps 3-4: move recovered files into place.
		if log != nil {
			log("recover-replace: steps 1-2 completed, completing steps 3-4")
		}
		if err := os.Rename(recDat, origDat); err != nil {
			return fmt.Errorf("complete: rename %s -> %s: %w", recDat, origDat, err)
		}
		if err := os.Rename(recIdx, origIdx); err != nil {
			return fmt.Errorf("complete: rename %s -> %s: %w", recIdx, origIdx, err)
		}

	case origDatExists && !origIdxExists && bakDatExists && bakIdxExists && !recDatExists:
		// State: steps 1-3 completed (recovered .dat moved to original, .idx not yet).
		// Complete step 4.
		if log != nil {
			log("recover-replace: steps 1-3 completed, completing step 4")
		}
		if recIdxExists {
			if err := os.Rename(recIdx, origIdx); err != nil {
				return fmt.Errorf("complete: rename %s -> %s: %w", recIdx, origIdx, err)
			}
		} else {
			// recovered .idx also gone — restore from backup
			if log != nil {
				log("recover-replace: recovered .idx missing, restoring .idx from backup")
			}
			if err := os.Rename(bakIdx, origIdx); err != nil {
				return fmt.Errorf("rollback: rename %s -> %s: %w", bakIdx, origIdx, err)
			}
		}

	case origDatExists && origIdxExists && bakDatExists && bakIdxExists:
		// State: all steps completed. Just clean up.
		if log != nil {
			log("recover-replace: replacement fully completed, removing stale marker")
		}

	default:
		return fmt.Errorf("unrecognized state — cannot auto-recover.\n"+
			"  original .dat exists=%v, .idx exists=%v\n"+
			"  backup .dat exists=%v, .idx exists=%v\n"+
			"  recovered .dat exists=%v, .idx exists=%v\n"+
			"  Please resolve manually and remove %s",
			origDatExists, origIdxExists, bakDatExists, bakIdxExists, recDatExists, recIdxExists, markerPath)
	}

	// Remove the marker file
	if err := os.Remove(markerPath); err != nil {
		return fmt.Errorf("remove marker file: %w", err)
	}
	if log != nil {
		log("recover-replace: done — marker removed")
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// PreFlightChecks validates that the environment is ready for a rescue operation.
// Returns a list of issues. Empty list = all good.
func PreFlightChecks(datPath string, extractPath string, force ...bool) []string {
	skipExistsCheck := len(force) > 0 && force[0]
	var issues []string

	// Check source is readable
	srcFile, err := os.Open(datPath)
	if err != nil {
		issues = append(issues, fmt.Sprintf("cannot read source: %v", err))
		return issues // no point continuing
	}
	srcStat, err := srcFile.Stat()
	srcFile.Close()
	if err != nil {
		issues = append(issues, fmt.Sprintf("cannot stat source: %v", err))
		return issues
	}

	if srcStat.Size() < SuperBlockSize {
		issues = append(issues, fmt.Sprintf("source file too small (%d bytes, need at least %d)", srcStat.Size(), SuperBlockSize))
	}

	// Check output directory exists and is writable
	if extractPath != "" {
		outDir := filepath.Dir(extractPath)
		dirStat, err := os.Stat(outDir)
		if err != nil {
			issues = append(issues, fmt.Sprintf("output directory does not exist: %s", outDir))
		} else if !dirStat.IsDir() {
			issues = append(issues, fmt.Sprintf("output path parent is not a directory: %s", outDir))
		} else {
			// Check writable by creating a temp file
			testFile, err := os.CreateTemp(outDir, ".rescue-writetest-*")
			if err != nil {
				issues = append(issues, fmt.Sprintf("output directory not writable: %s (%v)", outDir, err))
			} else {
				testPath := testFile.Name()
				testFile.Close()
				os.Remove(testPath)
			}
		}

		// Check disk space: need at least source file size for the output
		var statfs syscall.Statfs_t
		if err := syscall.Statfs(outDir, &statfs); err == nil {
			availableBytes := int64(statfs.Bavail) * int64(statfs.Bsize)
			if availableBytes < srcStat.Size() {
				issues = append(issues, fmt.Sprintf("insufficient disk space: need %s, available %s",
					humanSize(srcStat.Size()), humanSize(availableBytes)))
			}
		}

		// Check output file does not already exist (safety: don't overwrite unexpected files)
		if !skipExistsCheck {
			if _, err := os.Stat(extractPath); err == nil {
				issues = append(issues, fmt.Sprintf("output file already exists: %s (use --force to overwrite, or choose a different path)", extractPath))
			}
			idxOutPath := extractPath[:len(extractPath)-4] + ".idx"
			if _, err := os.Stat(idxOutPath); err == nil {
				issues = append(issues, fmt.Sprintf("output idx already exists: %s (use --force to overwrite, or choose a different path)", idxOutPath))
			}
		}
	}

	return issues
}
