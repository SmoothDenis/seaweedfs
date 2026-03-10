package rescue

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	if log != nil {
		log("replace: backing up %s -> %s", originalDatPath, bakDatPath)
	}

	// Step 1: Rename original .dat to .bak
	if err := os.Rename(originalDatPath, bakDatPath); err != nil {
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
		return fmt.Errorf("move recovered .dat into place (originals restored): %w", err)
	}

	// Step 4: Rename recovered .idx to original path
	if err := os.Rename(recoveredIdxPath, originalIdxPath); err != nil {
		// Rollback: restore .dat from backup, move recovered .dat back
		os.Rename(originalDatPath, recoveredDatPath)
		os.Rename(bakDatPath, originalDatPath)
		os.Rename(bakIdxPath, originalIdxPath)
		return fmt.Errorf("move recovered .idx into place (originals restored): %w", err)
	}

	if log != nil {
		log("replace: done — originals backed up as .bak")
		log("replace:   %s", bakDatPath)
		log("replace:   %s", bakIdxPath)
	}

	return nil
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
