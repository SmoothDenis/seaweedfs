package rescue

import (
	"fmt"
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
