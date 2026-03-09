package rescue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeWriterAtomicCommit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "output.dat")

	sw, err := NewSafeWriter(target)
	if err != nil {
		t.Fatal(err)
	}

	// Target should NOT exist yet (writing to temp)
	if _, err := os.Stat(target); err == nil {
		t.Error("target should not exist before commit")
	}

	// Write some data
	sw.File().Write([]byte("hello world"))

	// Commit
	if err := sw.Commit(); err != nil {
		t.Fatal(err)
	}

	// Now target should exist with correct content
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Errorf("expected 'hello world', got %q", string(data))
	}
}

func TestSafeWriterAbortCleansUp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "output.dat")

	sw, err := NewSafeWriter(target)
	if err != nil {
		t.Fatal(err)
	}

	tempPath := sw.tempPath
	sw.File().Write([]byte("data that should be discarded"))

	// Abort instead of commit
	sw.Abort()

	// Target should NOT exist
	if _, err := os.Stat(target); err == nil {
		t.Error("target should not exist after abort")
	}

	// Temp file should be cleaned up
	if _, err := os.Stat(tempPath); err == nil {
		t.Error("temp file should be cleaned up after abort")
	}
}

func TestLockFilePreventsDoubleRun(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	os.WriteFile(datPath, []byte("dummy"), 0644)

	// First lock should succeed
	lock1, err := LockFile(datPath)
	if err != nil {
		t.Fatal(err)
	}

	// Second lock should fail
	_, err = LockFile(datPath)
	if err == nil {
		t.Fatal("expected second lock to fail")
	}

	// Release first lock
	UnlockFile(lock1)

	// Now third lock should succeed
	lock3, err := LockFile(datPath)
	if err != nil {
		t.Fatalf("expected lock to succeed after unlock, got: %v", err)
	}
	UnlockFile(lock3)
}

func TestPreFlightChecksHappyPath(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")

	// Create a valid minimal dat file
	f, _ := os.Create(datPath)
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)
	f.Close()

	extractPath := filepath.Join(dir, "output.dat")
	issues := PreFlightChecks(datPath, extractPath)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got: %v", issues)
	}
}

func TestPreFlightChecksOutputExists(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, _ := os.Create(datPath)
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)
	f.Close()

	extractPath := filepath.Join(dir, "output.dat")
	os.WriteFile(extractPath, []byte("existing"), 0644)

	// Without force: should report issue
	issues := PreFlightChecks(datPath, extractPath)
	if len(issues) == 0 {
		t.Error("expected issue about existing output file")
	}

	// With force: should pass
	issues = PreFlightChecks(datPath, extractPath, true)
	found := false
	for _, issue := range issues {
		if issue == "output file already exists" {
			found = true
		}
	}
	if found {
		t.Error("with force=true, should not complain about existing output")
	}
}

func TestPreFlightChecksBadSource(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "nonexistent.dat")
	issues := PreFlightChecks(datPath, "")
	if len(issues) == 0 {
		t.Error("expected issue about non-existent source")
	}
}

func TestReplaceOriginalHappyPath(t *testing.T) {
	dir := t.TempDir()

	// Create "original" files
	origDat := filepath.Join(dir, "volume.dat")
	origIdx := filepath.Join(dir, "volume.idx")
	os.WriteFile(origDat, []byte("original dat content"), 0644)
	os.WriteFile(origIdx, []byte("original idx content"), 0644)

	// Create "recovered" files
	recDat := filepath.Join(dir, "recovered.dat")
	recIdx := filepath.Join(dir, "recovered.idx")
	os.WriteFile(recDat, []byte("recovered dat content"), 0644)
	os.WriteFile(recIdx, []byte("recovered idx content"), 0644)

	err := ReplaceOriginal(origDat, recDat, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Original paths should now have recovered content
	data, _ := os.ReadFile(origDat)
	if string(data) != "recovered dat content" {
		t.Errorf("expected recovered dat, got %q", string(data))
	}
	data, _ = os.ReadFile(origIdx)
	if string(data) != "recovered idx content" {
		t.Errorf("expected recovered idx, got %q", string(data))
	}

	// Backups should have original content
	data, _ = os.ReadFile(origDat + ".bak")
	if string(data) != "original dat content" {
		t.Errorf("expected original dat in backup, got %q", string(data))
	}
	data, _ = os.ReadFile(origIdx + ".bak")
	if string(data) != "original idx content" {
		t.Errorf("expected original idx in backup, got %q", string(data))
	}

	// Recovered files should no longer exist at original paths
	if _, err := os.Stat(recDat); err == nil {
		t.Error("recovered .dat should have been moved, not copied")
	}
	if _, err := os.Stat(recIdx); err == nil {
		t.Error("recovered .idx should have been moved, not copied")
	}
}

func TestReplaceOriginalBackupExists(t *testing.T) {
	dir := t.TempDir()

	origDat := filepath.Join(dir, "volume.dat")
	os.WriteFile(origDat, []byte("original"), 0644)
	os.WriteFile(origDat+".bak", []byte("old backup"), 0644)

	recDat := filepath.Join(dir, "recovered.dat")
	recIdx := filepath.Join(dir, "recovered.idx")
	os.WriteFile(recDat, []byte("recovered"), 0644)
	os.WriteFile(recIdx, []byte("recovered idx"), 0644)

	err := ReplaceOriginal(origDat, recDat, nil)
	if err == nil {
		t.Fatal("expected error about existing backup")
	}

	// Original should be untouched
	data, _ := os.ReadFile(origDat)
	if string(data) != "original" {
		t.Error("original should be untouched when backup exists")
	}
}

func TestReplaceOriginalMissingRecovered(t *testing.T) {
	dir := t.TempDir()
	origDat := filepath.Join(dir, "volume.dat")
	os.WriteFile(origDat, []byte("original"), 0644)

	err := ReplaceOriginal(origDat, filepath.Join(dir, "nonexistent.dat"), nil)
	if err == nil {
		t.Fatal("expected error about missing recovered file")
	}
}

func TestAtomicExtractDoesNotLeavePartialFiles(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, _ := os.Create(datPath)
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)
	f.Write(buildNeedleV3(0xAA, 1, []byte("test data")))
	f.Close()

	scanner := NewScanner(datPath)
	result, _ := scanner.Run()

	// Extract to a valid path — should produce .dat + .idx atomically
	outPath := filepath.Join(dir, "output.dat")
	count, err := ExtractValidNeedles(datPath, result, outPath)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 extracted, got %d", count)
	}

	// Both files should exist
	if _, err := os.Stat(outPath); err != nil {
		t.Error("output .dat should exist")
	}
	idxPath := filepath.Join(dir, "output.idx")
	if _, err := os.Stat(idxPath); err != nil {
		t.Error("output .idx should exist")
	}

	// No temp files should remain
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
