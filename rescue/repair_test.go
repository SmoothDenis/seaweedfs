package rescue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAttemptRepairSingleByte(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	// Superblock
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)

	// Write a valid needle
	data := []byte("hello world, this is test data for repair")
	needle := buildNeedleV3(0xAA, 1, data)
	needleOffset := int64(SuperBlockSize)
	f.Write(needle)

	// Corrupt one byte in the file data (byte 5 of the actual file data)
	corruptPos := NeedleHeaderSize + 4 + 5 // header + DataSize + 5th byte
	original := needle[corruptPos]
	corrupted := original ^ 0x42
	f.WriteAt([]byte{corrupted}, needleOffset+int64(corruptPos))
	f.Close()

	// Scan to get the corrupted record
	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.CorruptedData != 1 {
		t.Fatalf("expected 1 corrupted needle, got %d", result.Stats.CorruptedData)
	}

	// Attempt repair
	datFile, _ := os.Open(datPath)
	defer datFile.Close()

	rec := result.Records[0]
	rr := AttemptRepair(datFile, rec, 3)

	if !rr.Repaired {
		t.Fatal("expected repair to succeed for single-byte corruption")
	}
	if rr.ByteOffset != 5 {
		t.Errorf("expected corrupted byte at position 5, got %d", rr.ByteOffset)
	}
	if rr.OrigByte != corrupted {
		t.Errorf("expected orig byte 0x%02X, got 0x%02X", corrupted, rr.OrigByte)
	}
	if rr.FixedByte != original {
		t.Errorf("expected fixed byte 0x%02X, got 0x%02X", original, rr.FixedByte)
	}
}

func TestAttemptRepairMultiByteFailure(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)

	data := []byte("data with multiple corruptions coming")
	needle := buildNeedleV3(0xBB, 2, data)
	needleOffset := int64(SuperBlockSize)
	f.Write(needle)

	// Corrupt TWO bytes
	pos1 := NeedleHeaderSize + 4 + 3
	pos2 := NeedleHeaderSize + 4 + 10
	f.WriteAt([]byte{0xFF}, needleOffset+int64(pos1))
	f.WriteAt([]byte{0xFE}, needleOffset+int64(pos2))
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatal(err)
	}

	datFile, _ := os.Open(datPath)
	defer datFile.Close()

	rr := AttemptRepair(datFile, result.Records[0], 3)
	if rr.Repaired {
		t.Fatal("should not repair multi-byte corruption")
	}
	if !rr.MultiErrors {
		t.Fatal("should flag multi-byte errors")
	}
}

func TestRepairAndExtract(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)

	data1 := []byte("healthy file number one")
	data2 := []byte("this file will be corrupted and repaired")
	data3 := []byte("another healthy file")

	f.Write(buildNeedleV3(0xAA, 1, data1))
	needle2Offset := int64(SuperBlockSize + len(buildNeedleV3(0xAA, 1, data1)))
	f.Write(buildNeedleV3(0xBB, 2, data2))
	f.Write(buildNeedleV3(0xCC, 3, data3))

	// Corrupt one byte in needle 2
	corruptPos := needle2Offset + int64(NeedleHeaderSize+4+8)
	f.WriteAt([]byte{0xFF}, corruptPos)
	f.Close()

	// Scan
	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.ValidNeedles != 2 {
		t.Fatalf("expected 2 valid, got %d", result.Stats.ValidNeedles)
	}
	if result.Stats.CorruptedData != 1 {
		t.Fatalf("expected 1 corrupted, got %d", result.Stats.CorruptedData)
	}

	// Repair and extract
	outPath := filepath.Join(dir, "repaired.dat")
	extracted, repaired, err := RepairAndExtract(datPath, result, outPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	if repaired != 1 {
		t.Errorf("expected 1 repaired, got %d", repaired)
	}
	if extracted != 3 {
		t.Errorf("expected 3 extracted, got %d", extracted)
	}

	// Verify the repaired volume is clean
	scanner2 := NewScanner(outPath)
	result2, err := scanner2.Run()
	if err != nil {
		t.Fatal(err)
	}

	if result2.Stats.ValidNeedles != 3 {
		t.Errorf("repaired volume should have 3 valid needles, got %d", result2.Stats.ValidNeedles)
	}
	if result2.Stats.CorruptedData != 0 {
		t.Errorf("repaired volume should have 0 corrupted, got %d", result2.Stats.CorruptedData)
	}
}

func TestDetectSignaturesInGaps(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	// Write some data with file signatures embedded
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)

	// Simulate a corruption gap containing JPEG and PNG signatures
	gapData := make([]byte, 256)
	// JPEG at offset 0
	gapData[0] = 0xFF
	gapData[1] = 0xD8
	gapData[2] = 0xFF
	// PNG at offset 40
	copy(gapData[40:], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	f.Write(gapData)
	f.Close()

	datFile, _ := os.Open(datPath)
	defer datFile.Close()

	gaps := []Gap{{StartOffset: SuperBlockSize, EndOffset: int64(SuperBlockSize + len(gapData))}}
	sigs := DetectSignaturesInGaps(datFile, gaps)

	if len(sigs) == 0 {
		t.Fatal("expected to find file signatures in gap")
	}

	foundJPEG := false
	for _, sig := range sigs {
		if sig.FileType == "JPEG image" {
			foundJPEG = true
		}
	}
	if !foundJPEG {
		t.Error("expected to find JPEG signature")
	}
}
