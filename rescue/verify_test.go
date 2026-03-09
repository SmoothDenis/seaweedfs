package rescue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyCleanExtract(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)

	f.Write(buildNeedleV3(0xAA, 1, []byte("file one")))
	f.Write(buildNeedleV3(0xBB, 2, []byte("file two")))

	// Corrupt needle 2 (single byte)
	n1Size := len(buildNeedleV3(0xAA, 1, []byte("file one")))
	corruptPos := int64(SuperBlockSize + n1Size + NeedleHeaderSize + 4 + 2)
	f.WriteAt([]byte{0xFF}, corruptPos)
	f.Close()

	// Scan
	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.CorruptedData != 1 {
		t.Fatalf("expected 1 corrupted, got %d", result.Stats.CorruptedData)
	}

	// Repair and extract
	outPath := filepath.Join(dir, "repaired.dat")
	_, _, err = RepairAndExtract(datPath, result, outPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify
	vr, err := VerifyOutput(outPath, result, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !vr.Clean {
		t.Error("expected clean output after repair")
	}
	if vr.Regression {
		t.Error("expected no regression")
	}
	if vr.OutputStats.ValidNeedles != 2 {
		t.Errorf("expected 2 valid in output, got %d", vr.OutputStats.ValidNeedles)
	}
}

func TestVerifyDetectsRegression(t *testing.T) {
	// Simulate a regression by creating a "worse" output
	dir := t.TempDir()

	// Original: 3 valid + 1 corrupted
	origResult := &ScanResult{
		Stats: ScanStats{
			ValidNeedles:  3,
			CorruptedData: 1,
		},
	}

	// Create output with only 2 valid needles (regression)
	outPath := filepath.Join(dir, "bad_output.dat")
	f, _ := os.Create(outPath)
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)
	f.Write(buildNeedleV3(0xAA, 1, []byte("one")))
	f.Write(buildNeedleV3(0xBB, 2, []byte("two")))
	f.Close()

	vr, err := VerifyOutput(outPath, origResult, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !vr.Regression {
		t.Error("expected regression to be detected")
	}
}

func TestDryRunRepair(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	sb := make([]byte, SuperBlockSize)
	sb[0] = 3
	f.Write(sb)

	data1 := []byte("healthy file")
	data2 := []byte("file with single byte error")
	data3 := []byte("file with multi byte errors here")

	f.Write(buildNeedleV3(0xAA, 1, data1))
	n1Size := len(buildNeedleV3(0xAA, 1, data1))
	f.Write(buildNeedleV3(0xBB, 2, data2))
	n2Size := len(buildNeedleV3(0xBB, 2, data2))
	f.Write(buildNeedleV3(0xCC, 3, data3))

	// Corrupt 1 byte in needle 2
	f.WriteAt([]byte{0xFF}, int64(SuperBlockSize+n1Size+NeedleHeaderSize+4+5))
	// Corrupt 2 bytes in needle 3
	n3Start := int64(SuperBlockSize + n1Size + n2Size)
	f.WriteAt([]byte{0xFF}, n3Start+int64(NeedleHeaderSize+4+3))
	f.WriteAt([]byte{0xFE}, n3Start+int64(NeedleHeaderSize+4+10))
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatal(err)
	}

	if result.Stats.CorruptedData != 2 {
		t.Fatalf("expected 2 corrupted, got %d", result.Stats.CorruptedData)
	}

	dr, err := DryRunRepair(datPath, result, nil)
	if err != nil {
		t.Fatal(err)
	}

	if dr.Total != 2 {
		t.Errorf("expected 2 total, got %d", dr.Total)
	}
	if dr.Repairable != 1 {
		t.Errorf("expected 1 repairable, got %d", dr.Repairable)
	}
}
