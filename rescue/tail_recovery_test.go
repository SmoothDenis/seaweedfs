package rescue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTailRecoveryFindsNeedleWithDestroyedHeader(t *testing.T) {
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

	// Needle 1: valid
	n1 := buildNeedleV3(0xAA, 1, []byte("first file is fine"))
	f.Write(n1)

	// Needle 2: we'll destroy its header but keep data+tail intact
	n2 := buildNeedleV3(0xBB, 2, []byte("second file has destroyed header"))
	n2Offset := int64(SuperBlockSize + len(n1))
	f.Write(n2)

	// Needle 3: valid
	n3 := buildNeedleV3(0xCC, 3, []byte("third file is fine"))
	f.Write(n3)

	// Destroy header of needle 2 (overwrite first 16 bytes with garbage)
	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF}
	f.WriteAt(garbage, n2Offset)
	f.Close()

	// Scan with deep scan (which includes tail recovery for V3)
	scanner := NewScanner(datPath)
	scanner.DeepScan = true
	result, err := scanner.Run()
	if err != nil {
		t.Fatal(err)
	}

	// We should find a needle at offset 64 via tail recovery.
	// Since the header was destroyed, NeedleId will be garbage, but
	// the data should be intact (correct DataSize and CRC match).
	found := false
	for _, rec := range result.Records {
		if rec.Source == "tail-recovery" && rec.Offset == n2Offset {
			found = true
			if rec.Status != StatusRecovered {
				t.Errorf("expected StatusRecovered, got %v", rec.Status)
			}
			expectedDataSize := uint32(len("second file has destroyed header"))
			if rec.DataSize != expectedDataSize {
				t.Errorf("expected dataSize %d, got %d", expectedDataSize, rec.DataSize)
			}
			if rec.ComputedCRC != rec.StoredCRC {
				t.Errorf("CRC should match: computed=%08x stored=%08x", rec.ComputedCRC, rec.StoredCRC)
			}
			break
		}
	}

	if !found {
		t.Error("tail recovery should have found a needle at the destroyed header's offset")
		t.Logf("records: %+v", result.Records)
	}
}

func TestTailRecoverySkipsV2(t *testing.T) {
	// V2 has no timestamps, so tail recovery should not find anything
	dir := t.TempDir()
	datPath := filepath.Join(dir, "test.dat")
	f, err := os.Create(datPath)
	if err != nil {
		t.Fatal(err)
	}

	sb := make([]byte, SuperBlockSize)
	sb[0] = 2
	f.Write(sb)
	f.Close()

	datFile, _ := os.Open(datPath)
	defer datFile.Close()

	gaps := []Gap{{StartOffset: SuperBlockSize, EndOffset: 1024}}
	recovered := RecoverFromTails(datFile, gaps, 2, SuperBlockSize, nil)
	if len(recovered) != 0 {
		t.Errorf("V2 should not produce tail recoveries, got %d", len(recovered))
	}
}
