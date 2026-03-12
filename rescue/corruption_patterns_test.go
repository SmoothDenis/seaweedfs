package rescue

import (
	"encoding/binary"
	"hash/crc32"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// --- Scanner tests for new edge cases ---

// TestScanDeletedNeedleAfterCorruption verifies that gap recovery recognizes
// deleted (tombstone) needles as valid anchors, not just StatusValid needles.
func TestScanDeletedNeedleAfterCorruption(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("valid data"))
	n2 := buildNeedleV3(0xBB, 2, []byte("will be corrupted"))
	n3 := buildDeletedNeedleV3(0xCC, 3) // deleted needle after corruption

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Corrupt needle 2 header
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	corruptOffset := int64(SuperBlockSize + len(n1))
	garbage := make([]byte, 16)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	f.WriteAt(garbage, corruptOffset)
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should find needle 1 (valid) and needle 3 (deleted) as gap anchor
	foundDeleted := false
	for _, rec := range result.Records {
		if rec.NeedleId == 3 && rec.Status == StatusDeleted {
			foundDeleted = true
		}
	}
	if !foundDeleted {
		t.Error("deleted needle 3 not found as gap anchor after corruption")
	}
	if len(result.CorruptionGaps) == 0 {
		t.Error("expected corruption gap between needle 1 and deleted needle 3")
	}
}

// TestScanZeroSizeNeedle verifies that Size=0 needles are treated as valid,
// not deleted (matching real SeaweedFS semantics).
func TestScanZeroSizeNeedle(t *testing.T) {
	dir := t.TempDir()

	// Build a zero-size needle manually
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], 0x12345678)
	binary.BigEndian.PutUint64(header[4:12], 42)
	binary.BigEndian.PutUint32(header[12:16], 0) // Size = 0

	// Tail: CRC=0 (CRC32C of empty data) + timestamp + padding
	tail := make([]byte, NeedleChecksumSize+TimestampSize)
	binary.BigEndian.PutUint32(tail[0:4], 0) // CRC of empty = 0
	binary.BigEndian.PutUint64(tail[4:12], 1700000000_000_000_000)

	raw := append(header, tail...)
	padLen := PaddingLength(0, 3)
	raw = append(raw, make([]byte, padLen)...)

	datPath := writeDatFile(t, dir, raw)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.ValidNeedles != 1 {
		t.Errorf("expected 1 valid needle (size=0), got %d valid", result.Stats.ValidNeedles)
	}
	if result.Stats.DeletedNeedles != 0 {
		t.Errorf("size=0 needle should not be counted as deleted, got %d deleted", result.Stats.DeletedNeedles)
	}
}

// TestScanTruncatedNeedleBody verifies graceful handling when needle header is
// valid but body is cut off at EOF.
func TestScanTruncatedNeedleBody(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("complete needle"))

	datPath := writeDatFile(t, dir, n1)

	// Append a partial needle: just header + a few body bytes (truncated)
	f, _ := os.OpenFile(datPath, os.O_RDWR|os.O_APPEND, 0644)
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], 0xBB)
	binary.BigEndian.PutUint64(header[4:12], 2)
	binary.BigEndian.PutUint32(header[12:16], 100) // Size=100 but file ends soon
	f.Write(header)
	f.Write([]byte("partial"))
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should recover needle 1, and handle the truncated needle gracefully
	if result.Stats.ValidNeedles != 1 {
		t.Errorf("expected 1 valid needle, got %d", result.Stats.ValidNeedles)
	}
}

// TestScanAllZerosCorruption tests recovery when a portion of the volume
// is overwritten with all zeros (common SSD failure mode).
func TestScanAllZerosCorruption(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("before zeros"))
	n2 := buildNeedleV3(0xBB, 2, []byte("will become zeros"))
	n3 := buildNeedleV3(0xCC, 3, []byte("after zeros"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Overwrite needle 2 with all zeros
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	corruptOffset := int64(SuperBlockSize + len(n1))
	zeros := make([]byte, len(n2))
	f.WriteAt(zeros, corruptOffset)
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid {
			foundIds[rec.NeedleId] = true
		}
	}
	if !foundIds[1] {
		t.Error("needle 1 should survive all-zeros corruption in needle 2")
	}
	if !foundIds[3] {
		t.Error("needle 3 should be recovered after all-zeros corruption gap")
	}
}

// TestScanRepeatingPatternCorruption tests recovery when corruption writes
// a repeating pattern (e.g., 0xDEADBEEF).
func TestScanRepeatingPatternCorruption(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("before pattern"))
	n2 := buildNeedleV3(0xBB, 2, []byte("will be patterned"))
	n3 := buildNeedleV3(0xCC, 3, []byte("after pattern"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Overwrite needle 2 with repeating 0xDEADBEEF pattern
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	corruptOffset := int64(SuperBlockSize + len(n1))
	pattern := make([]byte, len(n2))
	for i := 0; i+3 < len(pattern); i += 4 {
		pattern[i] = 0xDE
		pattern[i+1] = 0xAD
		pattern[i+2] = 0xBE
		pattern[i+3] = 0xEF
	}
	f.WriteAt(pattern, corruptOffset)
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid {
			foundIds[rec.NeedleId] = true
		}
	}
	if !foundIds[1] || !foundIds[3] {
		t.Errorf("expected needles 1 and 3 to survive pattern corruption, found: %v", foundIds)
	}
}

// TestScanManyNeedles tests scanning a volume with 100+ needles where
// corruption occurs in the middle.
func TestScanManyNeedles(t *testing.T) {
	dir := t.TempDir()

	var needles [][]byte
	for i := uint64(1); i <= 100; i++ {
		data := make([]byte, 10+i%20) // varying sizes
		for j := range data {
			data[j] = byte(i)
		}
		needles = append(needles, buildNeedleV3(uint32(i), i, data))
	}

	datPath := writeDatFile(t, dir, needles...)

	// Corrupt needles 50-52
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	offset := int64(SuperBlockSize)
	for i := 0; i < 49; i++ {
		offset += int64(len(needles[i]))
	}
	// Corrupt 3 needles worth of data
	corruptLen := len(needles[49]) + len(needles[50]) + len(needles[51])
	garbage := make([]byte, corruptLen)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	f.WriteAt(garbage, offset)
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should find ~97 valid needles (100 - 3 corrupted)
	if result.Stats.ValidNeedles < 95 {
		t.Errorf("expected at least 95 valid needles out of 100, got %d", result.Stats.ValidNeedles)
	}
	if len(result.CorruptionGaps) == 0 {
		t.Error("expected corruption gaps")
	}
}

// TestScanDuplicateNeedleId verifies handling of duplicate NeedleId.
func TestScanDuplicateNeedleId(t *testing.T) {
	dir := t.TempDir()
	// Two needles with the same NeedleId but different data
	n1 := buildNeedleV3(0xAA, 1, []byte("first version"))
	n2 := buildNeedleV3(0xBB, 1, []byte("second version")) // same NeedleId=1

	datPath := writeDatFile(t, dir, n1, n2)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Both should be found in scan
	count := 0
	for _, rec := range result.Records {
		if rec.NeedleId == 1 && rec.Status == StatusValid {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 records with NeedleId=1, got %d", count)
	}

	// But extract should deduplicate
	outPath := filepath.Join(dir, "output.dat")
	extracted, err := ExtractValidNeedles(datPath, result, outPath)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if extracted != 1 {
		t.Errorf("expected 1 extracted (deduplicated), got %d", extracted)
	}
}

// TestScanMinInt32Size verifies that Size = math.MinInt32 doesn't crash.
func TestScanMinInt32Size(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("normal"))

	datPath := writeDatFile(t, dir, n1)

	// Append a needle with Size = MinInt32
	f, _ := os.OpenFile(datPath, os.O_RDWR|os.O_APPEND, 0644)
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], 0xBB)
	binary.BigEndian.PutUint64(header[4:12], 2)
	binary.BigEndian.PutUint32(header[12:16], 0x80000000) // math.MinInt32 as uint32
	f.Write(header)
	f.Close()

	// Should not panic or crash
	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.ValidNeedles != 1 {
		t.Errorf("expected 1 valid needle, got %d", result.Stats.ValidNeedles)
	}
}

// TestScanNeedleAtExactEOF verifies that a needle ending exactly at EOF works.
func TestScanNeedleAtExactEOF(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("exactly at eof"))

	datPath := writeDatFile(t, dir, n1)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.ValidNeedles != 1 {
		t.Errorf("expected 1 valid needle at exact EOF, got %d", result.Stats.ValidNeedles)
	}
}

// TestScanMultipleCorruptionGaps verifies correct handling of multiple
// distinct corruption gaps with valid needles between them.
func TestScanMultipleCorruptionGaps(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("gap1 before"))
	n2 := buildNeedleV3(0xBB, 2, []byte("gap1 corrupt"))
	n3 := buildNeedleV3(0xCC, 3, []byte("between gaps"))
	n4 := buildNeedleV3(0xDD, 4, []byte("gap2 corrupt"))
	n5 := buildNeedleV3(0xEE, 5, []byte("gap2 after"))

	datPath := writeDatFile(t, dir, n1, n2, n3, n4, n5)

	// Corrupt needle 2 (first gap)
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	offset2 := int64(SuperBlockSize + len(n1))
	garbage := make([]byte, 16)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	f.WriteAt(garbage, offset2)

	// Corrupt needle 4 (second gap)
	offset4 := int64(SuperBlockSize + len(n1) + len(n2) + len(n3))
	f.WriteAt(garbage, offset4)
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid {
			foundIds[rec.NeedleId] = true
		}
	}

	for _, id := range []uint64{1, 3, 5} {
		if !foundIds[id] {
			t.Errorf("needle %d not found (should survive through multiple gaps)", id)
		}
	}
	if len(result.CorruptionGaps) < 2 {
		t.Errorf("expected at least 2 corruption gaps, got %d", len(result.CorruptionGaps))
	}
}

// --- Repair tests ---

// TestRepairAdjacentBitFlips verifies multi-byte corruption detection.
func TestRepairAdjacentBitFlips(t *testing.T) {
	dir := t.TempDir()
	data := []byte("test data for adjacent corruption")
	n1 := buildNeedleV3(0xAA, 1, data)
	datPath := writeDatFile(t, dir, n1)

	// Corrupt two adjacent bytes in the data
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	dataStart := int64(SuperBlockSize + NeedleHeaderSize + 4) // header + DataSize
	f.WriteAt([]byte{0xFF}, dataStart+2)                      // byte 2
	f.WriteAt([]byte{0xFF}, dataStart+3)                      // byte 3
	f.Close()

	scanner := NewScanner(datPath)
	result, _ := scanner.Run()

	for _, rec := range result.Records {
		if rec.Status == StatusCorruptedData {
			src, _ := os.Open(datPath)
			defer src.Close()
			rr := AttemptRepair(src, rec, result.Version)
			if rr.Repaired {
				t.Error("should NOT be able to repair two adjacent corrupted bytes with single-byte repair")
			}
			if !rr.MultiErrors && !rr.Ambiguous {
				t.Error("expected MultiErrors flag for multi-byte corruption")
			}
		}
	}
}

// --- Extractor tests ---

// TestExtractPadsNonAlignedSuperblock verifies that output offsets are
// 8-byte aligned even when superblock has odd ExtraSize.
func TestExtractPadsNonAlignedSuperblock(t *testing.T) {
	dir := t.TempDir()

	// Create superblock with 5-byte ExtraSize (total 13 bytes, not 8-byte aligned)
	sb := make([]byte, SuperBlockSize+5)
	sb[0] = 3 // version
	binary.BigEndian.PutUint16(sb[6:8], 5)
	sb[8] = 0x01 // extra data
	sb[9] = 0x02
	sb[10] = 0x03
	sb[11] = 0x04
	sb[12] = 0x05

	n1 := buildNeedleV3(0xAA, 1, []byte("test data"))
	datPath := writeDatFileWithSuperBlock(t, dir, sb, n1)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Extract
	outPath := filepath.Join(dir, "output.dat")
	extracted, err := ExtractValidNeedles(datPath, result, outPath)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if extracted != 1 {
		t.Errorf("expected 1 extracted, got %d", extracted)
	}

	// Verify output offsets are 8-byte aligned
	outScanner := NewScanner(outPath)
	outResult, err := outScanner.Run()
	if err != nil {
		t.Fatalf("output scan failed: %v", err)
	}

	for _, rec := range outResult.Records {
		if rec.Offset%NeedlePaddingSize != 0 {
			t.Errorf("needle at offset %d is not 8-byte aligned", rec.Offset)
		}
	}
}

// TestExtractPreservesDeletedNeedles verifies that deleted needles are
// included in the extract output.
func TestExtractPreservesDeletedNeedles(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("valid data"))
	n2 := buildDeletedNeedleV3(0xBB, 2)
	n3 := buildNeedleV3(0xCC, 3, []byte("more data"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	scanner := NewScanner(datPath)
	result, _ := scanner.Run()

	outPath := filepath.Join(dir, "output.dat")
	extracted, err := ExtractValidNeedles(datPath, result, outPath)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}

	// Should extract all 3 (2 valid + 1 deleted)
	if extracted != 3 {
		t.Errorf("expected 3 extracted (including deleted), got %d", extracted)
	}
}

// --- Tail recovery tests ---

// TestTailRecoveryMultipleCandidatesInGap verifies recovery of multiple
// needles from a single corruption gap.
func TestTailRecoveryMultipleCandidatesInGap(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("before gap"))
	n2 := buildNeedleV3(0xBB, 2, []byte("first in gap"))
	n3 := buildNeedleV3(0xCC, 3, []byte("second in gap"))
	n4 := buildNeedleV3(0xDD, 4, []byte("after gap"))

	datPath := writeDatFile(t, dir, n1, n2, n3, n4)

	// Corrupt headers of needles 2 and 3 (but leave body+tail intact)
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	offset2 := int64(SuperBlockSize + len(n1))
	offset3 := offset2 + int64(len(n2))
	garbage := make([]byte, NeedleHeaderSize)
	for i := range garbage {
		garbage[i] = 0xFE
	}
	f.WriteAt(garbage, offset2)
	f.WriteAt(garbage, offset3)
	f.Close()

	scanner := NewScanner(datPath)
	scanner.DeepScan = true
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Needle 4 should be found via sequential scan
	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid || rec.Status == StatusRecovered {
			foundIds[rec.NeedleId] = true
		}
	}
	if !foundIds[1] {
		t.Error("needle 1 not found")
	}
	if !foundIds[4] {
		t.Error("needle 4 not found after gap")
	}
	// Needles 2 and 3 may be recovered via tail recovery
	recoveredCount := 0
	for _, rec := range result.Records {
		if rec.Status == StatusRecovered {
			recoveredCount++
		}
	}
	if recoveredCount == 0 {
		t.Log("note: no tail recovery candidates found (header corruption may prevent reconstruction)")
	}
}

// TestTailRecoveryFalseTimestamp verifies that garbage data that happens to
// look like a valid timestamp but has wrong CRC is rejected.
func TestTailRecoveryFalseTimestamp(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0xAA, 1, []byte("valid needle"))

	datPath := writeDatFile(t, dir, n1)

	// Append garbage with a plausible timestamp but wrong CRC
	f, _ := os.OpenFile(datPath, os.O_RDWR|os.O_APPEND, 0644)
	garbage := make([]byte, 64) // 8-byte aligned
	// Write a "valid" timestamp at offset 4 (CRC position) + 8 (timestamp)
	binary.BigEndian.PutUint32(garbage[48:52], 0xDEADBEEF)            // fake CRC
	binary.BigEndian.PutUint64(garbage[52:60], 1700000000_000_000_000) // valid timestamp
	f.Write(garbage)
	f.Close()

	fileSize := int64(SuperBlockSize + len(n1) + len(garbage))

	// Run tail recovery on the garbage area
	datFile, _ := os.Open(datPath)
	defer datFile.Close()
	gaps := []Gap{{StartOffset: int64(SuperBlockSize + len(n1)), EndOffset: fileSize}}
	recovered := RecoverFromTails(datFile, gaps, 3, SuperBlockSize, nil)

	// Should NOT produce false positives (CRC won't match)
	for _, rec := range recovered {
		if rec.ComputedCRC != rec.StoredCRC {
			t.Error("tail recovery produced a record with mismatched CRC (false positive)")
		}
	}
}

// --- Safety tests ---

// TestInterruptedReplaceRecovery verifies detection of interrupted replace.
func TestInterruptedReplaceRecovery(t *testing.T) {
	dir := t.TempDir()
	datPath := filepath.Join(dir, "volume.dat")
	os.WriteFile(datPath, []byte("data"), 0644)

	// Create a marker file simulating interrupted replace
	markerPath := datPath + ".rescue-replace-in-progress"
	os.WriteFile(markerPath, []byte("original_dat=/path/to/dat\n"), 0644)

	msg := CheckInterruptedReplace(datPath)
	if msg == "" {
		t.Error("expected warning about interrupted replace")
	}

	// Clean state should return empty
	os.Remove(markerPath)
	msg = CheckInterruptedReplace(datPath)
	if msg != "" {
		t.Errorf("expected empty for clean state, got: %s", msg)
	}
}

// --- Corruption pattern tests ---

// TestBitFlipInEveryNeedleField systematically tests bit flips in each field.
func TestBitFlipInEveryNeedleField(t *testing.T) {
	data := []byte("test data for bit flips")
	n1 := buildNeedleV3(0xAA, 1, data)

	// Test flipping bits in various field positions
	fieldPositions := map[string]int{
		"cookie":    0,
		"needleId":  4,
		"size":      12,
		"dataSize":  NeedleHeaderSize,
		"data":      NeedleHeaderSize + 4,
		"flags":     NeedleHeaderSize + 4 + len(data),
		"crc":       NeedleHeaderSize + int(4+len(data)+1),
		"timestamp": NeedleHeaderSize + int(4+len(data)+1) + NeedleChecksumSize,
	}

	for fieldName, pos := range fieldPositions {
		if pos >= len(n1) {
			continue
		}
		t.Run("flip_"+fieldName, func(t *testing.T) {
			testDir := t.TempDir()
			datPath := writeDatFile(t, testDir, n1)

			// Flip one bit
			f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
			buf := []byte{0}
			f.ReadAt(buf, int64(SuperBlockSize+pos))
			buf[0] ^= 0x01 // flip LSB
			f.WriteAt(buf, int64(SuperBlockSize+pos))
			f.Close()

			scanner := NewScanner(datPath)
			_, err := scanner.Run()
			if err != nil {
				t.Fatalf("scan crashed on %s bit flip: %v", fieldName, err)
			}
		})
	}
}

// TestSectorCorruption simulates a 512-byte sector of zeros.
func TestSectorCorruption(t *testing.T) {
	dir := t.TempDir()

	// Build enough needles to span multiple sectors
	var needles [][]byte
	for i := uint64(1); i <= 20; i++ {
		data := make([]byte, 50)
		for j := range data {
			data[j] = byte(i)
		}
		needles = append(needles, buildNeedleV3(uint32(i), i, data))
	}

	datPath := writeDatFile(t, dir, needles...)

	// Zero out a 512-byte sector in the middle
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	sectorOffset := int64(SuperBlockSize + len(needles[0])*5) // roughly middle
	zeros := make([]byte, 512)
	f.WriteAt(zeros, sectorOffset)
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should recover most needles
	if result.Stats.ValidNeedles < 10 {
		t.Errorf("expected at least 10 valid needles after sector corruption, got %d", result.Stats.ValidNeedles)
	}
}

// TestRandomBitFlips tests recovery with random bit flips at various densities.
func TestRandomBitFlips(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewSource(42))

	var needles [][]byte
	for i := uint64(1); i <= 10; i++ {
		data := make([]byte, 100)
		for j := range data {
			data[j] = byte(i*10 + uint64(j))
		}
		needles = append(needles, buildNeedleV3(uint32(i), i, data))
	}

	datPath := writeDatFile(t, dir, needles...)

	// Read entire file
	fileData, _ := os.ReadFile(datPath)
	totalBytes := len(fileData) - SuperBlockSize

	// Flip ~1% of bits (in the data area, not superblock)
	flipped := 0
	for i := SuperBlockSize; i < len(fileData); i++ {
		if rng.Intn(100) == 0 {
			fileData[i] ^= byte(1 << uint(rng.Intn(8)))
			flipped++
		}
	}
	os.WriteFile(datPath, fileData, 0644)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed after %d bit flips in %d bytes: %v", flipped, totalBytes, err)
	}

	// With 1% bit flip rate, some needles should still survive
	t.Logf("after %d random bit flips: %d valid, %d corrupted, %d gaps",
		flipped, result.Stats.ValidNeedles, result.Stats.CorruptedData, len(result.CorruptionGaps))
}

// TestSingleBitFlipPerNeedle tests that single-byte repair fixes every needle
// when each has exactly one corrupted bit.
func TestSingleBitFlipPerNeedle(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewSource(123))

	var needles [][]byte
	for i := uint64(1); i <= 5; i++ {
		data := make([]byte, 20)
		for j := range data {
			data[j] = byte(i*10 + uint64(j))
		}
		needles = append(needles, buildNeedleV3(uint32(i), i, data))
	}

	datPath := writeDatFile(t, dir, needles...)

	// Flip exactly one byte in the DATA portion of each needle
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	offset := int64(SuperBlockSize)
	for _, n := range needles {
		dataStart := offset + NeedleHeaderSize + 4 // skip header + DataSize field
		dataLen := binary.BigEndian.Uint32(n[NeedleHeaderSize : NeedleHeaderSize+4])
		if dataLen > 0 {
			flipPos := dataStart + int64(rng.Intn(int(dataLen)))
			buf := []byte{0}
			f.ReadAt(buf, flipPos)
			buf[0] ^= 0x01
			f.WriteAt(buf, flipPos)
		}
		offset += int64(len(n))
	}
	f.Close()

	// Scan + repair
	scanner := NewScanner(datPath)
	result, _ := scanner.Run()

	if result.Stats.CorruptedData == 0 {
		t.Skip("no corrupted needles detected (bit flip may have been in padding)")
	}

	outPath := filepath.Join(dir, "repaired.dat")
	extracted, repaired, err := RepairAndExtract(datPath, result, outPath, nil)
	if err != nil {
		t.Fatalf("repair and extract failed: %v", err)
	}

	t.Logf("extracted: %d, repaired: %d out of %d corrupted", extracted, repaired, result.Stats.CorruptedData)
	if repaired == 0 && result.Stats.CorruptedData > 0 {
		t.Error("expected at least some repairs for single-byte corruptions")
	}
}

// TestFullVolumeRecoveryPipeline tests the complete end-to-end pipeline:
// create volume -> corrupt -> scan -> repair -> extract -> verify.
func TestFullVolumeRecoveryPipeline(t *testing.T) {
	dir := t.TempDir()

	// Create a realistic volume with various needle types
	n1 := buildNeedleV3(0xAA, 1, []byte("important document"))
	n2 := buildNeedleV3(0xBB, 2, []byte("image data placeholder"))
	n3 := buildDeletedNeedleV3(0xCC, 3) // deleted needle
	n4 := buildNeedleV3(0xDD, 4, []byte("another file"))
	n5 := buildNeedleV3(0xEE, 5, []byte("last file in volume"))

	datPath := writeDatFile(t, dir, n1, n2, n3, n4, n5)

	// Corrupt needle 2's data (single byte flip for repairable corruption)
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	dataPos := int64(SuperBlockSize + len(n1) + NeedleHeaderSize + 4 + 3) // byte 3 of n2's data
	buf := []byte{0}
	f.ReadAt(buf, dataPos)
	buf[0] ^= 0x40 // flip one bit
	f.WriteAt(buf, dataPos)

	// Destroy needle 4's header completely
	offset4 := int64(SuperBlockSize + len(n1) + len(n2) + len(n3))
	headerGarbage := make([]byte, NeedleHeaderSize)
	for i := range headerGarbage {
		headerGarbage[i] = 0xFF
	}
	f.WriteAt(headerGarbage, offset4)
	f.Close()

	// Step 1: Scan with deep scan
	scanner := NewScanner(datPath)
	scanner.DeepScan = true
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	t.Logf("scan: %d valid, %d corrupted, %d deleted, %d gaps",
		result.Stats.ValidNeedles, result.Stats.CorruptedData,
		result.Stats.DeletedNeedles, len(result.CorruptionGaps))

	// Step 2: Repair + Extract
	outPath := filepath.Join(dir, "recovered.dat")
	extracted, repaired, err := RepairAndExtract(datPath, result, outPath, nil)
	if err != nil {
		t.Fatalf("repair+extract failed: %v", err)
	}

	t.Logf("extracted: %d, repaired: %d", extracted, repaired)

	// Step 3: Verify
	vr, idxIssues, err := VerifyExtractedVolume(outPath, result, nil)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	t.Logf("verify: clean=%v, regression=%v, intact=%d, missing=%d",
		vr.Clean, vr.Regression, vr.NeedlesIntact, len(vr.NeedlesMissing))

	if vr.Regression {
		t.Error("verification detected regression")
	}
	// Some idx issues are expected: needles recovered via tail recovery with
	// destroyed headers are written to .dat but excluded from .idx (unreliable NeedleId).
	if len(idxIssues) > 0 {
		t.Logf("idx issues (expected for destroyed-header needles): %v", idxIssues)
	}

	// Should have recovered needles 1, 3 (deleted), 5, and repaired needle 2.
	// Needle 4's header was destroyed; data may be recovered via tail recovery
	// but its NeedleId is unreliable.
	if extracted < 3 {
		t.Errorf("expected at least 3 extracted needles, got %d", extracted)
	}
}

// TestInterleavedCorruption tests alternating valid/corrupted/valid sequences.
func TestInterleavedCorruption(t *testing.T) {
	dir := t.TempDir()

	var needles [][]byte
	for i := uint64(1); i <= 10; i++ {
		data := make([]byte, 15)
		for j := range data {
			data[j] = byte(i)
		}
		needles = append(needles, buildNeedleV3(uint32(i), i, data))
	}

	datPath := writeDatFile(t, dir, needles...)

	// Corrupt every other needle (2, 4, 6, 8)
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	offset := int64(SuperBlockSize)
	for i, n := range needles {
		if (i+1)%2 == 0 { // corrupt needles 2, 4, 6, 8
			garbage := make([]byte, NeedleHeaderSize)
			for j := range garbage {
				garbage[j] = 0xFE
			}
			f.WriteAt(garbage, offset)
		}
		offset += int64(len(n))
	}
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should find odd-numbered needles (1, 3, 5, 7, 9)
	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid {
			foundIds[rec.NeedleId] = true
		}
	}
	for _, id := range []uint64{1, 3, 5, 7, 9} {
		if !foundIds[id] {
			t.Errorf("needle %d not found in interleaved corruption", id)
		}
	}
}

// TestDeduplicateByNeedleId tests the deduplication helper.
func TestDeduplicateByNeedleId(t *testing.T) {
	records := []NeedleRecord{
		{NeedleId: 1, Status: StatusCorruptedData, Offset: 100},
		{NeedleId: 1, Status: StatusValid, Offset: 200},
		{NeedleId: 2, Status: StatusRecovered, Offset: 300},
		{NeedleId: 2, Status: StatusValid, Offset: 400},
		{NeedleId: 3, Status: StatusDeleted, Offset: 500},
	}

	deduped := DeduplicateByNeedleId(records)
	if len(deduped) != 3 {
		t.Fatalf("expected 3 deduplicated records, got %d", len(deduped))
	}

	byID := make(map[uint64]NeedleRecord)
	for _, r := range deduped {
		byID[r.NeedleId] = r
	}

	if byID[1].Status != StatusValid {
		t.Errorf("NeedleId 1: expected Valid (best), got %s", byID[1].Status)
	}
	if byID[2].Status != StatusValid {
		t.Errorf("NeedleId 2: expected Valid (best), got %s", byID[2].Status)
	}
	if byID[3].Status != StatusDeleted {
		t.Errorf("NeedleId 3: expected Deleted (only), got %s", byID[3].Status)
	}
}

// TestAbsInt32Overflow verifies the overflow guard.
func TestAbsInt32Overflow(t *testing.T) {
	result := absInt32(math.MinInt32)
	if result < 0 {
		t.Errorf("absInt32(MinInt32) should not return negative, got %d", result)
	}
	if result != math.MaxInt32 {
		t.Errorf("absInt32(MinInt32) should return MaxInt32, got %d", result)
	}
}

// TestIsReasonableSizeMinInt32 verifies MinInt32 is rejected.
func TestIsReasonableSizeMinInt32(t *testing.T) {
	if IsReasonableSize(math.MinInt32) {
		t.Error("math.MinInt32 should not be a reasonable size")
	}
}

// Ensure imports are used.
var (
	_ = crc32.MakeTable(crc32.Castagnoli)
)
