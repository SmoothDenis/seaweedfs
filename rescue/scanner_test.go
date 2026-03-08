package rescue

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// --- Test helpers: build synthetic .dat and .idx files ---

var testCRC32cTable = crc32.MakeTable(crc32.Castagnoli)

// buildNeedleV3 creates a raw V3 needle on disk (header + body + tail + padding).
// data is the actual file content (what CRC is computed over).
func buildNeedleV3(cookie uint32, needleId uint64, data []byte) []byte {
	dataSize := uint32(len(data))
	// Body = DataSize(4) + Data(N) + Flags(1)
	bodySize := int32(4 + dataSize + 1)

	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], cookie)
	binary.BigEndian.PutUint64(header[4:12], needleId)
	binary.BigEndian.PutUint32(header[12:16], uint32(bodySize))

	body := make([]byte, bodySize)
	binary.BigEndian.PutUint32(body[0:4], dataSize)
	copy(body[4:4+dataSize], data)
	body[4+dataSize] = 0x00 // flags: none

	crc := crc32.Update(0, testCRC32cTable, data)
	tail := make([]byte, NeedleChecksumSize+TimestampSize)
	binary.BigEndian.PutUint32(tail[0:4], crc)
	binary.BigEndian.PutUint64(tail[4:12], 1700000000_000_000_000) // timestamp ~2023

	raw := make([]byte, 0, NeedleHeaderSize+int(bodySize)+len(tail))
	raw = append(raw, header...)
	raw = append(raw, body...)
	raw = append(raw, tail...)

	// Padding
	padLen := PaddingLength(bodySize, 3)
	if padLen > 0 {
		raw = append(raw, make([]byte, padLen)...)
	}

	return raw
}

// buildDeletedNeedleV3 creates a deleted (tombstone) needle.
func buildDeletedNeedleV3(cookie uint32, needleId uint64) []byte {
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], cookie)
	binary.BigEndian.PutUint64(header[4:12], needleId)
	// Size = 0 for deleted
	binary.BigEndian.PutUint32(header[12:16], 0)

	tail := make([]byte, NeedleChecksumSize+TimestampSize)
	binary.BigEndian.PutUint64(tail[4:12], 1700000000_000_000_000)

	raw := append(header, tail...)
	padLen := PaddingLength(0, 3)
	if padLen > 0 {
		raw = append(raw, make([]byte, padLen)...)
	}
	return raw
}

// buildSuperBlock returns an 8-byte V3 superblock.
func buildSuperBlock() []byte {
	sb := make([]byte, SuperBlockSize)
	sb[0] = 3 // version 3
	return sb
}

// writeDatFile creates a .dat file with superblock + needles.
func writeDatFile(t *testing.T, dir string, needles ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, "test.dat")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Write superblock
	if _, err := f.Write(buildSuperBlock()); err != nil {
		t.Fatal(err)
	}
	// Write needles
	for _, n := range needles {
		if _, err := f.Write(n); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// writeIdxFile creates a .idx file from entries.
func writeIdxFile(t *testing.T, dir string, entries []IdxEntry) string {
	t.Helper()
	path := filepath.Join(dir, "test.idx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, IdxEntrySize)
	for _, e := range entries {
		binary.BigEndian.PutUint64(buf[0:8], e.NeedleId)
		binary.BigEndian.PutUint32(buf[8:12], uint32(e.Offset/NeedlePaddingSize))
		binary.BigEndian.PutUint32(buf[12:16], uint32(e.Size))
		if _, err := f.Write(buf); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// --- Tests ---

func TestScanCleanVolume(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("hello world"))
	n2 := buildNeedleV3(0x22222222, 2, []byte("test data 12345"))
	n3 := buildNeedleV3(0x33333333, 3, []byte("x"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Version != 3 {
		t.Errorf("expected version 3, got %d", result.Version)
	}
	if result.Stats.TotalNeedles != 3 {
		t.Errorf("expected 3 needles, got %d", result.Stats.TotalNeedles)
	}
	if result.Stats.ValidNeedles != 3 {
		t.Errorf("expected 3 valid needles, got %d", result.Stats.ValidNeedles)
	}
	if len(result.CorruptionGaps) != 0 {
		t.Errorf("expected 0 corruption gaps, got %d", len(result.CorruptionGaps))
	}

	// Verify needle IDs
	for i, rec := range result.Records {
		expectedId := uint64(i + 1)
		if rec.NeedleId != expectedId {
			t.Errorf("needle %d: expected id %d, got %d", i, expectedId, rec.NeedleId)
		}
		if rec.Status != StatusValid {
			t.Errorf("needle %d: expected VALID, got %s", i, rec.Status)
		}
	}
}

func TestScanWithDeletedNeedle(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("hello"))
	n2 := buildDeletedNeedleV3(0x22222222, 2)
	n3 := buildNeedleV3(0x33333333, 3, []byte("world"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.TotalNeedles != 3 {
		t.Errorf("expected 3 needles, got %d", result.Stats.TotalNeedles)
	}
	if result.Stats.ValidNeedles != 2 {
		t.Errorf("expected 2 valid needles, got %d", result.Stats.ValidNeedles)
	}
	if result.Stats.DeletedNeedles != 1 {
		t.Errorf("expected 1 deleted needle, got %d", result.Stats.DeletedNeedles)
	}
}

func TestScanWithCorruptedMiddle(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("first needle data"))
	n2 := buildNeedleV3(0x22222222, 2, []byte("second needle data"))
	n3 := buildNeedleV3(0x33333333, 3, []byte("third needle data"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Corrupt the middle needle by overwriting its header with garbage
	f, err := os.OpenFile(datPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	corruptOffset := int64(SuperBlockSize + len(n1))
	garbage := make([]byte, 16) // overwrite header
	for i := range garbage {
		garbage[i] = 0xFF
	}
	if _, err := f.WriteAt(garbage, corruptOffset); err != nil {
		t.Fatal(err)
	}
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should find needle 1 and 3, with a corruption gap over needle 2
	if result.Stats.ValidNeedles < 2 {
		t.Errorf("expected at least 2 valid needles, got %d", result.Stats.ValidNeedles)
	}
	if len(result.CorruptionGaps) == 0 {
		t.Error("expected at least 1 corruption gap")
	}

	// Verify we found needle 1 and 3
	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid {
			foundIds[rec.NeedleId] = true
		}
	}
	if !foundIds[1] {
		t.Error("needle 1 not found (should survive corruption)")
	}
	if !foundIds[3] {
		t.Error("needle 3 not found (should be recovered after corruption gap)")
	}
}

func TestScanWithIdxCrossReference(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("hello"))
	n2 := buildNeedleV3(0x22222222, 2, []byte("world"))

	datPath := writeDatFile(t, dir, n1, n2)

	// Build matching idx
	// Body size for "hello": 4 + 5 + 1 = 10
	bodySize1 := int32(4 + 5 + 1)
	idxEntries := []IdxEntry{
		{NeedleId: 1, Offset: int64(SuperBlockSize), Size: bodySize1},
		{NeedleId: 2, Offset: int64(SuperBlockSize) + int64(len(n1)), Size: int32(4 + 5 + 1)},
	}
	idxPath := writeIdxFile(t, dir, idxEntries)

	scanner := NewScanner(datPath)
	scanner.IdxPath = idxPath
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.IdxEntries != 2 {
		t.Errorf("expected 2 idx entries, got %d", result.Stats.IdxEntries)
	}

	// Check that records have IdxMatch set
	matchCount := 0
	for _, rec := range result.Records {
		if rec.IdxMatch {
			matchCount++
		}
	}
	if matchCount < 2 {
		t.Errorf("expected 2 idx matches, got %d", matchCount)
	}
}

func TestDeepScanRecovery(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("first"))
	n2 := buildNeedleV3(0x22222222, 2, []byte("second"))
	n3 := buildNeedleV3(0x33333333, 3, []byte("third"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Corrupt needle 2 header (but leave body/CRC intact)
	// This means sequential scan won't find it, but deep scan might
	f, err := os.OpenFile(datPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	corruptOffset := int64(SuperBlockSize + len(n1))
	// Corrupt the Size field with a value exceeding MaxReasonableNeedleSize
	// so sequential scan treats it as corrupted header
	sizeOffset := corruptOffset + 12 // offset of Size within header
	hugeSizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(hugeSizeBuf, uint32(MaxReasonableNeedleSize+1000))
	if _, err := f.WriteAt(hugeSizeBuf, sizeOffset); err != nil {
		t.Fatal(err)
	}
	f.Close()

	scanner := NewScanner(datPath)
	scanner.DeepScan = true
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should find needles 1 and 3 via sequential, and corruption gap
	if result.Stats.ValidNeedles < 2 {
		t.Errorf("expected at least 2 valid needles, got %d", result.Stats.ValidNeedles)
	}
	if len(result.CorruptionGaps) == 0 {
		t.Error("expected corruption gaps")
	}
}

func TestEmptyVolume(t *testing.T) {
	dir := t.TempDir()
	datPath := writeDatFile(t, dir) // only superblock, no needles

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.TotalNeedles != 0 {
		t.Errorf("expected 0 needles, got %d", result.Stats.TotalNeedles)
	}
}

func TestTooSmallFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.dat")
	os.WriteFile(path, []byte{0x03, 0x00}, 0644) // 2 bytes, too small

	scanner := NewScanner(path)
	_, err := scanner.Run()
	if err == nil {
		t.Error("expected error for too-small file")
	}
}

func TestCRC32Castagnoli(t *testing.T) {
	// Verify our CRC matches what SeaweedFS uses
	data := []byte("hello world")
	crc := ComputeCRC32C(data)
	expected := crc32.Update(0, crc32.MakeTable(crc32.Castagnoli), data)
	if crc != expected {
		t.Errorf("CRC mismatch: got %x, expected %x", crc, expected)
	}
}

func TestPaddingLength(t *testing.T) {
	tests := []struct {
		size    int32
		version int
	}{
		{0, 3},
		{1, 3},
		{5, 3},
		{10, 3},
		{100, 3},
		{1000, 3},
		{0, 2},
		{1, 2},
		{100, 2},
	}

	for _, tt := range tests {
		pad := PaddingLength(tt.size, tt.version)
		diskSize := ActualDiskSize(tt.size, tt.version)

		// Verify disk size is 8-byte aligned
		if diskSize%NeedlePaddingSize != 0 {
			t.Errorf("size=%d version=%d: disk size %d not 8-byte aligned (pad=%d)", tt.size, tt.version, diskSize, pad)
		}

		// Verify padding is 0-7
		if pad < 0 || pad >= NeedlePaddingSize {
			t.Errorf("size=%d version=%d: invalid padding %d", tt.size, tt.version, pad)
		}
	}
}

func TestParseNeedleHeader(t *testing.T) {
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], 0xDEADBEEF)
	binary.BigEndian.PutUint64(header[4:12], 0x123456789ABCDEF0)
	binary.BigEndian.PutUint32(header[12:16], 42)

	cookie, needleId, size := ParseNeedleHeader(header)
	if cookie != 0xDEADBEEF {
		t.Errorf("cookie: got %x, want DEADBEEF", cookie)
	}
	if needleId != 0x123456789ABCDEF0 {
		t.Errorf("needleId: got %x, want 123456789ABCDEF0", needleId)
	}
	if size != 42 {
		t.Errorf("size: got %d, want 42", size)
	}
}

func TestIsReasonableSize(t *testing.T) {
	if !IsReasonableSize(0) {
		t.Error("0 should be reasonable (deleted)")
	}
	if !IsReasonableSize(100) {
		t.Error("100 should be reasonable")
	}
	if !IsReasonableSize(-1) {
		t.Error("-1 (tombstone) should be reasonable")
	}
	if !IsReasonableSize(-100) {
		t.Error("-100 should be reasonable (deleted)")
	}
	if IsReasonableSize(MaxReasonableNeedleSize + 1) {
		t.Error("size > max should be unreasonable")
	}
}

func TestValidateNeedleAtOffset(t *testing.T) {
	data := []byte("test payload data")
	needle := buildNeedleV3(0xAABBCCDD, 42, data)

	rec, ok := ValidateNeedleAtOffset(needle, 0, 3)
	if !ok {
		t.Fatal("validation failed for valid needle")
	}
	if rec.Status != StatusValid {
		t.Errorf("expected VALID, got %s", rec.Status)
	}
	if rec.NeedleId != 42 {
		t.Errorf("expected id 42, got %d", rec.NeedleId)
	}
	if rec.Cookie != 0xAABBCCDD {
		t.Errorf("expected cookie AABBCCDD, got %x", rec.Cookie)
	}
	if rec.DataSize != uint32(len(data)) {
		t.Errorf("expected dataSize %d, got %d", len(data), rec.DataSize)
	}
	if rec.ComputedCRC != rec.StoredCRC {
		t.Errorf("CRC mismatch: computed %x, stored %x", rec.ComputedCRC, rec.StoredCRC)
	}
}

func TestValidateCorruptedNeedle(t *testing.T) {
	data := []byte("test payload")
	needle := buildNeedleV3(0x11223344, 7, data)

	// Corrupt the data portion
	needle[NeedleHeaderSize+4+2] ^= 0xFF // flip a byte in the file data

	rec, ok := ValidateNeedleAtOffset(needle, 0, 3)
	if ok {
		t.Error("validation should fail for corrupted needle")
	}
	if rec.Status != StatusCorruptedData {
		t.Errorf("expected CORRUPTED_DATA, got %s", rec.Status)
	}
	if rec.ComputedCRC == rec.StoredCRC {
		t.Error("CRCs should differ for corrupted data")
	}
}

func TestScanLargeCorruptionGap(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("first"))
	n3 := buildNeedleV3(0x33333333, 3, []byte("third"))

	// Create dat with needle 1, then 1KB of garbage, then needle 3
	path := filepath.Join(dir, "test.dat")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(buildSuperBlock())
	f.Write(n1)
	// Write garbage aligned to 8 bytes
	garbageSize := 1024 // must be multiple of 8
	garbage := make([]byte, garbageSize)
	for i := range garbage {
		garbage[i] = 0xAB
	}
	f.Write(garbage)
	f.Write(n3)
	f.Close()

	scanner := NewScanner(path)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should find needle 1 and 3
	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		if rec.Status == StatusValid {
			foundIds[rec.NeedleId] = true
		}
	}
	if !foundIds[1] {
		t.Error("needle 1 not found")
	}
	if !foundIds[3] {
		t.Error("needle 3 not found after 1KB corruption gap")
	}
	if len(result.CorruptionGaps) == 0 {
		t.Error("expected corruption gap")
	}
}

func TestIdxReader(t *testing.T) {
	dir := t.TempDir()
	entries := []IdxEntry{
		{NeedleId: 1, Offset: 8, Size: 100},
		{NeedleId: 2, Offset: 1024, Size: 200},
		{NeedleId: 3, Offset: 4096, Size: -1}, // deleted
	}
	idxPath := writeIdxFile(t, dir, entries)

	result, err := ReadIdxFile(idxPath)
	if err != nil {
		t.Fatalf("ReadIdxFile failed: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}

	e1 := result[1]
	if e1.Offset != 8 || e1.Size != 100 {
		t.Errorf("entry 1: offset=%d size=%d, want offset=8 size=100", e1.Offset, e1.Size)
	}

	e3 := result[3]
	if e3.Size != -1 {
		t.Errorf("entry 3: size=%d, want -1", e3.Size)
	}
}

func TestExtractValidNeedles(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("keep me"))
	n2 := buildNeedleV3(0x22222222, 2, []byte("corrupt me"))
	n3 := buildNeedleV3(0x33333333, 3, []byte("keep me too"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Corrupt needle 2
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	corruptOffset := int64(SuperBlockSize + len(n1))
	garbage := make([]byte, len(n2))
	for i := range garbage {
		garbage[i] = 0xDE
	}
	f.WriteAt(garbage, corruptOffset)
	f.Close()

	// Scan
	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Extract
	extractPath := filepath.Join(dir, "recovered.dat")
	count, err := ExtractValidNeedles(datPath, result, extractPath)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}

	if count < 2 {
		t.Errorf("expected at least 2 extracted needles, got %d", count)
	}

	// Verify extracted file is scannable
	scanner2 := NewScanner(extractPath)
	result2, err := scanner2.Run()
	if err != nil {
		t.Fatalf("scan extracted file failed: %v", err)
	}

	if result2.Stats.ValidNeedles < 2 {
		t.Errorf("extracted file should have at least 2 valid needles, got %d", result2.Stats.ValidNeedles)
	}
	if len(result2.CorruptionGaps) != 0 {
		t.Errorf("extracted file should have 0 corruption gaps, got %d", len(result2.CorruptionGaps))
	}

	// Verify .idx was created
	idxPath := filepath.Join(dir, "recovered.idx")
	if _, err := os.Stat(idxPath); os.IsNotExist(err) {
		t.Error("expected .idx file to be created")
	}
}

func TestActualDiskSize(t *testing.T) {
	// V3: header(16) + body(size) + checksum(4) + timestamp(8) + padding
	// For size=10: 16 + 10 + 4 + 8 = 38, pad to 40
	ds := ActualDiskSize(10, 3)
	if ds%8 != 0 {
		t.Errorf("disk size %d not 8-byte aligned", ds)
	}
	if ds != 40 {
		t.Errorf("expected 40, got %d", ds)
	}

	// For size=0: 16 + 0 + 4 + 8 = 28, pad to 32
	ds0 := ActualDiskSize(0, 3)
	if ds0 != 32 {
		t.Errorf("expected 32 for size=0, got %d", ds0)
	}
}
