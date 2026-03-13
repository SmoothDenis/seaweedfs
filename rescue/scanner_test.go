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
// Uses Size=-1 (TombstoneFileSize) to match real SeaweedFS semantics.
func buildDeletedNeedleV3(cookie uint32, needleId uint64) []byte {
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], cookie)
	binary.BigEndian.PutUint64(header[4:12], needleId)
	// Size = -1 (0xFFFFFFFF) for tombstone/deleted
	binary.BigEndian.PutUint32(header[12:16], 0xFFFFFFFF)

	// For deleted needles, body size = abs(Size) = 1
	// Body is just 1 byte (the absolute value of -1)
	body := make([]byte, 1)

	tail := make([]byte, NeedleChecksumSize+TimestampSize)
	binary.BigEndian.PutUint64(tail[4:12], 1700000000_000_000_000)

	raw := append(header, body...)
	raw = append(raw, tail...)
	padLen := PaddingLength(-1, 3)
	if padLen > 0 {
		raw = append(raw, make([]byte, padLen)...)
	}
	return raw
}

// buildDeletionMarkerV3 creates a Size=0 deletion marker as SeaweedFS writes when deleting a needle.
// CRC of empty data = 0, timestamp is set to a reasonable value.
func buildDeletionMarkerV3(cookie uint32, needleId uint64) []byte {
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], cookie)
	binary.BigEndian.PutUint64(header[4:12], needleId)
	// Size = 0 (deletion marker)
	binary.BigEndian.PutUint32(header[12:16], 0)

	// CRC of empty data = 0
	tail := make([]byte, NeedleChecksumSize+TimestampSize)
	binary.BigEndian.PutUint32(tail[0:4], 0) // CRC = 0
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

	buf := make([]byte, IdxEntrySize4)
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

		// SeaweedFS padding is always 1-8, never 0
		if pad < 1 || pad > NeedlePaddingSize {
			t.Errorf("size=%d version=%d: invalid padding %d (expected 1-8)", tt.size, tt.version, pad)
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

// --- Integration tests: realistic needle format matching real SeaweedFS ---

const (
	flagHasName             = 0x02
	flagHasMime             = 0x04
	flagHasLastModifiedDate = 0x08
	flagHasTtl              = 0x10
	flagHasPairs            = 0x20
)

// buildRealisticNeedleV3 creates a V3 needle with metadata fields exactly as
// real SeaweedFS writes them: DataSize + Data + Flags + [Name] + [Mime] + [LastMod] + [TTL] + [Pairs].
// CRC is computed over Data only (matching real SeaweedFS).
func buildRealisticNeedleV3(cookie uint32, needleId uint64, data []byte, name string, mime string, lastMod uint64, hasTTL bool, pairs []byte) []byte {
	dataSize := uint32(len(data))

	// Build body: DataSize(4) + Data(N) + Flags(1) + optional fields
	var flags byte
	body := make([]byte, 0, 4+len(data)+1+1+len(name)+1+len(mime)+5+2+2+len(pairs))

	// DataSize
	ds := make([]byte, 4)
	binary.BigEndian.PutUint32(ds, dataSize)
	body = append(body, ds...)

	// Data
	body = append(body, data...)

	// Flags
	if len(name) > 0 {
		flags |= flagHasName
	}
	if len(mime) > 0 {
		flags |= flagHasMime
	}
	if lastMod > 0 {
		flags |= flagHasLastModifiedDate
	}
	if hasTTL {
		flags |= flagHasTtl
	}
	if len(pairs) > 0 {
		flags |= flagHasPairs
	}
	body = append(body, flags)

	// Name
	if len(name) > 0 {
		body = append(body, byte(len(name)))
		body = append(body, []byte(name)...)
	}

	// Mime
	if len(mime) > 0 {
		body = append(body, byte(len(mime)))
		body = append(body, []byte(mime)...)
	}

	// LastModified (5 bytes from uint64, bytes 3-7)
	if lastMod > 0 {
		lm := make([]byte, 8)
		binary.BigEndian.PutUint64(lm, lastMod)
		body = append(body, lm[3:8]...)
	}

	// TTL (2 bytes: count + unit)
	if hasTTL {
		body = append(body, 5, 2) // 5 minutes
	}

	// Pairs
	if len(pairs) > 0 {
		ps := make([]byte, 2)
		binary.BigEndian.PutUint16(ps, uint16(len(pairs)))
		body = append(body, ps...)
		body = append(body, pairs...)
	}

	bodySize := int32(len(body))

	// Header
	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], cookie)
	binary.BigEndian.PutUint64(header[4:12], needleId)
	binary.BigEndian.PutUint32(header[12:16], uint32(bodySize))

	// CRC over Data only (matching real SeaweedFS)
	crc := crc32.Update(0, testCRC32cTable, data)
	tail := make([]byte, NeedleChecksumSize+TimestampSize)
	binary.BigEndian.PutUint32(tail[0:4], crc)
	binary.BigEndian.PutUint64(tail[4:12], 1700000000_000_000_000)

	raw := make([]byte, 0, NeedleHeaderSize+int(bodySize)+len(tail)+NeedlePaddingSize)
	raw = append(raw, header...)
	raw = append(raw, body...)
	raw = append(raw, tail...)

	// Padding (1-8 bytes, matching SeaweedFS)
	padLen := PaddingLength(bodySize, 3)
	raw = append(raw, make([]byte, padLen)...)

	return raw
}

// buildNeedleV2 creates a V2 needle (no timestamp in tail).
func buildNeedleV2(cookie uint32, needleId uint64, data []byte) []byte {
	dataSize := uint32(len(data))
	bodySize := int32(4 + dataSize + 1) // DataSize + Data + Flags

	header := make([]byte, NeedleHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], cookie)
	binary.BigEndian.PutUint64(header[4:12], needleId)
	binary.BigEndian.PutUint32(header[12:16], uint32(bodySize))

	body := make([]byte, bodySize)
	binary.BigEndian.PutUint32(body[0:4], dataSize)
	copy(body[4:4+dataSize], data)
	body[4+dataSize] = 0x00

	crc := crc32.Update(0, testCRC32cTable, data)
	tail := make([]byte, NeedleChecksumSize) // V2: no timestamp
	binary.BigEndian.PutUint32(tail[0:4], crc)

	raw := make([]byte, 0, NeedleHeaderSize+int(bodySize)+NeedleChecksumSize+NeedlePaddingSize)
	raw = append(raw, header...)
	raw = append(raw, body...)
	raw = append(raw, tail...)

	padLen := PaddingLength(bodySize, 2)
	raw = append(raw, make([]byte, padLen)...)

	return raw
}

func buildSuperBlockV2() []byte {
	sb := make([]byte, SuperBlockSize)
	sb[0] = 2 // version 2
	return sb
}

func writeDatFileWithSuperBlock(t *testing.T, dir string, sb []byte, needles ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, "test.dat")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(sb); err != nil {
		t.Fatal(err)
	}
	for _, n := range needles {
		if _, err := f.Write(n); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestRealisticV3NeedlesWithMetadata tests scanning needles that have
// Name, Mime, LastModified, TTL, and Pairs - exactly like real SeaweedFS volumes.
func TestRealisticV3NeedlesWithMetadata(t *testing.T) {
	dir := t.TempDir()

	n1 := buildRealisticNeedleV3(0xAABBCCDD, 1,
		[]byte("Hello, World!"),           // data
		"greeting.txt",                    // name
		"text/plain",                      // mime
		1700000000,                        // lastModified
		false,                             // ttl
		nil,                               // pairs
	)
	n2 := buildRealisticNeedleV3(0x11223344, 2,
		[]byte(`{"key": "value"}`),        // data
		"config.json",                     // name
		"application/json",                // mime
		1700000001,                        // lastModified
		true,                              // ttl
		[]byte(`{"upload":"direct"}`),     // pairs
	)
	n3 := buildRealisticNeedleV3(0x55667788, 3,
		[]byte{0x89, 0x50, 0x4E, 0x47},   // data (fake PNG header)
		"image.png",                       // name
		"image/png",                       // mime
		1700000002,                        // lastModified
		false,                             // ttl
		nil,                               // pairs
	)

	datPath := writeDatFile(t, dir, n1, n2, n3)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
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

	// Verify each needle
	for i, rec := range result.Records {
		if rec.Status != StatusValid {
			t.Errorf("needle %d (id=%d): expected VALID, got %s", i, rec.NeedleId, rec.Status)
		}
		if rec.ComputedCRC != rec.StoredCRC {
			t.Errorf("needle %d (id=%d): CRC mismatch computed=%x stored=%x", i, rec.NeedleId, rec.ComputedCRC, rec.StoredCRC)
		}
	}

	// Verify data sizes match the actual data (not body+metadata)
	expectedDataSizes := []uint32{13, 16, 4} // "Hello, World!", `{"key": "value"}`, 4 bytes PNG
	for i, rec := range result.Records {
		if rec.DataSize != expectedDataSizes[i] {
			t.Errorf("needle %d: expected dataSize %d, got %d", i, expectedDataSizes[i], rec.DataSize)
		}
	}
}

// TestV2Volume tests scanning a Version 2 volume (no timestamp in tail).
func TestV2Volume(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV2(0xAAAAAAAA, 1, []byte("v2 data one"))
	n2 := buildNeedleV2(0xBBBBBBBB, 2, []byte("v2 data two"))
	n3 := buildNeedleV2(0xCCCCCCCC, 3, []byte("v2 data three"))

	datPath := writeDatFileWithSuperBlock(t, dir, buildSuperBlockV2(), n1, n2, n3)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Version != 2 {
		t.Errorf("expected version 2, got %d", result.Version)
	}
	if result.Stats.TotalNeedles != 3 {
		t.Errorf("expected 3 needles, got %d", result.Stats.TotalNeedles)
	}
	if result.Stats.ValidNeedles != 3 {
		t.Errorf("expected 3 valid, got %d", result.Stats.ValidNeedles)
	}
	if len(result.CorruptionGaps) != 0 {
		t.Errorf("expected 0 corruption gaps, got %d", len(result.CorruptionGaps))
	}
}

// TestV2CorruptionRecovery tests that the rescue tool can recover from
// corruption in V2 volumes.
func TestV2CorruptionRecovery(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV2(0xAAAAAAAA, 1, []byte("keep me v2"))
	n2 := buildNeedleV2(0xBBBBBBBB, 2, []byte("corrupt me v2"))
	n3 := buildNeedleV2(0xCCCCCCCC, 3, []byte("keep me too v2"))

	datPath := writeDatFileWithSuperBlock(t, dir, buildSuperBlockV2(), n1, n2, n3)

	// Corrupt needle 2
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	corruptOffset := int64(SuperBlockSize + len(n1))
	garbage := make([]byte, len(n2))
	for i := range garbage {
		garbage[i] = 0xFE
	}
	f.WriteAt(garbage, corruptOffset)
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
		t.Error("needle 1 not found")
	}
	if !foundIds[3] {
		t.Error("needle 3 not recovered after corruption gap in V2 volume")
	}
	if len(result.CorruptionGaps) == 0 {
		t.Error("expected corruption gap in V2 volume")
	}
}

// TestRealisticNeedleExtractWithMetadata tests that extract preserves
// needles with metadata correctly.
func TestRealisticNeedleExtractWithMetadata(t *testing.T) {
	dir := t.TempDir()

	n1 := buildRealisticNeedleV3(0xAABBCCDD, 1,
		[]byte("important data"),
		"document.txt", "text/plain", 1700000000, true, []byte(`{"source":"api"}`))
	n2 := buildRealisticNeedleV3(0x11223344, 2,
		[]byte("corrupt this"),
		"bad.txt", "text/plain", 1700000001, false, nil)
	n3 := buildRealisticNeedleV3(0x55667788, 3,
		[]byte("also important"),
		"another.txt", "text/plain", 1700000002, false, nil)

	datPath := writeDatFile(t, dir, n1, n2, n3)

	// Corrupt needle 2
	f, _ := os.OpenFile(datPath, os.O_RDWR, 0644)
	f.WriteAt(make([]byte, 16), int64(SuperBlockSize+len(n1)))
	f.Close()

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Extract valid needles
	extractPath := filepath.Join(dir, "extracted.dat")
	count, err := ExtractValidNeedles(datPath, result, extractPath)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if count < 2 {
		t.Errorf("expected at least 2 extracted, got %d", count)
	}

	// Re-scan extracted file
	scanner2 := NewScanner(extractPath)
	result2, err := scanner2.Run()
	if err != nil {
		t.Fatalf("scan extracted failed: %v", err)
	}
	if result2.Stats.ValidNeedles < 2 {
		t.Errorf("extracted file: expected at least 2 valid, got %d", result2.Stats.ValidNeedles)
	}
	if len(result2.CorruptionGaps) != 0 {
		t.Errorf("extracted file should have 0 corruption gaps")
	}
}

// TestAlignedSizeNeedles tests needles whose total size (before padding)
// is already 8-byte aligned - this was a bug where padding was incorrectly 0.
func TestAlignedSizeNeedles(t *testing.T) {
	dir := t.TempDir()

	// Craft data sizes that cause aligned totals.
	// For V3: total = 16 + bodySize + 4 + 8 = 28 + bodySize
	// bodySize = 4 + dataLen + 1 (DataSize + Data + Flags)
	// total = 28 + 4 + dataLen + 1 = 33 + dataLen
	// For total % 8 == 0: dataLen = 7 (total=40), dataLen = 15 (total=48), etc.
	// bodySize for dataLen=7: 12. Padding = 8 - ((28+12)%8) = 8 - (40%8) = 8 - 0 = 8

	data7 := []byte("1234567")                // 7 bytes -> bodySize=12, total=40, padding=8
	data15 := []byte("123456789012345")        // 15 bytes -> bodySize=20, total=48, padding=8

	n1 := buildNeedleV3(0x11111111, 1, data7)
	n2 := buildNeedleV3(0x22222222, 2, data15)
	n3 := buildNeedleV3(0x33333333, 3, []byte("after aligned"))

	datPath := writeDatFile(t, dir, n1, n2, n3)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.TotalNeedles != 3 {
		t.Errorf("expected 3 needles, got %d", result.Stats.TotalNeedles)
	}
	if result.Stats.ValidNeedles != 3 {
		t.Errorf("expected 3 valid, got %d (padding bug?)", result.Stats.ValidNeedles)
	}
	if len(result.CorruptionGaps) != 0 {
		t.Errorf("expected 0 corruption gaps, got %d (padding calculation error)", len(result.CorruptionGaps))
	}

	// Verify all 3 needle IDs found
	foundIds := make(map[uint64]bool)
	for _, rec := range result.Records {
		foundIds[rec.NeedleId] = true
	}
	if !foundIds[1] || !foundIds[2] || !foundIds[3] {
		t.Errorf("not all needles found: %v", foundIds)
	}
}

func TestActualDiskSize(t *testing.T) {
	// V3: header(16) + body(size) + checksum(4) + timestamp(8) + padding(1-8)
	// SeaweedFS padding is always 1-8 bytes, never 0.

	// size=10: 16 + 10 + 4 + 8 = 38, pad = 8-(38%8) = 8-6 = 2, total = 40
	ds := ActualDiskSize(10, 3)
	if ds%8 != 0 {
		t.Errorf("disk size %d not 8-byte aligned", ds)
	}
	if ds != 40 {
		t.Errorf("expected 40, got %d", ds)
	}

	// size=0: 16 + 0 + 4 + 8 = 28, pad = 8-(28%8) = 8-4 = 4, total = 32
	ds0 := ActualDiskSize(0, 3)
	if ds0 != 32 {
		t.Errorf("expected 32 for size=0, got %d", ds0)
	}

	// size=4: 16 + 4 + 4 + 8 = 32, pad = 8-(32%8) = 8-0 = 8, total = 40
	// This is the key case: SeaweedFS padding never returns 0.
	ds4 := ActualDiskSize(4, 3)
	if ds4 != 40 {
		t.Errorf("expected 40 for size=4 (padding=8 when aligned), got %d", ds4)
	}

	// size=12: 16 + 12 + 4 + 8 = 40, pad = 8-(40%8) = 8, total = 48
	ds12 := ActualDiskSize(12, 3)
	if ds12 != 48 {
		t.Errorf("expected 48 for size=12, got %d", ds12)
	}

	// V2: size=10: 16 + 10 + 4 = 30, pad = 8-(30%8) = 8-6 = 2, total = 32
	dsV2 := ActualDiskSize(10, 2)
	if dsV2 != 32 {
		t.Errorf("expected 32 for V2 size=10, got %d", dsV2)
	}

	// V2: size=4: 16 + 4 + 4 = 24, pad = 8-(24%8) = 8-0 = 8, total = 32
	dsV2_4 := ActualDiskSize(4, 2)
	if dsV2_4 != 32 {
		t.Errorf("expected 32 for V2 size=4, got %d", dsV2_4)
	}
}

// --- Deletion marker tests ---

func TestScanDeletionMarker(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("hello"))
	dm := buildDeletionMarkerV3(0x11111111, 1) // deletion marker for same NeedleId
	n2 := buildNeedleV3(0x22222222, 2, []byte("world"))

	datPath := writeDatFile(t, dir, n1, dm, n2)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.TotalNeedles != 3 {
		t.Errorf("expected 3 total needles, got %d", result.Stats.TotalNeedles)
	}
	if result.Stats.ValidNeedles != 2 {
		t.Errorf("expected 2 valid needles, got %d", result.Stats.ValidNeedles)
	}
	if result.Stats.DeletionMarkers != 1 {
		t.Errorf("expected 1 deletion marker, got %d", result.Stats.DeletionMarkers)
	}

	// Verify the deletion marker has the correct status
	foundMarker := false
	for _, rec := range result.Records {
		if rec.Status == StatusDeletionMarker {
			foundMarker = true
			if rec.Size != 0 {
				t.Errorf("deletion marker should have Size=0, got %d", rec.Size)
			}
		}
	}
	if !foundMarker {
		t.Error("deletion marker not found in records")
	}
}

func TestScanMixedDeletedAndMarkers(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("data"))
	dm := buildDeletionMarkerV3(0x22222222, 2)  // Size=0 deletion marker
	del := buildDeletedNeedleV3(0x33333333, 3)   // Size=-1 tombstone
	n2 := buildNeedleV3(0x44444444, 4, []byte("more data"))

	datPath := writeDatFile(t, dir, n1, dm, del, n2)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.TotalNeedles != 4 {
		t.Errorf("expected 4 total needles, got %d", result.Stats.TotalNeedles)
	}
	if result.Stats.ValidNeedles != 2 {
		t.Errorf("expected 2 valid, got %d", result.Stats.ValidNeedles)
	}
	if result.Stats.DeletionMarkers != 1 {
		t.Errorf("expected 1 deletion marker, got %d", result.Stats.DeletionMarkers)
	}
	if result.Stats.DeletedNeedles != 1 {
		t.Errorf("expected 1 deleted (Size<0), got %d", result.Stats.DeletedNeedles)
	}
}

func TestExtractSkipsDeletionMarkers(t *testing.T) {
	dir := t.TempDir()
	n1 := buildNeedleV3(0x11111111, 1, []byte("keep this"))
	dm := buildDeletionMarkerV3(0x11111111, 1) // deletion marker
	n2 := buildNeedleV3(0x22222222, 2, []byte("keep this too"))

	datPath := writeDatFile(t, dir, n1, dm, n2)

	scanner := NewScanner(datPath)
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Extract
	outPath := filepath.Join(dir, "out.dat")
	count, err := ExtractValidNeedles(datPath, result, outPath)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}

	// Should extract 2 valid needles, NOT the deletion marker
	// But dedup means only 1 per NeedleId, so needleId=1 valid wins over marker
	if count != 2 {
		t.Errorf("expected 2 extracted needles, got %d", count)
	}

	// Scan the output — should have no deletion markers
	outScanner := NewScanner(outPath)
	outResult, err := outScanner.Run()
	if err != nil {
		t.Fatalf("output scan failed: %v", err)
	}
	if outResult.Stats.DeletionMarkers != 0 {
		t.Errorf("output should have 0 deletion markers, got %d", outResult.Stats.DeletionMarkers)
	}
	if outResult.Stats.ValidNeedles != 2 {
		t.Errorf("output should have 2 valid needles, got %d", outResult.Stats.ValidNeedles)
	}
}

func TestStatsWithIdx(t *testing.T) {
	dir := t.TempDir()

	n1 := buildNeedleV3(0x11111111, 100, []byte("active file"))
	n2 := buildNeedleV3(0x22222222, 200, []byte("will be deleted"))
	dm := buildDeletionMarkerV3(0x22222222, 200) // deletion marker for n2
	n3 := buildNeedleV3(0x33333333, 300, []byte("another active"))

	datPath := writeDatFile(t, dir, n1, n2, dm, n3)

	// Build idx: n1 active, n2 tombstoned (points to dm offset), n3 active
	n1Offset := int64(SuperBlockSize)
	n1DiskSize := ActualDiskSize(int32(4+len("active file")+1), 3)
	n2Offset := n1Offset + n1DiskSize
	n2DiskSize := ActualDiskSize(int32(4+len("will be deleted")+1), 3)
	dmOffset := n2Offset + n2DiskSize
	dmDiskSize := ActualDiskSize(0, 3)
	n3Offset := dmOffset + dmDiskSize

	idxPath := writeIdxFile(t, dir, []IdxEntry{
		{NeedleId: 100, Offset: n1Offset, Size: int32(4 + len("active file") + 1)},
		{NeedleId: 200, Offset: dmOffset, Size: -1}, // tombstone pointing to deletion marker
		{NeedleId: 300, Offset: n3Offset, Size: int32(4 + len("another active") + 1)},
	})

	scanner := NewScanner(datPath)
	scanner.IdxPath = idxPath
	result, err := scanner.Run()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.Stats.IdxActive != 2 {
		t.Errorf("expected 2 active idx entries, got %d", result.Stats.IdxActive)
	}
	if result.Stats.IdxTombstoned != 1 {
		t.Errorf("expected 1 tombstoned idx entry, got %d", result.Stats.IdxTombstoned)
	}
	if result.Stats.DeletionMarkers != 1 {
		t.Errorf("expected 1 deletion marker, got %d", result.Stats.DeletionMarkers)
	}
	if result.Stats.ValidNeedles != 3 {
		t.Errorf("expected 3 valid needles (n1, n2 original, n3), got %d", result.Stats.ValidNeedles)
	}
}

func TestDeduplicateWithDeletionMarker(t *testing.T) {
	// When same NeedleId has both Valid and DeletionMarker records,
	// Valid should win because it has higher priority
	records := []NeedleRecord{
		{NeedleId: 1, Status: StatusDeletionMarker, Size: 0, Offset: 100},
		{NeedleId: 1, Status: StatusValid, Size: 10, Offset: 8},
		{NeedleId: 2, Status: StatusValid, Size: 20, Offset: 50},
	}
	deduped := DeduplicateByNeedleId(records)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped records, got %d", len(deduped))
	}
	for _, rec := range deduped {
		if rec.NeedleId == 1 {
			if rec.Status != StatusValid {
				t.Errorf("NeedleId=1 should be Valid after dedup, got %s", rec.Status)
			}
			if rec.Size != 10 {
				t.Errorf("NeedleId=1 should have Size=10, got %d", rec.Size)
			}
		}
	}
}
