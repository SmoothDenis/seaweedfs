package rescue

import (
	"encoding/binary"
	"hash/crc32"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// ComputeCRC32C computes CRC32 Castagnoli over data bytes.
func ComputeCRC32C(data []byte) uint32 {
	return crc32.Update(0, crc32cTable, data)
}

// ParseNeedleHeader extracts Cookie, NeedleId, Size from a 16-byte header.
func ParseNeedleHeader(header []byte) (cookie uint32, needleId uint64, size int32) {
	cookie = binary.BigEndian.Uint32(header[0:CookieSize])
	needleId = binary.BigEndian.Uint64(header[CookieSize : CookieSize+NeedleIdSize])
	size = int32(binary.BigEndian.Uint32(header[CookieSize+NeedleIdSize : NeedleHeaderSize]))
	return
}

// IsReasonableSize checks if a Size value could plausibly be a real needle.
func IsReasonableSize(size int32) bool {
	if size == 0 {
		return true // deleted needle with zero size
	}
	abs := size
	if abs < 0 {
		if abs == -1 { // TombstoneFileSize (0xFFFFFFFF as int32)
			return true
		}
		abs = -abs
	}
	return abs > 0 && abs <= MaxReasonableNeedleSize
}

// IsReasonableTimestamp checks if a nanosecond timestamp is within a plausible range.
func IsReasonableTimestamp(ts uint64) bool {
	if ts == 0 {
		return true // unset is ok
	}
	return ts >= MinReasonableTimestamp && ts <= MaxReasonableTimestamp
}

// ValidateNeedleAtOffset reads and validates a needle at the given offset in a .dat file.
// Returns a NeedleRecord with status and computed CRC.
// The data parameter should contain bytes from offset to offset+NeedleHeaderSize+bodyLength+tailSize.
func ValidateNeedleAtOffset(data []byte, offset int64, version int) (NeedleRecord, bool) {
	rec := NeedleRecord{Offset: offset}

	if len(data) < NeedleHeaderSize {
		rec.Status = StatusCorruptedHeader
		return rec, false
	}

	rec.Cookie, rec.NeedleId, rec.Size = ParseNeedleHeader(data[:NeedleHeaderSize])

	if !IsReasonableSize(rec.Size) {
		rec.Status = StatusCorruptedHeader
		return rec, false
	}

	// Deleted needle
	if rec.Size <= 0 {
		// Sanity: NeedleId must be nonzero and not all-ones (garbage pattern)
		if rec.NeedleId == 0 || rec.NeedleId == 0xFFFFFFFFFFFFFFFF {
			rec.Status = StatusCorruptedHeader
			return rec, false
		}
		rec.Status = StatusDeleted
		return rec, true
	}

	bodyStart := NeedleHeaderSize
	bodyEnd := bodyStart + int(rec.Size)

	// Need at least body + checksum
	tailSize := NeedleChecksumSize
	if version == 3 {
		tailSize = NeedleChecksumSize + TimestampSize
	}
	needed := bodyEnd + tailSize
	if len(data) < needed {
		rec.Status = StatusCorruptedHeader
		return rec, false
	}

	// Extract DataSize (first 4 bytes of body)
	if rec.Size >= 4 {
		rec.DataSize = binary.BigEndian.Uint32(data[bodyStart : bodyStart+4])
	}

	// Validate DataSize against Size
	if rec.DataSize > uint32(rec.Size) {
		rec.Status = StatusCorruptedData
		return rec, false
	}

	// Extract actual file data for CRC computation
	fileDataStart := bodyStart + 4 // skip DataSize field
	fileDataEnd := fileDataStart + int(rec.DataSize)
	if fileDataEnd > bodyEnd {
		rec.Status = StatusCorruptedData
		return rec, false
	}

	fileData := data[fileDataStart:fileDataEnd]
	rec.ComputedCRC = ComputeCRC32C(fileData)

	// Read stored CRC from tail
	rec.StoredCRC = binary.BigEndian.Uint32(data[bodyEnd : bodyEnd+NeedleChecksumSize])

	// Read timestamp if V3
	if version == 3 && len(data) >= bodyEnd+NeedleChecksumSize+TimestampSize {
		rec.Timestamp = binary.BigEndian.Uint64(data[bodyEnd+NeedleChecksumSize : bodyEnd+NeedleChecksumSize+TimestampSize])
	}

	if rec.ComputedCRC == rec.StoredCRC {
		rec.Status = StatusValid
		return rec, true
	}

	rec.Status = StatusCorruptedData
	return rec, false
}
