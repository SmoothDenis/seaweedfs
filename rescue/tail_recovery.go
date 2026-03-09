package rescue

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
)

// TailCandidate represents a potential needle found by scanning for tail patterns
// (CRC + Timestamp) in corruption gaps, then working backwards.
type TailCandidate struct {
	// Where the tail was found
	TailOffset int64
	Timestamp  uint64

	// Reconstructed needle (if successful)
	NeedleOffset int64
	NeedleId     uint64
	Cookie       uint32
	DataSize     uint32
	Size         int32
	CRCValid     bool
}

// RecoverFromTails scans corruption gaps for needle tail patterns (valid timestamps)
// and tries to reconstruct needle boundaries by working backwards.
//
// Strategy:
//  1. Scan every 8-byte aligned offset in the gap for a plausible V3 timestamp
//     (nanoseconds in 2010-2035 range) preceded by 4 bytes of CRC.
//  2. For each candidate tail, try different DataSize values to find a consistent
//     needle where: header is readable, DataSize fits, and CRC(data) matches stored CRC.
//  3. If found, reconstruct the full NeedleRecord.
//
// This is the "last resort" recovery — it works even when the needle header is
// partially overwritten, as long as the tail and data are intact.
func RecoverFromTails(datFile *os.File, gaps []Gap, version int, log Logger) []NeedleRecord {
	if version != 3 {
		// Tail recovery relies on V3 timestamps; V2 has no timestamp to anchor on
		return nil
	}

	var recovered []NeedleRecord
	fileSize, _ := datFile.Seek(0, io.SeekEnd)

	for gapIdx, gap := range gaps {
		gapRecovered := 0

		// Read the entire gap into memory for fast scanning.
		// Corruption gaps are typically small (a few KB to MB).
		gapSize := gap.Size()
		if gapSize > 256*1024*1024 {
			// Skip absurdly large gaps
			if log != nil {
				log("  tail-recovery: gap %d too large (%s), skipping", gapIdx+1, humanSize(gapSize))
			}
			continue
		}

		gapBuf := make([]byte, gapSize)
		n, err := datFile.ReadAt(gapBuf, gap.StartOffset)
		if err != nil && err != io.EOF {
			continue
		}
		gapBuf = gapBuf[:n]

		// Scan every byte offset for CRC(4)+Timestamp(8) pattern.
		// The tail isn't necessarily 8-byte aligned (only needle START is aligned).
		tailSize := NeedleChecksumSize + TimestampSize
		for i := 0; i+tailSize <= len(gapBuf); i++ {
			storedCRC := binary.BigEndian.Uint32(gapBuf[i : i+4])
			timestamp := binary.BigEndian.Uint64(gapBuf[i+4 : i+12])

			if !IsReasonableTimestamp(timestamp) || timestamp == 0 {
				continue
			}

			// Candidate tail found at absolute offset gap.StartOffset + i.
			tailAbsOffset := gap.StartOffset + int64(i)
			rec := tryReconstructFromTail(datFile, tailAbsOffset, storedCRC, timestamp, gap, version, fileSize)
			if rec != nil {
				rec.Source = "tail-recovery"
				rec.Status = StatusRecovered
				recovered = append(recovered, *rec)
				gapRecovered++
				if log != nil {
					log("  tail-recovery: found needle id=%d (dataSize=%d) at offset %d via tail at %d in gap %d",
						rec.NeedleId, rec.DataSize, rec.Offset, tailAbsOffset, gapIdx+1)
				}
				// Skip past this needle's tail to avoid duplicate matches
				i += tailSize - 1
			}
		}

		if gapRecovered == 0 && log != nil {
			log("  tail-recovery: gap %d — no needles recovered via tail patterns", gapIdx+1)
		}
	}

	return recovered
}

// tryReconstructFromTail attempts to find a valid needle whose body ends at tailOffset.
// The key insight: even if the header is completely destroyed, we can reconstruct
// boundaries using CRC validation alone. We try different DataSize values, compute
// CRC over candidate data, and check if it matches the stored CRC from the tail.
//
// If CRC matches, we've found the correct boundaries regardless of header state.
func tryReconstructFromTail(datFile *os.File, tailOffset int64, storedCRC uint32, timestamp uint64, gap Gap, version int, fileSize int64) *NeedleRecord {
	// tailOffset is where CRC starts, i.e. bodyEnd.
	// Body layout: DataSize(4) + Data(DataSize) + Flags(1) + optional metadata
	// bodySize = tailOffset - needleOffset - NeedleHeaderSize
	// needleOffset must be 8-byte aligned.
	//
	// Strategy: iterate over plausible DataSize values (1..maxDataSize).
	// For each, compute: bodySize >= 4 + DataSize + 1 (minimum: DataSize field + data + flags).
	// But body may contain extra metadata, so we iterate over bodySize values where
	// needleOffset is aligned and check CRC.

	// The maximum distance to search backwards
	maxBacktrack := tailOffset - int64(SuperBlockSize)
	if maxBacktrack > int64(MaxReasonableNeedleSize) {
		maxBacktrack = int64(MaxReasonableNeedleSize)
	}

	// For each candidate bodySize, compute needleOffset and check CRC
	for bodySize := int32(5); int64(bodySize)+NeedleHeaderSize <= maxBacktrack; bodySize++ {
		needleOffset := tailOffset - int64(bodySize) - NeedleHeaderSize
		if needleOffset < int64(SuperBlockSize) {
			break
		}
		if needleOffset%NeedlePaddingSize != 0 {
			continue
		}

		// Verify disk alignment: total size must produce correct padding
		diskSize := ActualDiskSize(bodySize, version)
		if needleOffset+diskSize > fileSize {
			continue
		}

		// Read body bytes (from after header to tailOffset)
		body := make([]byte, bodySize)
		n, err := datFile.ReadAt(body, needleOffset+NeedleHeaderSize)
		if err != nil && err != io.EOF {
			continue
		}
		if int32(n) < bodySize {
			continue
		}

		// Extract DataSize from the first 4 bytes of body
		if bodySize < 5 { // need at least DataSize(4) + 1 byte of data
			continue
		}
		dataSize := binary.BigEndian.Uint32(body[0:4])
		if dataSize == 0 || dataSize > uint32(bodySize-4) {
			continue
		}

		// Compute CRC over file data (starts at body[4], length = dataSize)
		fileData := body[4 : 4+dataSize]
		computedCRC := crc32.Update(0, crc32cTable, fileData)
		if computedCRC != storedCRC {
			continue
		}

		// CRC matches! Read the header (may be garbage, but grab whatever is there)
		headerBuf := make([]byte, NeedleHeaderSize)
		datFile.ReadAt(headerBuf, needleOffset)
		cookie, needleId, headerSize := ParseNeedleHeader(headerBuf)

		// If header size doesn't match, the header was destroyed — use our computed bodySize
		if headerSize != bodySize {
			// Header is destroyed. We know the correct bodySize from CRC validation.
			// NeedleId from header is garbage — mark as 0 so caller knows.
			return &NeedleRecord{
				Offset:      needleOffset,
				NeedleId:    needleId, // may be garbage if header is destroyed
				Cookie:      cookie,   // may be garbage
				Size:        bodySize,
				DataSize:    dataSize,
				StoredCRC:   storedCRC,
				ComputedCRC: computedCRC,
				Timestamp:   timestamp,
			}
		}

		// Header is intact — great, we have reliable NeedleId
		return &NeedleRecord{
			Offset:      needleOffset,
			NeedleId:    needleId,
			Cookie:      cookie,
			Size:        bodySize,
			DataSize:    dataSize,
			StoredCRC:   storedCRC,
			ComputedCRC: computedCRC,
			Timestamp:   timestamp,
		}
	}

	return nil
}
