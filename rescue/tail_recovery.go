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
//  1. Scan every byte offset in the gap for a plausible V3 timestamp
//     (nanoseconds in 2010-2035 range) preceded by 4 bytes of CRC.
//  2. For each candidate tail, try different bodySize values (8-byte aligned) to find
//     a consistent needle where CRC(data) matches stored CRC.
//  3. If found, reconstruct the full NeedleRecord.
//
// The search is bounded by gap boundaries: a needle's header must be within the gap
// (phase 2 already validated all needles outside gaps), so backtracking is limited
// to the gap size rather than MaxReasonableNeedleSize.
func RecoverFromTails(datFile *os.File, gaps []Gap, version int, superBlockSize int, log Logger) []NeedleRecord {
	if version != 3 {
		// Tail recovery relies on V3 timestamps; V2 has no timestamp to anchor on
		return nil
	}

	var recovered []NeedleRecord
	fileSize, _ := datFile.Seek(0, io.SeekEnd)

	// Process gaps in chunks to limit memory usage (max 4MB per chunk).
	const chunkSize = 4 * 1024 * 1024
	tailSize := NeedleChecksumSize + TimestampSize

	for gapIdx, gap := range gaps {
		gapRecovered := 0
		gapSize := gap.Size()

		if gapSize <= 0 {
			continue
		}

		if log != nil {
			log("  tail-recovery: gap %d/%d (%s, offsets %d-%d)...",
				gapIdx+1, len(gaps), humanSize(gapSize), gap.StartOffset, gap.EndOffset)
		}

		candidateCount := 0

		// Process this gap in chunks
		for chunkStart := gap.StartOffset; chunkStart < gap.EndOffset; chunkStart += chunkSize {
			chunkEnd := chunkStart + chunkSize
			if chunkEnd > gap.EndOffset {
				chunkEnd = gap.EndOffset
			}
			readSize := chunkEnd - chunkStart

			gapBuf := make([]byte, readSize)
			n, err := datFile.ReadAt(gapBuf, chunkStart)
			if err != nil && err != io.EOF {
				continue
			}
			gapBuf = gapBuf[:n]

			// Scan every byte offset for CRC(4)+Timestamp(8) pattern.
			for i := 0; i+tailSize <= len(gapBuf); i++ {
				storedCRC := binary.BigEndian.Uint32(gapBuf[i : i+4])
				timestamp := binary.BigEndian.Uint64(gapBuf[i+4 : i+12])

				if !IsReasonableTimestamp(timestamp) || timestamp == 0 {
					continue
				}

				candidateCount++
				if log != nil && candidateCount%100 == 0 {
					log("  tail-recovery: gap %d — checked %d tail candidates so far (offset %d)...",
						gapIdx+1, candidateCount, chunkStart+int64(i))
				}

				// Candidate tail found at absolute offset chunkStart + i.
				tailAbsOffset := chunkStart + int64(i)
				rec := tryReconstructFromTail(datFile, tailAbsOffset, storedCRC, timestamp, gap, version, fileSize, superBlockSize)
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
		}

		if log != nil {
			log("  tail-recovery: gap %d — %d tail candidates checked, %d needles recovered",
				gapIdx+1, candidateCount, gapRecovered)
		}
	}

	return recovered
}

// tryReconstructFromTail attempts to find a valid needle whose body ends at tailOffset.
// The key insight: even if the header is completely destroyed, we can reconstruct
// boundaries using CRC validation alone. We try different bodySize values, compute
// CRC over candidate data, and check if it matches the stored CRC from the tail.
//
// The search is bounded by the gap: the needle's header must be at or after
// gap.StartOffset (phase 2 already validated everything before the gap).
// bodySize is stepped by NeedlePaddingSize (8) since needleOffset must be 8-byte aligned.
func tryReconstructFromTail(datFile *os.File, tailOffset int64, storedCRC uint32, timestamp uint64, gap Gap, version int, fileSize int64, superBlockSize int) *NeedleRecord {
	// tailOffset is where CRC starts, i.e. bodyEnd.
	// Body layout: DataSize(4) + Data(DataSize) + Flags(1) + optional metadata
	// bodySize = tailOffset - needleOffset - NeedleHeaderSize
	// needleOffset must be 8-byte aligned.

	// The needle's header must be within (or at the start of) the gap.
	// Phase 2 already found all valid needles outside gaps, so needleOffset >= gap.StartOffset.
	// Allow one padding unit before gap as margin for boundary edge cases.
	earliestOffset := gap.StartOffset - NeedlePaddingSize
	if earliestOffset < int64(superBlockSize) {
		earliestOffset = int64(superBlockSize)
	}
	maxBacktrack := tailOffset - earliestOffset
	if maxBacktrack > int64(MaxReasonableNeedleSize) {
		maxBacktrack = int64(MaxReasonableNeedleSize)
	}
	if maxBacktrack < NeedleHeaderSize+5 {
		return nil
	}

	// Find first bodySize >= 5 where needleOffset is 8-byte aligned.
	// needleOffset = tailOffset - bodySize - NeedleHeaderSize
	// Since NeedleHeaderSize (16) is divisible by 8: needleOffset % 8 == (tailOffset - bodySize) % 8
	// So we need bodySize ≡ tailOffset (mod 8).
	rem := int32(tailOffset % NeedlePaddingSize)
	alignedStart := rem
	if alignedStart < 5 {
		alignedStart += int32(NeedlePaddingSize)
	}

	// Pre-allocate buffers: one for the largest body read, one for the header.
	maxBodySize := int32(maxBacktrack - NeedleHeaderSize)
	if maxBodySize < alignedStart {
		return nil
	}
	buf := make([]byte, maxBodySize)
	var headerBuf [NeedleHeaderSize]byte

	for bodySize := alignedStart; int64(bodySize)+NeedleHeaderSize <= maxBacktrack; bodySize += int32(NeedlePaddingSize) {
		needleOffset := tailOffset - int64(bodySize) - NeedleHeaderSize
		if needleOffset < int64(superBlockSize) {
			break
		}

		// Verify disk alignment: total size must produce correct padding
		diskSize := ActualDiskSize(bodySize, version)
		if needleOffset+diskSize > fileSize {
			continue
		}

		// Read body bytes (from after header to tailOffset), reusing pre-allocated buffer
		body := buf[:bodySize]
		n, err := datFile.ReadAt(body, needleOffset+NeedleHeaderSize)
		if err != nil && err != io.EOF {
			continue
		}
		if int32(n) < bodySize {
			continue
		}

		// Extract DataSize from the first 4 bytes of body
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
		datFile.ReadAt(headerBuf[:], needleOffset)
		cookie, needleId, headerSize := ParseNeedleHeader(headerBuf[:])

		// If header size doesn't match, the header was destroyed — use our computed bodySize
		if headerSize != bodySize {
			// Header is destroyed. We know the correct bodySize from CRC validation,
			// but NeedleId/Cookie from header are garbage. Mark HeaderIntact=false
			// so the extractor can exclude this from .idx (garbage NeedleId is dangerous).
			return &NeedleRecord{
				Offset:       needleOffset,
				NeedleId:     needleId, // WARNING: may be garbage if header is destroyed
				Cookie:       cookie,   // WARNING: may be garbage
				Size:         bodySize,
				DataSize:     dataSize,
				StoredCRC:    storedCRC,
				ComputedCRC:  computedCRC,
				Timestamp:    timestamp,
				HeaderIntact: false,
			}
		}

		// Header is intact — great, we have reliable NeedleId
		return &NeedleRecord{
			Offset:       needleOffset,
			NeedleId:     needleId,
			Cookie:       cookie,
			Size:         bodySize,
			DataSize:     dataSize,
			StoredCRC:    storedCRC,
			ComputedCRC:  computedCRC,
			Timestamp:    timestamp,
			HeaderIntact: true,
		}
	}

	return nil
}
