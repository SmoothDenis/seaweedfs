package rescue

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"
)

// RepairResult describes the outcome of a CRC repair attempt on one needle.
type RepairResult struct {
	NeedleId       uint64
	Offset         int64
	DataSize       uint32
	ByteOffset     int    // position within file data where corruption was found (-1 if not repairable)
	OrigByte       byte   // original (corrupted) byte value
	FixedByte      byte   // correct byte value
	StoredCRC      uint32 // CRC from the needle tail
	Repaired       bool   // true if exactly one single-byte fix was found
	MultiErrors    bool   // true if data has more than one corrupted byte (not auto-repairable)
	Ambiguous      bool   // true if multiple single-byte fixes found (CRC collision — unsafe to apply)
	AmbiguousCount int    // number of different single-byte fixes that match the CRC
}

// maxRepairDataSize is the largest file data we'll attempt byte-level repair on.
// For a 10 MB file: 10M × 256 CRC ops ≈ 2.5 billion ops — takes a few seconds.
// Beyond this, repair is still correct but too slow to be practical.
const maxRepairDataSize = 10 * 1024 * 1024 // 10 MB

// AttemptRepair tries to fix single-byte corruption in a corrupted-data needle.
// It reads the needle data, tries flipping each byte to all 256 values,
// and checks if any single-byte change makes the CRC match the stored value.
//
// This works because bit rot typically corrupts a small number of bytes.
// For single-byte errors (the most common case), this always finds the fix.
func AttemptRepair(datFile *os.File, rec NeedleRecord, version int) RepairResult {
	result := RepairResult{
		NeedleId:  rec.NeedleId,
		Offset:    rec.Offset,
		DataSize:  rec.DataSize,
		StoredCRC: rec.StoredCRC,
		ByteOffset: -1,
	}

	if rec.DataSize > maxRepairDataSize {
		return result
	}

	// Read the file data portion of the needle
	fileDataStart := rec.Offset + NeedleHeaderSize + 4 // skip header + DataSize field
	fileData := make([]byte, rec.DataSize)
	n, err := datFile.ReadAt(fileData, fileDataStart)
	if err != nil && err != io.EOF {
		return result
	}
	if uint32(n) < rec.DataSize {
		return result
	}

	// Try each byte position — collect ALL matches to detect CRC collisions.
	// CRC32 has ~1/2^32 collision probability per trial. For large needles
	// (e.g. 10MB × 255 trials ≈ 2.5 billion attempts), false positives are likely.
	// If multiple fixes are found, we cannot determine which is correct.
	type match struct {
		pos      int
		origByte byte
		fixByte  byte
	}
	var matches []match

	targetCRC := rec.StoredCRC
	for pos := 0; pos < len(fileData); pos++ {
		origByte := fileData[pos]
		for trial := 0; trial < 256; trial++ {
			b := byte(trial)
			if b == origByte {
				continue
			}
			fileData[pos] = b
			if crc32.Update(0, crc32cTable, fileData) == targetCRC {
				matches = append(matches, match{pos: pos, origByte: origByte, fixByte: b})
				// Don't break — keep scanning this position for more matches at same byte
			}
		}
		fileData[pos] = origByte // restore original
	}

	if len(matches) == 0 {
		// No single-byte fix found — corruption spans multiple bytes
		result.MultiErrors = true
		return result
	}

	if len(matches) == 1 {
		// Exactly one fix — safe to apply
		result.ByteOffset = matches[0].pos
		result.OrigByte = matches[0].origByte
		result.FixedByte = matches[0].fixByte
		result.Repaired = true
		return result
	}

	// Multiple fixes found — CRC collision, unsafe to apply
	result.Ambiguous = true
	result.AmbiguousCount = len(matches)
	return result
}

// DryRunResult holds the results of a repair dry-run.
type DryRunResult struct {
	Total      int
	Repairable int
	Results    []RepairResult
}

// DryRunRepair checks which corrupted needles can be fixed without writing any files.
func DryRunRepair(datPath string, result *ScanResult, log Logger) (*DryRunResult, error) {
	src, err := os.Open(datPath)
	if err != nil {
		return nil, fmt.Errorf("open dat: %w", err)
	}
	defer src.Close()

	dr := &DryRunResult{}
	for _, rec := range result.Records {
		if rec.Status != StatusCorruptedData {
			continue
		}
		dr.Total++
		if log != nil {
			log("  dry-run: checking needle id=%d (dataSize=%d)...", rec.NeedleId, rec.DataSize)
		}
		rr := AttemptRepair(src, rec, result.Version)
		dr.Results = append(dr.Results, rr)
		if rr.Repaired {
			dr.Repairable++
			if log != nil {
				log("  dry-run: needle id=%d FIXABLE — byte %d: 0x%02X → 0x%02X",
					rec.NeedleId, rr.ByteOffset, rr.OrigByte, rr.FixedByte)
			}
		} else if rr.Ambiguous {
			if log != nil {
				log("  dry-run: needle id=%d AMBIGUOUS — %d possible fixes (CRC collision, unsafe to apply)",
					rec.NeedleId, rr.AmbiguousCount)
			}
		} else if rr.MultiErrors {
			if log != nil {
				log("  dry-run: needle id=%d NOT FIXABLE (multi-byte corruption)", rec.NeedleId)
			}
		}
	}

	return dr, nil
}

// RepairAndExtract attempts CRC repair on corrupted needles, then extracts
// all recoverable data (valid + recovered + repaired) to a new .dat + .idx pair.
func RepairAndExtract(srcDatPath string, result *ScanResult, dstDatPath string, log Logger) (extracted int, repaired int, err error) {
	src, err := os.Open(srcDatPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open source dat: %w", err)
	}
	defer src.Close()

	// Attempt repair on all corrupted-data needles
	var repairs []RepairResult
	for i, rec := range result.Records {
		if rec.Status != StatusCorruptedData {
			continue
		}
		if log != nil {
			log("  repair: trying needle id=%d (dataSize=%d, offset=%d)...", rec.NeedleId, rec.DataSize, rec.Offset)
		}
		rr := AttemptRepair(src, rec, result.Version)
		if rr.Repaired {
			repairs = append(repairs, rr)
			result.Records[i].Status = StatusRepaired
			if log != nil {
				log("  repair: FIXED needle id=%d — byte %d: 0x%02X → 0x%02X",
					rec.NeedleId, rr.ByteOffset, rr.OrigByte, rr.FixedByte)
			}
		} else if rr.Ambiguous {
			if log != nil {
				log("  repair: needle id=%d AMBIGUOUS — %d possible fixes (CRC collision, skipping to avoid data corruption)",
					rec.NeedleId, rr.AmbiguousCount)
			}
		} else if rr.MultiErrors {
			if log != nil {
				log("  repair: needle id=%d has multi-byte corruption (not auto-repairable)", rec.NeedleId)
			}
		} else if rec.DataSize > maxRepairDataSize {
			if log != nil {
				log("  repair: needle id=%d too large for byte-level repair (%d bytes)", rec.NeedleId, rec.DataSize)
			}
		}
	}

	// Build repair lookup: offset → RepairResult
	repairMap := make(map[int64]RepairResult)
	for _, rr := range repairs {
		repairMap[rr.Offset] = rr
	}

	// Extract: valid + recovered + deleted + repaired (atomic write)
	sw, err := NewSafeWriter(dstDatPath)
	if err != nil {
		return 0, 0, fmt.Errorf("create safe writer for dat: %w", err)
	}
	dst := sw.File()

	if _, err := dst.Write(result.SuperBlockData); err != nil {
		sw.Abort()
		return 0, 0, fmt.Errorf("write superblock: %w", err)
	}

	validRecords := make([]NeedleRecord, 0, len(result.Records))
	for _, rec := range result.Records {
		switch rec.Status {
		case StatusValid, StatusRecovered, StatusDeleted, StatusRepaired:
			validRecords = append(validRecords, rec)
		}
	}
	sort.Slice(validRecords, func(i, j int) bool {
		return validRecords[i].Offset < validRecords[j].Offset
	})

	var idxEntries []idxWriteEntry
	written := 0
	repairedCount := 0

	for _, rec := range validRecords {
		diskSize := rec.ActualDiskSize(result.Version)

		buf := make([]byte, diskSize)
		n, err := src.ReadAt(buf, rec.Offset)
		if err != nil && err != io.EOF {
			sw.Abort()
			return written, repairedCount, fmt.Errorf("read needle at offset %d: %w", rec.Offset, err)
		}
		if int64(n) < diskSize {
			continue
		}

		// Apply repair patch if this needle was repaired
		if rr, ok := repairMap[rec.Offset]; ok && rr.Repaired {
			patchOffset := NeedleHeaderSize + 4 + rr.ByteOffset // header + DataSize field + position in file data
			buf[patchOffset] = rr.FixedByte
			// Recompute and write correct CRC to tail
			bodyEnd := NeedleHeaderSize + int(rec.Size)
			binary.BigEndian.PutUint32(buf[bodyEnd:bodyEnd+NeedleChecksumSize], rr.StoredCRC)
			repairedCount++
		}

		newOffset, err := dst.Seek(0, io.SeekCurrent)
		if err != nil {
			sw.Abort()
			return written, repairedCount, fmt.Errorf("seek dest: %w", err)
		}

		if _, err := dst.Write(buf[:diskSize]); err != nil {
			sw.Abort()
			return written, repairedCount, fmt.Errorf("write needle: %w", err)
		}

		idxEntries = append(idxEntries, idxWriteEntry{
			needleId: rec.NeedleId,
			offset:   newOffset,
			size:     rec.Size,
		})
		written++
	}

	// Commit .dat atomically
	if err := sw.Commit(); err != nil {
		return written, repairedCount, fmt.Errorf("commit dat: %w", err)
	}

	// Write .idx atomically
	idxPath := dstDatPath[:len(dstDatPath)-4] + ".idx"
	if err := writeIdxEntriesSafe(idxPath, idxEntries); err != nil {
		os.Remove(dstDatPath)
		return written, repairedCount, fmt.Errorf("write idx (dat rolled back): %w", err)
	}

	return written, repairedCount, nil
}

// Known file signatures for content-type sniffing in corruption gaps.
var fileSignatures = []struct {
	Magic  []byte
	Offset int // offset from start of data where magic appears
	Name   string
}{
	{[]byte{0xFF, 0xD8, 0xFF}, 0, "JPEG image"},
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "PNG image"},
	{[]byte("GIF87a"), 0, "GIF image"},
	{[]byte("GIF89a"), 0, "GIF image"},
	{[]byte{0x52, 0x49, 0x46, 0x46}, 0, "RIFF (WebP/AVI/WAV)"},
	{[]byte("%PDF"), 0, "PDF document"},
	{[]byte("PK\x03\x04"), 0, "ZIP archive"},
	{[]byte{0x1F, 0x8B}, 0, "gzip compressed"},
	{[]byte{0x42, 0x5A, 0x68}, 0, "bzip2 compressed"},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A}, 0, "xz compressed"},
	{[]byte("ftyp"), 4, "MP4/MOV video"}, // ftyp box: 4 bytes size + "ftyp" at offset 4
	{[]byte("ID3"), 0, "MP3 audio (ID3)"},
	{[]byte{0xFF, 0xFB}, 0, "MP3 audio"},
	{[]byte{0xFF, 0xF3}, 0, "MP3 audio"},
	{[]byte("OggS"), 0, "OGG audio/video"},
	{[]byte{0x1A, 0x45, 0xDF, 0xA3}, 0, "WebM/MKV video"},
}

// GapSignature describes a file signature found within a corruption gap.
type GapSignature struct {
	GapIndex int
	Offset   int64
	FileType string
}

// DetectSignaturesInGaps scans corruption gaps for known file signatures.
// This helps users understand what types of files were lost.
func DetectSignaturesInGaps(datFile *os.File, gaps []Gap) []GapSignature {
	var found []GapSignature
	buf := make([]byte, 4096) // read in chunks

	for i, gap := range gaps {
		// Scan the gap looking for file magic bytes
		for offset := gap.StartOffset; offset < gap.EndOffset; offset += NeedlePaddingSize {
			n, err := datFile.ReadAt(buf, offset)
			if err != nil && err != io.EOF {
				break
			}
			if n < 16 {
				continue
			}

			// The actual file data inside a needle starts at header(16) + DataSize(4) = 20 bytes from needle start
			// But since the header might be corrupted, also check at raw offset
			checkPoints := []int{0, NeedleHeaderSize + 4}
			for _, cp := range checkPoints {
				if cp+16 > n {
					continue
				}
				chunk := buf[cp:n]
				for _, sig := range fileSignatures {
					if sig.Offset+len(sig.Magic) <= len(chunk) {
						if bytes.HasPrefix(chunk[sig.Offset:], sig.Magic) {
							found = append(found, GapSignature{
								GapIndex: i,
								Offset:   offset + int64(cp),
								FileType: sig.Name,
							})
							break // one match per check point
						}
					}
				}
			}
		}
	}

	return found
}
