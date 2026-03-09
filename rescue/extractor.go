package rescue

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

// RebuildIdx rebuilds only the .idx file from scan results without touching the .dat file.
// It uses the original offsets from the scan, so the .dat must remain unchanged.
// Uses atomic write (temp + fsync + rename) to prevent corruption on crash.
func RebuildIdx(datPath string, result *ScanResult) (int, error) {
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
	for _, rec := range validRecords {
		idxEntries = append(idxEntries, idxWriteEntry{
			needleId: rec.NeedleId,
			offset:   rec.Offset,
			size:     rec.Size,
		})
	}

	idxPath := datPath[:len(datPath)-4] + ".idx"
	if err := writeIdxEntriesSafe(idxPath, idxEntries); err != nil {
		return 0, fmt.Errorf("write idx: %w", err)
	}
	return len(idxEntries), nil
}

// ExtractValidNeedles copies valid needles from a source .dat to a new clean .dat + .idx pair.
// By default only StatusValid/StatusRecovered/StatusDeleted are included.
// If includeCorrupted is true, StatusCorruptedData needles are also included
// (their header is intact so they can be read, but data may be partially damaged).
//
// Uses atomic writes: both .dat and .idx are written to temp files first, then
// fsync'd and renamed. If the process crashes mid-write, no partial files are left.
func ExtractValidNeedles(srcDatPath string, result *ScanResult, dstDatPath string, includeCorrupted ...bool) (int, error) {
	withCorrupted := len(includeCorrupted) > 0 && includeCorrupted[0]

	src, err := os.Open(srcDatPath)
	if err != nil {
		return 0, fmt.Errorf("open source dat: %w", err)
	}
	defer src.Close()

	// Use SafeWriter for atomic output
	sw, err := NewSafeWriter(dstDatPath)
	if err != nil {
		return 0, fmt.Errorf("create safe writer for dat: %w", err)
	}
	dst := sw.File()

	// Write superblock
	if _, err := dst.Write(result.SuperBlockData); err != nil {
		sw.Abort()
		return 0, fmt.Errorf("write superblock: %w", err)
	}

	// Sort records by offset for sequential reading
	validRecords := make([]NeedleRecord, 0, len(result.Records))
	for _, rec := range result.Records {
		switch rec.Status {
		case StatusValid, StatusRecovered, StatusDeleted:
			validRecords = append(validRecords, rec)
		case StatusCorruptedData:
			if withCorrupted {
				validRecords = append(validRecords, rec)
			}
		}
	}
	sort.Slice(validRecords, func(i, j int) bool {
		return validRecords[i].Offset < validRecords[j].Offset
	})

	// Copy valid needles and build idx entries
	var idxEntries []idxWriteEntry
	written := 0

	for _, rec := range validRecords {
		diskSize := rec.ActualDiskSize(result.Version)

		// Read original needle bytes
		buf := make([]byte, diskSize)
		n, err := src.ReadAt(buf, rec.Offset)
		if err != nil && err != io.EOF {
			sw.Abort()
			return written, fmt.Errorf("read needle at offset %d: %w", rec.Offset, err)
		}
		if int64(n) < diskSize {
			continue // truncated, skip
		}

		// Record new offset before writing
		newOffset, err := dst.Seek(0, io.SeekCurrent)
		if err != nil {
			sw.Abort()
			return written, fmt.Errorf("seek dest: %w", err)
		}

		if _, err := dst.Write(buf[:diskSize]); err != nil {
			sw.Abort()
			return written, fmt.Errorf("write needle: %w", err)
		}

		idxEntries = append(idxEntries, idxWriteEntry{
			needleId: rec.NeedleId,
			offset:   newOffset,
			size:     rec.Size,
		})
		written++
	}

	// Commit .dat atomically (fsync + rename)
	if err := sw.Commit(); err != nil {
		return written, fmt.Errorf("commit dat: %w", err)
	}

	// Write .idx atomically
	idxPath := dstDatPath[:len(dstDatPath)-4] + ".idx"
	if err := writeIdxEntriesSafe(idxPath, idxEntries); err != nil {
		// .dat was committed but .idx failed — remove .dat to avoid inconsistency
		os.Remove(dstDatPath)
		return written, fmt.Errorf("write idx (dat rolled back): %w", err)
	}

	return written, nil
}

type idxWriteEntry struct {
	needleId uint64
	offset   int64
	size     int32
}

// writeIdxEntriesSafe writes idx entries atomically via temp + fsync + rename.
func writeIdxEntriesSafe(path string, entries []idxWriteEntry) error {
	sw, err := NewSafeWriter(path)
	if err != nil {
		return err
	}

	f := sw.File()
	buf := make([]byte, IdxEntrySize)
	for _, e := range entries {
		binary.BigEndian.PutUint64(buf[0:8], e.needleId)
		binary.BigEndian.PutUint32(buf[8:12], uint32(e.offset/NeedlePaddingSize))
		binary.BigEndian.PutUint32(buf[12:16], uint32(e.size))
		if _, err := f.Write(buf); err != nil {
			sw.Abort()
			return err
		}
	}

	return sw.Commit()
}
