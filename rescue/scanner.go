package rescue

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

// Logger is a callback for progress/diagnostic messages.
// If nil, no logging is performed.
type Logger func(format string, args ...interface{})

type Scanner struct {
	DatPath    string
	IdxPath    string
	Version    int
	DeepScan   bool
	Verbose    bool
	Log        Logger // progress logging callback
	datFile    *os.File
	datSize    int64
	headerBuf  [NeedleHeaderSize]byte // reused across validateAtOffset calls
	idxEntries map[uint64]IdxEntry
}

func (s *Scanner) log(format string, args ...interface{}) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

func NewScanner(datPath string) *Scanner {
	return &Scanner{
		DatPath: datPath,
		Version: 0, // auto-detect
	}
}

func (s *Scanner) Run() (*ScanResult, error) {
	var err error
	s.datFile, err = os.Open(s.DatPath)
	if err != nil {
		return nil, fmt.Errorf("open dat file: %w", err)
	}
	defer s.datFile.Close()

	stat, err := s.datFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat dat file: %w", err)
	}
	s.datSize = stat.Size()

	result := &ScanResult{
		DatFileSize: s.datSize,
		datPath:     s.DatPath,
	}

	// Read superblock (minimum 8 bytes, may be larger with ExtraSize)
	if s.datSize < SuperBlockSize {
		return nil, fmt.Errorf("dat file too small: %d bytes", s.datSize)
	}
	header := make([]byte, SuperBlockSize)
	if _, err := s.datFile.ReadAt(header, 0); err != nil {
		return nil, fmt.Errorf("read superblock: %w", err)
	}

	// Auto-detect version from superblock byte 0
	if s.Version == 0 {
		s.Version = int(header[0])
		if s.Version < 1 || s.Version > 3 {
			return nil, fmt.Errorf("invalid version %d in superblock", s.Version)
		}
	}
	if s.Version == 1 {
		return nil, fmt.Errorf("needle version 1 is not supported (only V2 and V3)")
	}
	result.Version = s.Version

	// Read ExtraSize from superblock bytes 6-7 (V2/V3 may have protobuf extra data)
	extraSize := int(binary.BigEndian.Uint16(header[6:8]))
	superBlockTotal := SuperBlockSize + extraSize
	if int64(superBlockTotal) > s.datSize {
		return nil, fmt.Errorf("superblock ExtraSize=%d exceeds file size", extraSize)
	}

	// Read full superblock including extra data
	result.SuperBlockData = make([]byte, superBlockTotal)
	copy(result.SuperBlockData, header)
	if extraSize > 0 {
		if _, err := s.datFile.ReadAt(result.SuperBlockData[SuperBlockSize:], SuperBlockSize); err != nil {
			return nil, fmt.Errorf("read superblock extra data (%d bytes): %w", extraSize, err)
		}
		s.log("volume: superblock has %d bytes extra data (total %d bytes)", extraSize, superBlockTotal)
	}
	result.SuperBlockSize = superBlockTotal

	s.log("volume: %s (%s, version %d)", s.DatPath, humanSize(s.datSize), s.Version)

	// Load idx if available
	if s.IdxPath != "" {
		s.idxEntries, err = ReadIdxFile(s.IdxPath)
		if err != nil {
			s.log("warning: cannot read idx file: %v (continuing without)", err)
			s.idxEntries = nil
		} else {
			result.Stats.IdxEntries = len(s.idxEntries)
			s.log("loaded %d idx entries from %s", len(s.idxEntries), s.IdxPath)
		}
	}

	startTime := time.Now()

	// Phase 1: idx-guided scan
	if s.idxEntries != nil {
		s.log("[phase 1/3] idx-guided validation of %d entries...", len(s.idxEntries))
		s.phase1IdxGuided(result)
		s.log("[phase 1/3] done: %d matches, %d mismatches", result.Stats.IdxMatches, result.Stats.IdxMismatches)
	}

	// Phase 2: sequential scan with recovery
	s.log("[phase 2/3] sequential scan of %s...", humanSize(s.datSize))
	s.phase2Sequential(result)
	if len(result.CorruptionGaps) == 0 {
		s.log("[phase 2/3] done: %d needles, no corruption", len(result.Records))
	} else {
		s.log("[phase 2/3] done: %d needles found, %d corruption gaps detected", len(result.Records), len(result.CorruptionGaps))
	}

	// Phase 3: deep scan (optional)
	if s.DeepScan && len(result.CorruptionGaps) > 0 {
		totalGapSize := int64(0)
		for _, gap := range result.CorruptionGaps {
			totalGapSize += gap.Size()
		}
		s.log("[phase 3/4] deep scan of %d gaps (%s)...", len(result.CorruptionGaps), humanSize(totalGapSize))
		beforeRecords := len(result.Records)
		s.phase3Deep(result)
		s.log("[phase 3/4] done: recovered %d additional needles", len(result.Records)-beforeRecords)
	} else if s.DeepScan {
		s.log("[phase 3/4] skipped: no corruption gaps to deep scan")
	}

	// Phase 4: tail-pattern recovery (optional, only V3)
	if s.DeepScan && len(result.CorruptionGaps) > 0 && s.Version == 3 {
		totalGapBytes := int64(0)
		for _, g := range result.CorruptionGaps {
			totalGapBytes += g.Size()
		}
		s.log("[phase 4/4] tail-pattern recovery in %d gaps (%s total)...", len(result.CorruptionGaps), humanSize(totalGapBytes))
		seenOffsets := make(map[int64]bool)
		for _, rec := range result.Records {
			seenOffsets[rec.Offset] = true
		}
		tailRecovered := RecoverFromTails(s.datFile, result.CorruptionGaps, s.Version, result.SuperBlockSize, s.Log)
		added := 0
		for _, rec := range tailRecovered {
			if !seenOffsets[rec.Offset] {
				result.Records = append(result.Records, rec)
				seenOffsets[rec.Offset] = true
				added++
			}
		}
		s.log("[phase 4/4] done: recovered %d additional needles via tail patterns", added)
	} else if s.DeepScan && s.Version != 3 {
		s.log("[phase 4/4] skipped: tail-pattern recovery requires V3 (timestamps)")
	}

	// Compute final stats
	s.computeStats(result)

	elapsed := time.Since(startTime)
	throughput := float64(s.datSize) / (1024 * 1024) / elapsed.Seconds()
	s.log("scan completed in %v (%.1f MB/s)", elapsed.Round(time.Millisecond), throughput)

	return result, nil
}

func (s *Scanner) phase1IdxGuided(result *ScanResult) {
	for _, entry := range s.idxEntries {
		if entry.Offset < int64(result.SuperBlockSize) || entry.Offset >= s.datSize {
			continue
		}
		rec := s.validateAtOffset(entry.Offset)
		if rec == nil {
			result.Stats.IdxMismatches++
			continue
		}
		rec.Source = "idx-guided"
		rec.IdxMatch = true
		if rec.NeedleId == entry.NeedleId {
			result.Stats.IdxMatches++
		} else {
			result.Stats.IdxMismatches++
		}
	}
	// Phase 1 validates idx entries but does not add records (phase 2 handles record collection)
}

func (s *Scanner) phase2Sequential(result *ScanResult) {
	offset := int64(result.SuperBlockSize)
	seenOffsets := make(map[int64]bool)
	lastProgressPct := -1

	for offset < s.datSize {
		// Log progress every 10%
		pct := int(float64(offset) / float64(s.datSize) * 100)
		if pct/10 > lastProgressPct/10 && pct > 0 {
			lastProgressPct = pct
			s.log("  scanning... %d%% (offset %d / %d)", pct, offset, s.datSize)
		}
		rec := s.validateAtOffset(offset)
		if rec != nil && (rec.Status == StatusValid || rec.Status == StatusDeleted || rec.Status == StatusCorruptedData || rec.Status == StatusDeletionMarker) {
			rec.Source = "sequential"
			// Cross-reference with idx
			if s.idxEntries != nil {
				if idxEntry, ok := s.idxEntries[rec.NeedleId]; ok && idxEntry.Offset == offset {
					rec.IdxMatch = true
				}
			}
			if !seenOffsets[offset] {
				result.Records = append(result.Records, *rec)
				seenOffsets[offset] = true
			}
			if rec.Status == StatusCorruptedData {
				s.log("  CRC MISMATCH at offset %d: needle id=%d, stored=%08x computed=%08x (data corrupted but header intact)",
					offset, rec.NeedleId, rec.StoredCRC, rec.ComputedCRC)
			}
			offset += rec.ActualDiskSize(s.Version)
			continue
		}

		// Corruption detected - scan forward for next valid needle
		gapStart := offset
		s.log("  CORRUPTION at offset %d: invalid needle header or bad CRC", offset)
		found := false
		scanOffset := offset + NeedlePaddingSize

		for scanOffset < s.datSize {
			candidate := s.validateAtOffset(scanOffset)
			if candidate != nil && (candidate.Status == StatusValid || candidate.Status == StatusDeleted || candidate.Status == StatusDeletionMarker) {
				// Found next valid needle
				gap := Gap{StartOffset: gapStart, EndOffset: scanOffset}
				result.CorruptionGaps = append(result.CorruptionGaps, gap)
				s.log("  RECOVERED at offset %d: found valid needle id=%d after %s gap (offsets %d-%d)",
					scanOffset, candidate.NeedleId, humanSize(gap.Size()), gapStart, scanOffset)
				candidate.Source = "sequential"
				if s.idxEntries != nil {
					if idxEntry, ok := s.idxEntries[candidate.NeedleId]; ok && idxEntry.Offset == scanOffset {
						candidate.IdxMatch = true
					}
				}
				if !seenOffsets[scanOffset] {
					result.Records = append(result.Records, *candidate)
					seenOffsets[scanOffset] = true
				}
				offset = scanOffset + candidate.ActualDiskSize(s.Version)
				found = true
				break
			}
			scanOffset += NeedlePaddingSize
		}

		if !found {
			// Rest of file is corrupted
			gap := Gap{StartOffset: gapStart, EndOffset: s.datSize}
			result.CorruptionGaps = append(result.CorruptionGaps, gap)
			s.log("  LOST tail of volume: %s corrupted from offset %d to end of file", humanSize(gap.Size()), gapStart)
			break
		}
	}
}

func (s *Scanner) phase3Deep(result *ScanResult) {
	seenOffsets := make(map[int64]bool)
	for _, rec := range result.Records {
		seenOffsets[rec.Offset] = true
	}

	for i, gap := range result.CorruptionGaps {
		recoveredInGap := 0
		for offset := gap.StartOffset; offset < gap.EndOffset; offset += NeedlePaddingSize {
			if seenOffsets[offset] {
				continue
			}
			rec := s.validateAtOffset(offset)
			if rec != nil && rec.Status == StatusValid {
				rec.Source = "deep-scan"
				rec.Status = StatusRecovered
				if s.idxEntries != nil {
					if idxEntry, ok := s.idxEntries[rec.NeedleId]; ok && idxEntry.Offset == offset {
						rec.IdxMatch = true
					}
				}
				result.Records = append(result.Records, *rec)
				seenOffsets[offset] = true
				recoveredInGap++
				s.log("  deep-scan: recovered needle id=%d (dataSize=%d) at offset %d inside gap %d",
					rec.NeedleId, rec.DataSize, offset, i+1)
			}
		}
		if recoveredInGap == 0 {
			s.log("  deep-scan: gap %d (offsets %d-%d, %s) — no recoverable needles found",
				i+1, gap.StartOffset, gap.EndOffset, humanSize(gap.Size()))
		}
	}
}

func (s *Scanner) validateAtOffset(offset int64) *NeedleRecord {
	// Read header first to determine size (reuse pre-allocated buffer)
	if _, err := s.datFile.ReadAt(s.headerBuf[:], offset); err != nil {
		return nil
	}

	_, _, size := ParseNeedleHeader(s.headerBuf[:])
	if !IsReasonableSize(size) {
		return nil
	}

	// Calculate total bytes needed
	diskSize := ActualDiskSize(size, s.Version)
	if offset+diskSize > s.datSize {
		// Not enough data - might be valid but truncated
		return nil
	}

	// Read full needle data
	fullBuf := make([]byte, diskSize)
	n, err := s.datFile.ReadAt(fullBuf, offset)
	if err != nil && err != io.EOF {
		return nil
	}
	if int64(n) < diskSize {
		return nil
	}

	rec, _ := ValidateNeedleAtOffset(fullBuf, offset, s.Version)
	return &rec
}

func (s *Scanner) computeStats(result *ScanResult) {
	uniqueIds := make(map[uint64]struct{})
	for _, rec := range result.Records {
		result.Stats.TotalNeedles++
		uniqueIds[rec.NeedleId] = struct{}{}
		switch rec.Status {
		case StatusValid:
			result.Stats.ValidNeedles++
		case StatusDeleted:
			result.Stats.DeletedNeedles++
		case StatusCorruptedData:
			result.Stats.CorruptedData++
		case StatusCorruptedHeader:
			result.Stats.CorruptedHeader++
		case StatusRecovered:
			result.Stats.Recovered++
			result.Stats.BytesRecovered += rec.ActualDiskSize(result.Version)
		case StatusRepaired:
			result.Stats.Repaired++
		case StatusDeletionMarker:
			result.Stats.DeletionMarkers++
		}
	}
	result.Stats.UniqueNeedleIds = len(uniqueIds)
	result.Stats.BytesScanned = result.DatFileSize
	for _, gap := range result.CorruptionGaps {
		result.Stats.BytesCorrupted += gap.Size()
	}

	// Idx cross-reference stats
	if s.idxEntries != nil {
		// Build set of NeedleIds found in scan (excluding deletion markers)
		scannedIds := make(map[uint64]struct{})
		for _, rec := range result.Records {
			if rec.Status != StatusDeletionMarker {
				scannedIds[rec.NeedleId] = struct{}{}
			}
		}

		for _, entry := range s.idxEntries {
			if entry.Size > 0 {
				result.Stats.IdxActive++
				if _, found := scannedIds[entry.NeedleId]; found {
					result.Stats.IdxConfirmed++
				}
			} else {
				result.Stats.IdxTombstoned++
			}
		}
		result.Stats.IdxOrphaned = result.Stats.IdxActive - result.Stats.IdxConfirmed
	}
}
