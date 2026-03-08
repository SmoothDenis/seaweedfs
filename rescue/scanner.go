package rescue

import (
	"fmt"
	"io"
	"os"
)

type Scanner struct {
	DatPath    string
	IdxPath    string
	Version    int
	DeepScan   bool
	Verbose    bool
	datFile    *os.File
	datSize    int64
	idxEntries map[uint64]IdxEntry
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
	}

	// Read superblock
	if s.datSize < SuperBlockSize {
		return nil, fmt.Errorf("dat file too small: %d bytes", s.datSize)
	}
	result.SuperBlockData = make([]byte, SuperBlockSize)
	if _, err := s.datFile.ReadAt(result.SuperBlockData, 0); err != nil {
		return nil, fmt.Errorf("read superblock: %w", err)
	}

	// Auto-detect version from superblock byte 0
	if s.Version == 0 {
		s.Version = int(result.SuperBlockData[0])
		if s.Version < 1 || s.Version > 3 {
			return nil, fmt.Errorf("invalid version %d in superblock", s.Version)
		}
	}
	result.Version = s.Version

	// Load idx if available
	if s.IdxPath != "" {
		s.idxEntries, err = ReadIdxFile(s.IdxPath)
		if err != nil {
			// Non-fatal: continue without idx
			s.idxEntries = nil
		} else {
			result.Stats.IdxEntries = len(s.idxEntries)
		}
	}

	// Phase 1: idx-guided scan
	if s.idxEntries != nil {
		s.phase1IdxGuided(result)
	}

	// Phase 2: sequential scan with recovery
	s.phase2Sequential(result)

	// Phase 3: deep scan (optional)
	if s.DeepScan && len(result.CorruptionGaps) > 0 {
		s.phase3Deep(result)
	}

	// Compute final stats
	s.computeStats(result)

	return result, nil
}

func (s *Scanner) phase1IdxGuided(result *ScanResult) {
	for _, entry := range s.idxEntries {
		if entry.Offset < SuperBlockSize || entry.Offset >= s.datSize {
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
	// Phase 1 results are used as anchors in phase 2, not added to records directly
}

func (s *Scanner) phase2Sequential(result *ScanResult) {
	offset := int64(SuperBlockSize)
	seenOffsets := make(map[int64]bool)

	for offset < s.datSize {
		rec := s.validateAtOffset(offset)
		if rec != nil && (rec.Status == StatusValid || rec.Status == StatusDeleted || rec.Status == StatusCorruptedData) {
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
			offset += rec.ActualDiskSize(s.Version)
			continue
		}

		// Corruption detected - scan forward for next valid needle
		gapStart := offset
		found := false
		scanOffset := offset + NeedlePaddingSize

		for scanOffset < s.datSize {
			candidate := s.validateAtOffset(scanOffset)
			if candidate != nil && candidate.Status == StatusValid {
				// Found next valid needle
				result.CorruptionGaps = append(result.CorruptionGaps, Gap{
					StartOffset: gapStart,
					EndOffset:   scanOffset,
				})
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
			result.CorruptionGaps = append(result.CorruptionGaps, Gap{
				StartOffset: gapStart,
				EndOffset:   s.datSize,
			})
			break
		}
	}
}

func (s *Scanner) phase3Deep(result *ScanResult) {
	seenOffsets := make(map[int64]bool)
	for _, rec := range result.Records {
		seenOffsets[rec.Offset] = true
	}

	for _, gap := range result.CorruptionGaps {
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
			}
		}
	}
}

func (s *Scanner) validateAtOffset(offset int64) *NeedleRecord {
	// Read header first to determine size
	headerBuf := make([]byte, NeedleHeaderSize)
	if _, err := s.datFile.ReadAt(headerBuf, offset); err != nil {
		return nil
	}

	_, _, size := ParseNeedleHeader(headerBuf)
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
	for _, rec := range result.Records {
		result.Stats.TotalNeedles++
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
		}
	}
	result.Stats.BytesScanned = result.DatFileSize
	for _, gap := range result.CorruptionGaps {
		result.Stats.BytesCorrupted += gap.Size()
	}
}
