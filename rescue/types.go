package rescue

import (
	"fmt"
	"math"
)

type NeedleStatus int

const (
	StatusValid           NeedleStatus = iota // Header OK, CRC OK
	StatusCorruptedData                       // Header OK, CRC mismatch
	StatusCorruptedHeader                     // Header unreadable / invalid size
	StatusRecovered                           // Found via deep scan
	StatusDeleted                             // Size < 0 (tombstone)
	StatusRepaired                            // CRC mismatch fixed by single-byte repair
	StatusDeletionMarker                      // Size == 0 (deletion marker appended when needle is deleted)
)

func (s NeedleStatus) String() string {
	switch s {
	case StatusValid:
		return "VALID"
	case StatusCorruptedData:
		return "CORRUPTED_DATA"
	case StatusCorruptedHeader:
		return "CORRUPTED_HEADER"
	case StatusRecovered:
		return "RECOVERED"
	case StatusDeleted:
		return "DELETED"
	case StatusRepaired:
		return "REPAIRED"
	case StatusDeletionMarker:
		return "DELETION_MARKER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

type NeedleRecord struct {
	Offset      int64
	NeedleId    uint64
	Cookie      uint32
	Size        int32
	DataSize    uint32
	StoredCRC   uint32
	ComputedCRC uint32
	Timestamp   uint64 // AppendAtNs (V3 only)
	Status       NeedleStatus
	Source       string // "idx-guided", "sequential", "deep-scan", "tail-recovery"
	IdxMatch     bool   // matches .idx entry
	HeaderIntact bool   // true if needle header was readable (NeedleId/Cookie are reliable)
}

// ActualDiskSize returns the total bytes this needle occupies on disk including header, body, tail, and padding.
func (r *NeedleRecord) ActualDiskSize(version int) int64 {
	return ActualDiskSize(r.Size, version)
}

type Gap struct {
	StartOffset int64
	EndOffset   int64
}

func (g Gap) Size() int64 {
	return g.EndOffset - g.StartOffset
}

type ScanStats struct {
	TotalNeedles    int
	ValidNeedles    int
	DeletedNeedles  int
	DeletionMarkers int // Size=0 entries (deletion markers in .dat)
	CorruptedData   int
	CorruptedHeader int
	Recovered       int
	Repaired        int
	BytesScanned    int64
	BytesCorrupted  int64
	BytesRecovered  int64
	IdxEntries      int
	IdxMatches      int
	IdxMismatches   int
	UniqueNeedleIds int // count of distinct NeedleIds
	IdxActive       int // idx entries with Size > 0 (active)
	IdxTombstoned   int // idx entries with Size <= 0 (tombstoned)
	IdxConfirmed    int // active idx entries found in .dat scan
	IdxOrphaned     int // active idx entries NOT found in .dat scan
}

type ScanResult struct {
	Version        int
	SuperBlockData []byte
	SuperBlockSize int    // actual superblock size in bytes (8 + ExtraSize)
	DatFileSize    int64
	Records        []NeedleRecord
	CorruptionGaps []Gap
	Stats          ScanStats
	datPath        string // source file path (for report recommendations)
}

type IdxEntry struct {
	NeedleId uint64
	Offset   int64 // actual byte offset (already multiplied by 8)
	Size     int32
}

const (
	NeedleHeaderSize   = 16 // Cookie(4) + NeedleId(8) + Size(4)
	NeedleChecksumSize = 4  // CRC32
	TimestampSize      = 8  // uint64 nanoseconds
	NeedlePaddingSize  = 8  // alignment boundary
	CookieSize         = 4
	NeedleIdSize       = 8
	SizeSize           = 4

	SuperBlockSize = 8

	MaxReasonableNeedleSize = 256 * 1024 * 1024 // 256MB - sanity check for Size field

	// Minimum reasonable nanosecond timestamp: 2010-01-01
	MinReasonableTimestamp = 1262304000_000_000_000
	// Maximum reasonable nanosecond timestamp: 2035-01-01
	MaxReasonableTimestamp = 2051222400_000_000_000
)

// PaddingLength computes padding bytes needed to align needle to 8-byte boundary.
// Matches SeaweedFS: padding is always 1-8 bytes, never 0.
func PaddingLength(size int32, version int) int {
	if version == 3 {
		return int(NeedlePaddingSize - ((NeedleHeaderSize + int(absInt32(size)) + NeedleChecksumSize + TimestampSize) % NeedlePaddingSize))
	}
	return int(NeedlePaddingSize - ((NeedleHeaderSize + int(absInt32(size)) + NeedleChecksumSize) % NeedlePaddingSize))
}

// ActualDiskSize returns total bytes a needle occupies on disk.
// Matches SeaweedFS GetActualSize: Header + Size + Checksum + Timestamp(V3) + Padding(1-8).
func ActualDiskSize(size int32, version int) int64 {
	absSize := int64(absInt32(size))
	padding := int64(PaddingLength(size, version))
	if version == 3 {
		return int64(NeedleHeaderSize) + absSize + NeedleChecksumSize + TimestampSize + padding
	}
	return int64(NeedleHeaderSize) + absSize + NeedleChecksumSize + padding
}

// statusPriority returns a priority for NeedleStatus (higher = better).
// Used for deduplication: when multiple records share a NeedleId, keep the best one.
func statusPriority(s NeedleStatus) int {
	switch s {
	case StatusValid:
		return 6
	case StatusRepaired:
		return 5
	case StatusRecovered:
		return 4
	case StatusDeleted:
		return 3
	case StatusCorruptedData:
		return 2
	case StatusDeletionMarker:
		return 1
	default:
		return 0
	}
}

// DeduplicateByNeedleId removes duplicate NeedleId entries, keeping the record
// with the highest status priority. This prevents writing conflicting entries
// to the .idx file and avoids wasting space with duplicate data in .dat.
func DeduplicateByNeedleId(records []NeedleRecord) []NeedleRecord {
	bestByID := make(map[uint64]NeedleRecord, len(records))
	for _, rec := range records {
		if existing, ok := bestByID[rec.NeedleId]; !ok || statusPriority(rec.Status) > statusPriority(existing.Status) {
			bestByID[rec.NeedleId] = rec
		}
	}
	deduped := make([]NeedleRecord, 0, len(bestByID))
	for _, rec := range bestByID {
		deduped = append(deduped, rec)
	}
	return deduped
}

func absInt32(v int32) int32 {
	if v == math.MinInt32 {
		return math.MaxInt32 // overflow guard; will be caught by IsReasonableSize
	}
	if v < 0 {
		return -v
	}
	return v
}
