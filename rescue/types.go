package rescue

import "fmt"

type NeedleStatus int

const (
	StatusValid         NeedleStatus = iota // Header OK, CRC OK
	StatusCorruptedData                     // Header OK, CRC mismatch
	StatusCorruptedHeader                   // Header unreadable / invalid size
	StatusRecovered                         // Found via deep scan
	StatusDeleted                           // Size < 0 (tombstone)
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
	Status      NeedleStatus
	Source      string // "idx-guided", "sequential", "deep-scan"
	IdxMatch    bool   // matches .idx entry
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
	CorruptedData   int
	CorruptedHeader int
	Recovered       int
	BytesScanned    int64
	BytesCorrupted  int64
	BytesRecovered  int64
	IdxEntries      int
	IdxMatches      int
	IdxMismatches   int
}

type ScanResult struct {
	Version        int
	SuperBlockData []byte
	DatFileSize    int64
	Records        []NeedleRecord
	CorruptionGaps []Gap
	Stats          ScanStats
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
func PaddingLength(size int32, version int) int {
	var tailSize int
	switch version {
	case 2:
		tailSize = NeedleChecksumSize
	case 3:
		tailSize = NeedleChecksumSize + TimestampSize
	default:
		tailSize = NeedleChecksumSize + TimestampSize
	}
	total := NeedleHeaderSize + int(absInt32(size)) + tailSize
	remainder := total % NeedlePaddingSize
	if remainder == 0 {
		return 0
	}
	return NeedlePaddingSize - remainder
}

// ActualDiskSize returns total bytes a needle occupies on disk.
func ActualDiskSize(size int32, version int) int64 {
	absSize := absInt32(size)
	var tailSize int
	switch version {
	case 2:
		tailSize = NeedleChecksumSize
	case 3:
		tailSize = NeedleChecksumSize + TimestampSize
	default:
		tailSize = NeedleChecksumSize + TimestampSize
	}
	total := NeedleHeaderSize + int(absSize) + tailSize
	padding := NeedlePaddingSize - (total % NeedlePaddingSize)
	if padding == NeedlePaddingSize {
		padding = 0
	}
	return int64(total + padding)
}

func absInt32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}
