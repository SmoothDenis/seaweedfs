package rescue

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	IdxEntrySize4 = NeedleIdSize + 4 + SizeSize // 8 + 4 + 4 = 16 (4-byte offset)
	IdxEntrySize5 = NeedleIdSize + 5 + SizeSize // 8 + 5 + 4 = 17 (5-byte offset)
)

// ReadIdxFile reads a .idx file and returns a map of NeedleId -> IdxEntry.
// Auto-detects offset size (4 or 5 bytes) based on file size alignment.
// Offset is stored as actual_offset / 8 in the idx file.
func ReadIdxFile(path string) (map[uint64]IdxEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open idx file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat idx file: %w", err)
	}

	fileSize := stat.Size()

	// Auto-detect offset size: try 16 bytes (4-byte offset) and 17 bytes (5-byte offset)
	fits16 := fileSize%int64(IdxEntrySize4) == 0
	fits17 := fileSize%int64(IdxEntrySize5) == 0

	entrySize := 0
	offsetSize := 0
	switch {
	case fits16 && !fits17:
		entrySize = IdxEntrySize4
		offsetSize = 4
	case fits17 && !fits16:
		entrySize = IdxEntrySize5
		offsetSize = 5
	case fits16 && fits17:
		// Ambiguous — both could work. Default to 16 (4-byte offset) as it's more common.
		// Could also try both and validate, but 16 is the standard.
		entrySize = IdxEntrySize4
		offsetSize = 4
	default:
		return nil, fmt.Errorf("idx file size %d is not a multiple of 16 (4-byte offset) or 17 (5-byte offset)", fileSize)
	}

	entryCount := int(fileSize / int64(entrySize))
	entries := make(map[uint64]IdxEntry, entryCount)

	buf := make([]byte, entrySize)
	for {
		_, err := io.ReadFull(f, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read idx entry: %w", err)
		}

		needleId := binary.BigEndian.Uint64(buf[0:NeedleIdSize])

		var offsetRaw int64
		if offsetSize == 4 {
			offsetRaw = int64(binary.BigEndian.Uint32(buf[NeedleIdSize : NeedleIdSize+4]))
		} else {
			// 5-byte offset layout in idx: [b3 b2 b1 b0 b4]
			// where value = b0 + b1<<8 + b2<<16 + b3<<24 + b4<<32
			// bytes[0..3] are big-endian uint32, bytes[4] is the high byte
			offsetRaw = int64(binary.BigEndian.Uint32(buf[NeedleIdSize:NeedleIdSize+4])) |
				int64(buf[NeedleIdSize+4])<<32
		}
		size := int32(binary.BigEndian.Uint32(buf[NeedleIdSize+offsetSize : NeedleIdSize+offsetSize+SizeSize]))

		entries[needleId] = IdxEntry{
			NeedleId: needleId,
			Offset:   offsetRaw * NeedlePaddingSize, // convert to actual byte offset
			Size:     size,
		}
	}

	return entries, nil
}
