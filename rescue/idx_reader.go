package rescue

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const IdxEntrySize = NeedleIdSize + 4 + SizeSize // 8 + 4 + 4 = 16

// ReadIdxFile reads a .idx file and returns a map of NeedleId -> IdxEntry.
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

	if stat.Size()%IdxEntrySize != 0 {
		return nil, fmt.Errorf("idx file size %d is not a multiple of entry size %d", stat.Size(), IdxEntrySize)
	}

	entryCount := int(stat.Size() / IdxEntrySize)
	entries := make(map[uint64]IdxEntry, entryCount)

	buf := make([]byte, IdxEntrySize)
	for {
		_, err := io.ReadFull(f, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read idx entry: %w", err)
		}

		needleId := binary.BigEndian.Uint64(buf[0:NeedleIdSize])
		offsetRaw := binary.BigEndian.Uint32(buf[NeedleIdSize : NeedleIdSize+4])
		size := int32(binary.BigEndian.Uint32(buf[NeedleIdSize+4 : NeedleIdSize+4+SizeSize]))

		entries[needleId] = IdxEntry{
			NeedleId: needleId,
			Offset:   int64(offsetRaw) * NeedlePaddingSize, // convert to actual byte offset
			Size:     size,
		}
	}

	return entries, nil
}
