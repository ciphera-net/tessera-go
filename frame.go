package tessera

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxFrame bounds a single wire frame. It MUST match the sidecar's MAX_FRAME (1 MiB).
const MaxFrame = 1 << 20

// writeFrame writes [u32 big-endian length][payload]. Unlike the Rust side it does not flush:
// net.Conn writes are unbuffered, so the bytes are handed to the kernel immediately.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("tessera: frame too large (%d > %d)", len(payload), MaxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one length-prefixed frame, rejecting anything larger than MaxFrame before
// allocating (a hostile length prefix cannot trigger a huge allocation).
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("tessera: frame exceeds MaxFrame (%d)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
