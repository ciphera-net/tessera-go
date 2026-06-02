package tessera

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello tessera")
	var buf bytes.Buffer
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: %q != %q", got, payload)
	}
}

func TestReadFrameRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100*1024*1024) // 100 MiB
	buf.Write(hdr[:])
	buf.WriteByte('x')
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("expected oversized frame to be rejected")
	}
}

// TestWriteFrameRejectsOversized pins writeFrame's size guard: an over-cap payload is rejected
// and nothing is written (a partial header on the wire would desync the peer).
func TestWriteFrameRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("expected writeFrame to reject an oversized payload")
	}
	if buf.Len() != 0 {
		t.Fatalf("writeFrame wrote %d bytes before rejecting; must write nothing", buf.Len())
	}
}

// TestFrameBoundaryExactMaxIsAllowed locks the off-by-one contract: a payload of EXACTLY MaxFrame
// is accepted by both writer and reader (the cap is inclusive).
func TestFrameBoundaryExactMaxIsAllowed(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, MaxFrame)
	var buf bytes.Buffer
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatalf("a payload of exactly MaxFrame must be accepted: %v", err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("reading a MaxFrame payload must succeed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("MaxFrame round trip mismatch")
	}
}

// TestReadFrameRejectsJustOverBoundary pins the read-side cap at exactly MaxFrame+1 (the 100 MiB
// case above is unambiguously over; this nails the boundary), rejecting before any allocation.
func TestReadFrameRejectsJustOverBoundary(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrame+1)
	buf.Write(hdr[:])
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("expected a length of MaxFrame+1 to be rejected before allocation")
	}
}

// TestFrameEmptyPayloadRoundTrips confirms n=0 is a valid wire state (header only, empty body).
func TestFrameEmptyPayloadRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, []byte{}); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty payload must round trip to an empty slice, got %d bytes", len(got))
	}
}

// TestReadFrameTruncatedBodyIsUnexpectedEOF exercises the second io.ReadFull error path: a header
// promising more bytes than the body delivers must surface io.ErrUnexpectedEOF, not a silent short read.
func TestReadFrameTruncatedBodyIsUnexpectedEOF(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 10) // header promises 10 bytes...
	buf.Write(hdr[:])
	buf.Write([]byte("12345")) // ...but only 5 arrive
	if _, err := readFrame(&buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a truncated body must yield io.ErrUnexpectedEOF, got %v", err)
	}
}
