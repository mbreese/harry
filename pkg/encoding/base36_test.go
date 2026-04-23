package encoding

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	tests := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x01},
		{0xff},
		{0x01, 0x02, 0x03},
		[]byte("hello world"),
		make([]byte, 200), // all zeros
	}

	for i, data := range tests {
		encoded := Encode(data)
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("test %d: decode error: %v", i, err)
		}
		// Special case: empty input encodes to "0" which decodes to empty
		if len(data) == 0 {
			if len(decoded) != 0 {
				t.Fatalf("test %d: expected empty, got %v", i, decoded)
			}
			continue
		}
		if !bytes.Equal(data, decoded) {
			t.Fatalf("test %d: round trip failed\n  input:   %x\n  encoded: %s\n  decoded: %x", i, data, encoded, decoded)
		}
	}
}

func TestCaseInsensitive(t *testing.T) {
	data := []byte("test data")
	encoded := Encode(data)

	// Uppercase version should decode the same
	upper := make([]byte, len(encoded))
	for i, c := range encoded {
		if c >= 'a' && c <= 'z' {
			upper[i] = byte(c - 'a' + 'A')
		} else {
			upper[i] = byte(c)
		}
	}

	decoded, err := Decode(string(upper))
	if err != nil {
		t.Fatalf("decode uppercase error: %v", err)
	}
	if !bytes.Equal(data, decoded) {
		t.Fatalf("case insensitive decode failed")
	}
}

func TestDNSSafe(t *testing.T) {
	data := []byte("binary data \x00\xff\x80")
	encoded := Encode(data)

	for _, c := range encoded {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			t.Fatalf("non-DNS-safe character in encoded output: %c", c)
		}
	}
}
