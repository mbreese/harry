package encoding

import (
	"bytes"
	"crypto/rand"
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

func TestMaxDecodedSize(t *testing.T) {
	for _, maxChars := range []int{10, 50, 100, 255, 512, 1000, 2000} {
		maxBytes := MaxDecodedSize(maxChars)
		if maxBytes <= 0 {
			t.Fatalf("MaxDecodedSize(%d) = %d, expected positive", maxChars, maxBytes)
		}

		// Worst case: all 0xFF bytes produce the longest encoding
		worstCase := make([]byte, maxBytes)
		for i := range worstCase {
			worstCase[i] = 0xFF
		}
		encoded := Encode(worstCase)
		if len(encoded) > maxChars {
			t.Fatalf("MaxDecodedSize(%d)=%d: worst case encoded to %d chars (over by %d)",
				maxChars, maxBytes, len(encoded), len(encoded)-maxChars)
		}

		// Verify with random data (100 iterations)
		for i := 0; i < 100; i++ {
			data := make([]byte, maxBytes)
			rand.Read(data)
			encoded := Encode(data)
			if len(encoded) > maxChars {
				t.Fatalf("MaxDecodedSize(%d)=%d: random data encoded to %d chars (over by %d)",
					maxChars, maxBytes, len(encoded), len(encoded)-maxChars)
			}
		}

		t.Logf("MaxDecodedSize(%d) = %d bytes (worst case encodes to %d chars)",
			maxChars, maxBytes, len(Encode(worstCase)))
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
