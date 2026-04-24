// Package encoding provides DNS-safe base36 encoding/decoding.
// Base36 uses [0-9a-z] which is safe for DNS labels (case-insensitive).
package encoding

import (
	"fmt"
	"math"
	"math/big"
)

const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// log(36)/log(256) — how many bytes fit per base36 character
const bytesPerChar = 0.6463623459827747

// MaxDecodedSize returns the maximum number of raw bytes that,
// when encoded with Encode, will produce a base36 string of at most maxChars.
// Accounts for the 0x01 sentinel byte used internally by Encode.
func MaxDecodedSize(maxChars int) int {
	if maxChars <= 0 {
		return 0
	}
	// The sentinel byte (0x01) is prepended internally, consuming encoding space.
	// Subtract 2 bytes (1 for sentinel, 1 for safety margin on big.Int boundary).
	raw := int(math.Floor(float64(maxChars)*bytesPerChar)) - 2
	if raw < 0 {
		return 0
	}
	return raw
}

// Encode encodes binary data to a base36 string.
// A leading length byte is prepended to preserve leading zeros.
func Encode(data []byte) string {
	if len(data) == 0 {
		return "0"
	}

	// Prepend a 0x01 byte so leading zeros in data are preserved.
	padded := make([]byte, len(data)+1)
	padded[0] = 0x01
	copy(padded[1:], data)

	n := new(big.Int).SetBytes(padded)
	if n.Sign() == 0 {
		return "0"
	}

	base := big.NewInt(36)
	mod := new(big.Int)
	var encoded []byte

	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		encoded = append(encoded, alphabet[mod.Int64()])
	}

	// Reverse
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	return string(encoded)
}

// Decode decodes a base36 string back to binary data.
func Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// "0" is the encoding of empty input
	if s == "0" {
		return []byte{}, nil
	}

	n := new(big.Int)
	base := big.NewInt(36)

	for _, c := range s {
		var digit int64
		switch {
		case c >= '0' && c <= '9':
			digit = int64(c - '0')
		case c >= 'a' && c <= 'z':
			digit = int64(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			// Accept uppercase (DNS case-insensitive)
			digit = int64(c-'A') + 10
		default:
			return nil, fmt.Errorf("invalid base36 character: %c", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(digit))
	}

	b := n.Bytes()
	// Strip the leading 0x01 sentinel byte
	if len(b) == 0 || b[0] != 0x01 {
		return nil, fmt.Errorf("invalid encoded data (missing sentinel)")
	}
	return b[1:], nil
}
