package crypto

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	c, err := NewCipher("test-password")
	if err != nil {
		t.Fatal(err)
	}

	tests := [][]byte{
		[]byte("hello"),
		[]byte(""),
		make([]byte, 1000),
	}

	for i, plaintext := range tests {
		encrypted, err := c.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("test %d: encrypt: %v", i, err)
		}
		decrypted, err := c.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("test %d: decrypt: %v", i, err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("test %d: round trip failed", i)
		}
	}
}

func TestWrongPassword(t *testing.T) {
	c1, _ := NewCipher("password1")
	c2, _ := NewCipher("password2")

	encrypted, _ := c1.Encrypt([]byte("secret"))
	_, err := c2.Decrypt(encrypted)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong password")
	}
}

func TestDeterministicKey(t *testing.T) {
	c1, _ := NewCipher("same-password")
	c2, _ := NewCipher("same-password")

	// Both should be able to decrypt each other's output
	encrypted, _ := c1.Encrypt([]byte("data"))
	decrypted, err := c2.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "data" {
		t.Fatal("cross-instance decrypt failed")
	}
}
