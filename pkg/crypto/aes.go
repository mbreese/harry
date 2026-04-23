// Package crypto provides AES-GCM encryption with password-derived keys.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keyLen  = 32 // AES-256
	saltLen = 16
	pbkdf2Iterations = 100000
)

// DeriveKey derives an AES-256 key from a password and salt using PBKDF2.
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keyLen, sha256.New)
}

// Cipher wraps AES-GCM with a pre-derived key.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher creates a new Cipher from a password. It uses a fixed salt derived
// from the password itself (both sides need the same key without exchanging a salt).
func NewCipher(password string) (*Cipher, error) {
	// Use SHA-256 of the password as the salt. Both sides can compute this.
	saltHash := sha256.Sum256([]byte("harry-salt:" + password))
	salt := saltHash[:saltLen]

	key := DeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// Encrypt encrypts plaintext. Returns nonce + ciphertext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data produced by Encrypt (nonce + ciphertext).
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return c.aead.Open(nil, nonce, ciphertext, nil)
}

// Overhead returns the number of bytes added by encryption (nonce + GCM tag).
func (c *Cipher) Overhead() int {
	return c.aead.NonceSize() + c.aead.Overhead()
}
