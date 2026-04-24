package server

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mbreese/harry/pkg/protocol"
)

const (
	uploadFlagForce byte = 1 << 0 // Overwrite existing file
)

// handleUploadStart begins a new file upload.
// Payload format: [flags 1B][size 4B big-endian][sha1 20B][filename...]
// Idempotent: if the session already has an upload for the same file, just ACK.
func (h *Handler) handleUploadStart(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	if h.config.UploadDir == "" {
		log.Printf("client %d: upload rejected, no upload directory configured", clientID)
		return errorFrame()
	}

	// Parse payload: [flags 1B][size 4B][sha1 20B][filename...]
	if len(pkt.Payload) < 1+4+20+1 {
		log.Printf("client %d: upload rejected, payload too short", clientID)
		return errorFrame()
	}

	flags := pkt.Payload[0]
	expSize := uint32(pkt.Payload[1])<<24 | uint32(pkt.Payload[2])<<16 |
		uint32(pkt.Payload[3])<<8 | uint32(pkt.Payload[4])
	var expHash [20]byte
	copy(expHash[:], pkt.Payload[5:25])
	filename := string(pkt.Payload[25:])

	if filename == "" {
		log.Printf("client %d: upload rejected, empty filename", clientID)
		return errorFrame()
	}

	clean := filepath.Base(filename)
	if clean == "." || clean == ".." || strings.ContainsAny(clean, "/\\") {
		log.Printf("client %d: upload rejected, invalid filename: %q", clientID, filename)
		return errorFrame()
	}

	// Idempotent: if already uploading the same file, just ACK (DNS retry)
	if session.UploadFile == clean {
		return &protocol.Frame{Payload: []byte("ok")}
	}

	path := filepath.Join(h.config.UploadDir, clean)

	// Check if file already exists
	if flags&uploadFlagForce == 0 {
		if _, err := os.Stat(path); err == nil {
			log.Printf("client %d: upload rejected, file exists: %q (use -f to overwrite)", clientID, clean)
			return &protocol.Frame{
				Flags:   protocol.FlagError,
				Payload: []byte("file exists (use -f to overwrite)"),
			}
		}
	}

	f, err := os.Create(path)
	if err != nil {
		log.Printf("client %d: upload create error: %v", clientID, err)
		return errorFrame()
	}
	f.Close()

	session.UploadFile = clean
	session.UploadBytes = 0
	session.UploadExpSize = expSize
	session.UploadExpHash = expHash
	log.Printf("client %d: upload started: %q (expecting %d bytes, sha1=%x)",
		clientID, clean, expSize, expHash)

	return &protocol.Frame{Payload: []byte("ok")}
}

// handleUploadDone is called when the client signals upload complete.
// The server verifies the file against the expected size and SHA1
// sent in the upload start.
func (h *Handler) handleUploadDone(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	if session.isDuplicate(pkt.Counter) {
		return &protocol.Frame{Payload: []byte("ok")}
	}

	if session.UploadFile == "" {
		log.Printf("client %d: upload done but no active upload", clientID)
		return errorFrame()
	}

	// Read the uploaded file and verify
	path := filepath.Join(h.config.UploadDir, session.UploadFile)
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("client %d: upload verify error: %v", clientID, err)
		return errorFrame()
	}

	serverHash := sha1.Sum(data)
	serverHex := hex.EncodeToString(serverHash[:])

	if serverHash != session.UploadExpHash {
		expHex := hex.EncodeToString(session.UploadExpHash[:])
		log.Printf("client %d: upload hash mismatch: %q expected=%s got=%s",
			clientID, session.UploadFile, expHex, serverHex)
		session.UploadFile = ""
		session.UploadBytes = 0
		return &protocol.Frame{
			Flags:   protocol.FlagError,
			Payload: []byte(fmt.Sprintf("hash mismatch: expected=%s got=%s",
				hex.EncodeToString(session.UploadExpHash[:]), serverHex)),
		}
	}

	if uint32(len(data)) != session.UploadExpSize {
		log.Printf("client %d: upload size mismatch: %q expected=%d got=%d",
			clientID, session.UploadFile, session.UploadExpSize, len(data))
		session.UploadFile = ""
		session.UploadBytes = 0
		return &protocol.Frame{
			Flags:   protocol.FlagError,
			Payload: []byte("size mismatch"),
		}
	}

	log.Printf("client %d: upload verified: %q (%d bytes, sha1=%s)",
		clientID, session.UploadFile, len(data), serverHex)
	session.UploadFile = ""
	session.UploadBytes = 0

	return &protocol.Frame{Payload: []byte("ok:" + serverHex)}
}

// appendUpload appends data to the active upload file.
func (h *Handler) appendUpload(session *Session, data []byte) error {
	if session.UploadFile == "" {
		return fmt.Errorf("no active upload")
	}

	path := filepath.Join(h.config.UploadDir, session.UploadFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		return err
	}
	session.UploadBytes += n
	return nil
}
