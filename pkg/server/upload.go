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
// Payload format: [flags 1B][filename...]
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

	if len(pkt.Payload) < 2 {
		log.Printf("client %d: upload rejected, payload too short", clientID)
		return errorFrame()
	}

	flags := pkt.Payload[0]
	filename := string(pkt.Payload[1:])
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
	log.Printf("client %d: upload started: %q", clientID, clean)

	return &protocol.Frame{Payload: []byte("ok")}
}

// handleUploadDone completes the current upload.
func (h *Handler) handleUploadDone(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	// Deduplicate DNS retries
	if session.isDuplicate(pkt.Counter) {
		return &protocol.Frame{Payload: []byte("ok")}
	}

	if session.UploadFile == "" {
		log.Printf("client %d: upload done but no active upload", clientID)
		return errorFrame()
	}

	path := filepath.Join(h.config.UploadDir, session.UploadFile)
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("client %d: upload verify error: %v", clientID, err)
		return errorFrame()
	}

	serverHash := sha1.Sum(data)
	serverHex := hex.EncodeToString(serverHash[:])
	clientHex := string(pkt.Payload)

	if clientHex != serverHex {
		log.Printf("client %d: upload hash mismatch: %q client=%s server=%s",
			clientID, session.UploadFile, clientHex, serverHex)
		session.UploadFile = ""
		session.UploadBytes = 0
		return &protocol.Frame{
			Flags:   protocol.FlagError,
			Payload: []byte("hash mismatch"),
		}
	}

	log.Printf("client %d: upload complete: %q (%d bytes, sha1=%s)", clientID, session.UploadFile, session.UploadBytes, serverHex)
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
