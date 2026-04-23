package server

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mbreese/harry/pkg/protocol"
)

// handleUploadStart begins a new file upload.
// Payload is the filename to upload to.
func (h *Handler) handleUploadStart(pkt *protocol.Packet, clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	if h.config.UploadDir == "" {
		log.Printf("client %d: upload rejected, no upload directory configured", clientID)
		return &protocol.Response{Flags: protocol.FlagError}
	}

	filename := string(pkt.Payload)
	if filename == "" {
		log.Printf("client %d: upload rejected, empty filename", clientID)
		return &protocol.Response{Flags: protocol.FlagError}
	}

	// Sanitize filename
	clean := filepath.Base(filename)
	if clean == "." || clean == ".." || strings.ContainsAny(clean, "/\\") {
		log.Printf("client %d: upload rejected, invalid filename: %q", clientID, filename)
		return &protocol.Response{Flags: protocol.FlagError}
	}

	path := filepath.Join(h.config.UploadDir, clean)

	// Create/truncate the file
	f, err := os.Create(path)
	if err != nil {
		log.Printf("client %d: upload create error: %v", clientID, err)
		return &protocol.Response{Flags: protocol.FlagError}
	}
	f.Close()

	session.UploadFile = clean
	session.UploadBytes = 0
	log.Printf("client %d: upload started: %q", clientID, clean)

	return &protocol.Response{
		Payload: []byte("ok"),
	}
}

// handleUploadDone completes the current upload.
func (h *Handler) handleUploadDone(clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	if session.UploadFile == "" {
		log.Printf("client %d: upload done but no active upload", clientID)
		return &protocol.Response{Flags: protocol.FlagError}
	}

	log.Printf("client %d: upload complete: %q (%d bytes)", clientID, session.UploadFile, session.UploadBytes)
	session.UploadFile = ""
	session.UploadBytes = 0

	return &protocol.Response{
		Payload: []byte("ok"),
	}
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
