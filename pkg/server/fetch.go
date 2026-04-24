package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/mbreese/harry/pkg/protocol"
)

const (
	fetchNoRedirect byte = 1 << 0 // Don't follow redirects
)

var defaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

var noRedirectHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// handleFetch fetches a URL and creates a transfer for the response.
func (h *Handler) handleFetch(pkt *protocol.Packet, channelID byte) *protocol.Frame {
	session := h.sessions.Get(channelID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	if len(pkt.Payload) < 2 {
		return errorFrame()
	}

	fetchFlags := pkt.Payload[0]
	url := string(pkt.Payload[1:])

	log.Printf("ch %d: fetching %s (flags=%02x)", channelID, url, fetchFlags)

	client := defaultHTTPClient
	if fetchFlags&fetchNoRedirect != 0 {
		client = noRedirectHTTPClient
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("ch %d: fetch error: %v", channelID, err)
		errMsg := fmt.Sprintf("fetch error: %v", err)
		return &protocol.Frame{Flags: protocol.FlagError, Payload: []byte(errMsg)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ch %d: fetch read error: %v", channelID, err)
		errMsg := fmt.Sprintf("read error: %v", err)
		return &protocol.Frame{Flags: protocol.FlagError, Payload: []byte(errMsg)}
	}

	header := fmt.Sprintf("HTTP %d %s\n", resp.StatusCode, resp.Status)
	fullResp := append([]byte(header), body...)

	log.Printf("ch %d: fetched %s (%d bytes, status %d)", channelID, url, len(body), resp.StatusCode)

	maxPayload := h.responsePayloadSize(session)
	t := session.Transfers.NewTransfer(fullResp, maxPayload)
	return h.chunkFrame(t, 0)
}
