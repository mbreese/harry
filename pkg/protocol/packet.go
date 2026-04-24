// Package protocol defines the DNS tunnel wire format.
//
// Query format: <block4>.<block3>.<block2>.<block1>.<domain>
//
// The binary packet is: [cmd 1B] [counter 3B big-endian] [payload...]
// This is encrypted, then base36-encoded, then split across DNS labels.
//
// Blocks 1-3 have lengths 60-63, encoding 2 bits each (6 bits total = channel ID).
// Block 4 gets the remaining space to fill up to 253 total chars.
//
// Response: base36-encoded in TXT record.
// Response packet: [flags 1B] [payload...]
// Flags: bit 0 = more data queued
package protocol

import (
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/mbreese/harry/pkg/encoding"
)

// Command codes
const (
	CmdConnect    byte = 'c' // Initial connection, server assigns channel ID
	CmdPoll       byte = 'p' // Poll for queued data (no upstream payload)
	CmdData       byte = 'd' // Upstream data transfer
	CmdFile       byte = 'f' // Request a file by name
	CmdBoot       byte = 'b' // Bootstrap request
	CmdUpload     byte = 'u' // Start file upload (payload = filename)
	CmdUploadDone byte = 'U' // Signal upload complete
	CmdTune       byte = 't' // Auto-tune response size confirmation
	CmdList       byte = 'l' // List available files
	CmdFetch       byte = 'h' // Fetch a URL (server proxies HTTP request)
	CmdRShell      byte = 'r' // Start reverse shell (client spawns shell)
	CmdSocks5      byte = 's' // Start SOCKS5 proxy mode
	CmdStreamOpen  byte = 'o' // Open a new stream: [stream_id 2B][addr_type 1B][addr...][port 2B]
	CmdStreamClose byte = 'x' // Close a stream: [stream_id 2B]
)

// Response flags
const (
	FlagMoreData byte = 1 << 0 // Server has more data queued
	FlagError    byte = 1 << 1 // Error response
)

const (
	maxDomainLen = 253
	numBlocks    = 4
	// Blocks 1-3 carry channel ID in their lengths (60-63)
	minBlockLen = 60
	maxBlockLen = 63
	numIDBlocks = 3 // first 3 blocks carry 2 bits each
)

// Packet is the binary packet before encoding.
type Packet struct {
	Cmd     byte
	Counter uint32 // only lower 24 bits used
	Payload []byte
}

// Marshal serializes a packet to bytes.
func (p *Packet) Marshal() []byte {
	buf := make([]byte, 4+len(p.Payload))
	buf[0] = p.Cmd
	// 3 bytes big-endian counter
	buf[1] = byte(p.Counter >> 16)
	buf[2] = byte(p.Counter >> 8)
	buf[3] = byte(p.Counter)
	copy(buf[4:], p.Payload)
	return buf
}

// UnmarshalPacket deserializes bytes into a Packet.
func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}
	p := &Packet{
		Cmd:     data[0],
		Counter: uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
		Payload: data[4:],
	}
	return p, nil
}

// QueryConfig holds parameters for encoding/decoding DNS queries.
type QueryConfig struct {
	Domain string // base domain (e.g., "a.b.com")
}

// MaxPayload returns the maximum plaintext payload bytes that can fit in a query
// for a given domain, after accounting for cmd, counter, encryption, and encoding.
// cipherOverhead is the number of bytes added by encryption (nonce + tag).
func (qc *QueryConfig) MaxPayload(channelID byte, cipherOverhead int) int {
	totalEncoded := qc.totalEncodedChars(channelID)
	rawBytes := encoding.MaxDecodedSize(totalEncoded)
	// Raw layout after encryption: encrypted(cmd 1B + counter 3B + payload)
	// encrypted adds cipherOverhead bytes
	available := rawBytes - cipherOverhead - 4 // 4 = cmd + counter
	if available < 0 {
		return 0
	}
	return available
}

// totalEncodedChars returns the total base36 chars available across all blocks.
func (qc *QueryConfig) totalEncodedChars(channelID byte) int {
	b1, b2, b3 := channelIDToBlockLens(channelID)
	// dots: 3 between blocks + 1 before domain = 4
	b4 := maxDomainLen - len(qc.Domain) - b1 - b2 - b3 - numBlocks
	if b4 < 0 {
		b4 = 0
	}
	return b1 + b2 + b3 + b4
}

// EncodeQuery encodes raw bytes (typically encrypted) into a DNS query name.
// The channelID is encoded in the DNS label lengths.
func (qc *QueryConfig) EncodeQuery(data []byte, channelID byte) (string, error) {
	encoded := encoding.Encode(data)

	b1, b2, b3 := channelIDToBlockLens(channelID)
	b4 := maxDomainLen - len(qc.Domain) - b1 - b2 - b3 - numBlocks
	if b4 < 0 {
		return "", fmt.Errorf("domain too long: no space for data")
	}

	totalCapacity := b1 + b2 + b3 + b4

	// Pad encoded string to fill all blocks (use '0' padding on the left)
	if len(encoded) > totalCapacity {
		return "", fmt.Errorf("encoded data too long: %d > %d", len(encoded), totalCapacity)
	}
	padded := padLeft(encoded, totalCapacity, '0')

	// Split into blocks: block4 (leftmost) gets b4 chars, then b3, b2, b1
	blocks := make([]string, numBlocks)
	pos := 0
	blocks[3] = padded[pos : pos+b4] // block4 (leftmost label)
	pos += b4
	blocks[2] = padded[pos : pos+b3]
	pos += b3
	blocks[1] = padded[pos : pos+b2]
	pos += b2
	blocks[0] = padded[pos : pos+b1]

	// Build query: block4.block3.block2.block1.domain
	parts := make([]string, 0, numBlocks+1)
	for i := numBlocks - 1; i >= 0; i-- {
		parts = append(parts, blocks[i])
	}
	parts = append(parts, qc.Domain)

	return strings.Join(parts, "."), nil
}

// DecodeQuery decodes a DNS query name back into raw bytes and channel ID.
// The returned bytes are typically encrypted and need decryption before unmarshaling.
func (qc *QueryConfig) DecodeQuery(query string) ([]byte, byte, error) {
	query = strings.ToLower(query)

	suffix := "." + strings.ToLower(qc.Domain)
	if !strings.HasSuffix(query, suffix) {
		return nil, 0, fmt.Errorf("query %q does not end with domain %q", query, qc.Domain)
	}
	dataStr := query[:len(query)-len(suffix)]

	labels := strings.Split(dataStr, ".")
	if len(labels) != numBlocks {
		return nil, 0, fmt.Errorf("expected %d data labels, got %d", numBlocks, len(labels))
	}

	b1Len := len(labels[3])
	b2Len := len(labels[2])
	b3Len := len(labels[1])
	channelID := blockLensToChannelID(b1Len, b2Len, b3Len)

	var encoded strings.Builder
	for _, l := range labels {
		encoded.WriteString(l)
	}

	data, err := encoding.Decode(encoded.String())
	if err != nil {
		return nil, 0, fmt.Errorf("base36 decode: %w", err)
	}

	return data, channelID, nil
}

// Response represents a server response (application layer).
type Response struct {
	Flags   byte
	Payload []byte
}

// Frame constants for the wire format.
// Response frame: [crc32 4B] [transfer_id 2B] [chunk_idx 2B] [chunk_total 2B] [flags 1B] [encrypted...]
const (
	CRCSize       = 4  // CRC32
	TransferIDSize = 2 // uint16 transfer ID
	ChunkIdxSize   = 2 // uint16 chunk index
	ChunkTotalSize = 2 // uint16 total chunks
	FlagsSize      = 1
	FrameHeaderSize = TransferIDSize + ChunkIdxSize + ChunkTotalSize + FlagsSize // 7
	FrameOverhead   = CRCSize + FrameHeaderSize // 11
)

// Frame holds the decoded components of a wire-format frame.
type Frame struct {
	TransferID uint16
	ChunkIdx   uint16
	ChunkTotal uint16
	Flags      byte
	Payload    []byte // encrypted payload
}

// MarshalFrame builds a wire-format frame with CRC.
// CRC32 covers everything after itself.
func MarshalFrame(f *Frame) []byte {
	// Build inner: [transfer_id 2B][chunk_idx 2B][chunk_total 2B][flags 1B][payload]
	inner := make([]byte, FrameHeaderSize+len(f.Payload))
	inner[0] = byte(f.TransferID >> 8)
	inner[1] = byte(f.TransferID)
	inner[2] = byte(f.ChunkIdx >> 8)
	inner[3] = byte(f.ChunkIdx)
	inner[4] = byte(f.ChunkTotal >> 8)
	inner[5] = byte(f.ChunkTotal)
	inner[6] = f.Flags
	copy(inner[7:], f.Payload)

	// Compute CRC over inner
	crc := crc32.ChecksumIEEE(inner)

	// Build frame: [crc 4B][inner]
	frame := make([]byte, CRCSize+len(inner))
	frame[0] = byte(crc >> 24)
	frame[1] = byte(crc >> 16)
	frame[2] = byte(crc >> 8)
	frame[3] = byte(crc)
	copy(frame[CRCSize:], inner)

	return frame
}

// UnmarshalFrame verifies the CRC and extracts frame components.
func UnmarshalFrame(data []byte) (*Frame, error) {
	if len(data) < FrameOverhead {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	// Extract and verify CRC
	expectedCRC := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	inner := data[CRCSize:]
	actualCRC := crc32.ChecksumIEEE(inner)
	if expectedCRC != actualCRC {
		return nil, fmt.Errorf("CRC mismatch: expected %08x, got %08x", expectedCRC, actualCRC)
	}

	return &Frame{
		TransferID: uint16(inner[0])<<8 | uint16(inner[1]),
		ChunkIdx:   uint16(inner[2])<<8 | uint16(inner[3]),
		ChunkTotal: uint16(inner[4])<<8 | uint16(inner[5]),
		Flags:      inner[6],
		Payload:    inner[7:],
	}, nil
}

// channelIDToBlockLens returns the lengths of blocks 1-3 for a given channel ID (0-63).
func channelIDToBlockLens(channelID byte) (b1, b2, b3 int) {
	id := channelID & 0x3F // mask to 6 bits
	b1 = minBlockLen + int(id&0x03)
	b2 = minBlockLen + int((id>>2)&0x03)
	b3 = minBlockLen + int((id>>4)&0x03)
	return
}

// blockLensToChannelID reconstructs the channel ID from block lengths.
func blockLensToChannelID(b1, b2, b3 int) byte {
	bits1 := byte(b1-minBlockLen) & 0x03
	bits2 := byte(b2-minBlockLen) & 0x03
	bits3 := byte(b3-minBlockLen) & 0x03
	return bits1 | (bits2 << 2) | (bits3 << 4)
}

func padLeft(s string, totalLen int, pad byte) string {
	if len(s) >= totalLen {
		return s
	}
	padding := make([]byte, totalLen-len(s))
	for i := range padding {
		padding[i] = pad
	}
	return string(padding) + s
}

