package protocol

import (
	"bytes"
	"testing"
)

func TestChannelIDEncoding(t *testing.T) {
	for id := byte(0); id < 64; id++ {
		b1, b2, b3 := channelIDToBlockLens(id)
		got := blockLensToChannelID(b1, b2, b3)
		if got != id {
			t.Fatalf("channel ID round trip failed: %d -> (%d,%d,%d) -> %d", id, b1, b2, b3, got)
		}
		// Verify lengths are in range
		for _, l := range []int{b1, b2, b3} {
			if l < minBlockLen || l > maxBlockLen {
				t.Fatalf("block length %d out of range [%d,%d]", l, minBlockLen, maxBlockLen)
			}
		}
	}
}

func TestPacketMarshalRoundTrip(t *testing.T) {
	pkt := &Packet{
		Cmd:     CmdData,
		Counter: 0x010203,
		Payload: []byte("hello"),
	}

	data := pkt.Marshal()
	got, err := UnmarshalPacket(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.Cmd != pkt.Cmd || got.Counter != pkt.Counter || !bytes.Equal(got.Payload, pkt.Payload) {
		t.Fatalf("packet round trip failed: %+v != %+v", got, pkt)
	}
}

func TestQueryRoundTrip(t *testing.T) {
	domains := []string{"a.b.com", "tunnel.example.com", "x.y.z.example.org"}

	for _, domain := range domains {
		qc := &QueryConfig{Domain: domain}

		for _, channelID := range []byte{0, 1, 7, 31, 63} {
			// EncodeQuery now takes raw bytes (e.g., encrypted data)
			data := []byte("test encrypted data")

			query, err := qc.EncodeQuery(data, channelID)
			if err != nil {
				t.Fatalf("domain=%s channelID=%d: encode error: %v", domain, channelID, err)
			}

			if len(query) > maxDomainLen {
				t.Fatalf("domain=%s channelID=%d: query too long: %d", domain, channelID, len(query))
			}

			gotData, gotID, err := qc.DecodeQuery(query)
			if err != nil {
				t.Fatalf("domain=%s channelID=%d: decode error: %v\n  query: %s", domain, channelID, err, query)
			}

			if gotID != channelID {
				t.Fatalf("domain=%s: client ID mismatch: %d != %d", domain, gotID, channelID)
			}
			if !bytes.Equal(gotData, data) {
				t.Fatalf("domain=%s channelID=%d: data mismatch", domain, channelID)
			}
		}
	}
}

func TestQueryLength(t *testing.T) {
	qc := &QueryConfig{Domain: "a.b.com"}
	data := []byte("small test payload")

	query, err := qc.EncodeQuery(data, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Query: %s (len=%d)", query, len(query))
	if len(query) != maxDomainLen {
		t.Logf("Note: query length %d != %d (padding fills to max)", len(query), maxDomainLen)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	f := &Frame{
		TransferID: 5,
		ChunkIdx:   2,
		ChunkTotal: 10,
		Flags:      FlagMoreData,
		Payload:    []byte("encrypted data here"),
	}

	data := MarshalFrame(f)
	got, err := UnmarshalFrame(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.TransferID != f.TransferID {
		t.Fatalf("transfer ID mismatch: %d != %d", got.TransferID, f.TransferID)
	}
	if got.ChunkIdx != f.ChunkIdx {
		t.Fatalf("chunk idx mismatch: %d != %d", got.ChunkIdx, f.ChunkIdx)
	}
	if got.ChunkTotal != f.ChunkTotal {
		t.Fatalf("chunk total mismatch: %d != %d", got.ChunkTotal, f.ChunkTotal)
	}
	if got.Flags != f.Flags {
		t.Fatalf("flags mismatch: %d != %d", got.Flags, f.Flags)
	}
	if !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	data := MarshalFrame(&Frame{})
	got, err := UnmarshalFrame(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.TransferID != 0 || got.ChunkIdx != 0 || got.ChunkTotal != 0 || got.Flags != 0 || len(got.Payload) != 0 {
		t.Fatalf("empty frame mismatch: %+v", got)
	}
}

func TestFrameCorruptionDetected(t *testing.T) {
	data := MarshalFrame(&Frame{Flags: FlagMoreData, Payload: []byte("test data")})

	corrupted := make([]byte, len(data))
	copy(corrupted, data)
	corrupted[len(corrupted)-1] ^= 0x01

	_, err := UnmarshalFrame(corrupted)
	if err == nil {
		t.Fatal("expected CRC error on corrupted frame")
	}
}

func TestFrameTruncationDetected(t *testing.T) {
	data := MarshalFrame(&Frame{Payload: []byte("test data")})
	truncated := data[:len(data)-3]

	_, err := UnmarshalFrame(truncated)
	if err == nil {
		t.Fatal("expected CRC error on truncated frame")
	}
}

func TestMaxPayload(t *testing.T) {
	domains := []string{"a.b.com", "tunnel.example.com", "very.long.subdomain.example.org"}
	cipherOverhead := 28 // AES-GCM: 12 nonce + 16 tag
	for _, domain := range domains {
		qc := &QueryConfig{Domain: domain}
		maxPL := qc.MaxPayload(0, cipherOverhead)
		t.Logf("domain=%s maxPayload=%d", domain, maxPL)
		if maxPL <= 0 {
			t.Fatalf("domain=%s: max payload should be positive", domain)
		}
	}
}
