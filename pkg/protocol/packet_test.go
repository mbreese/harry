package protocol

import (
	"bytes"
	"testing"
)

func TestClientIDEncoding(t *testing.T) {
	for id := byte(0); id < 64; id++ {
		b1, b2, b3 := clientIDToBlockLens(id)
		got := blockLensToClientID(b1, b2, b3)
		if got != id {
			t.Fatalf("client ID round trip failed: %d -> (%d,%d,%d) -> %d", id, b1, b2, b3, got)
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

		for _, clientID := range []byte{0, 1, 7, 31, 63} {
			pkt := &Packet{
				Cmd:     CmdData,
				Counter: 42,
				Payload: []byte("test"),
			}

			query, err := qc.EncodeQuery(pkt, clientID)
			if err != nil {
				t.Fatalf("domain=%s clientID=%d: encode error: %v", domain, clientID, err)
			}

			// Verify total length
			if len(query) > maxDomainLen {
				t.Fatalf("domain=%s clientID=%d: query too long: %d", domain, clientID, len(query))
			}

			// Decode
			gotPkt, gotID, err := qc.DecodeQuery(query)
			if err != nil {
				t.Fatalf("domain=%s clientID=%d: decode error: %v\n  query: %s", domain, clientID, err, query)
			}

			if gotID != clientID {
				t.Fatalf("domain=%s: client ID mismatch: %d != %d", domain, gotID, clientID)
			}
			if gotPkt.Cmd != pkt.Cmd || gotPkt.Counter != pkt.Counter || !bytes.Equal(gotPkt.Payload, pkt.Payload) {
				t.Fatalf("domain=%s clientID=%d: packet mismatch", domain, clientID)
			}
		}
	}
}

func TestQueryLength(t *testing.T) {
	qc := &QueryConfig{Domain: "a.b.com"}
	pkt := &Packet{
		Cmd:     CmdPoll,
		Counter: 1,
	}

	query, err := qc.EncodeQuery(pkt, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Query: %s (len=%d)", query, len(query))
	if len(query) != maxDomainLen {
		t.Logf("Warning: query length %d != %d (padding should fill to max)", len(query), maxDomainLen)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	resp := &Response{
		Flags:   FlagMoreData,
		Payload: []byte("response data here"),
	}

	encoded := EncodeResponse(resp)
	got, err := DecodeResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if got.Flags != resp.Flags || !bytes.Equal(got.Payload, resp.Payload) {
		t.Fatalf("response round trip failed")
	}
}

func TestMaxPayload(t *testing.T) {
	domains := []string{"a.b.com", "tunnel.example.com", "very.long.subdomain.example.org"}
	for _, domain := range domains {
		qc := &QueryConfig{Domain: domain}
		maxPL := qc.MaxPayload(0)
		t.Logf("domain=%s maxPayload=%d", domain, maxPL)
		if maxPL <= 0 {
			t.Fatalf("domain=%s: max payload should be positive", domain)
		}
	}
}
