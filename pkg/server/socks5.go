package server

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mbreese/harry/pkg/protocol"
)

// socks5Bridge manages multiplexed TCP streams for SOCKS5 proxy.
type socks5Bridge struct {
	mu      sync.Mutex
	streams map[uint16]*proxyStream
}

// proxyStream represents a single proxied TCP connection.
type proxyStream struct {
	id           uint16
	conn         net.Conn
	mu           sync.Mutex
	buf          []byte // data from remote, waiting to send to client
	remoteClosed bool   // remote TCP connection has closed
}

func newSocks5Bridge() *socks5Bridge {
	return &socks5Bridge{
		streams: make(map[uint16]*proxyStream),
	}
}

// openStream dials the target and creates a new stream.
func (b *socks5Bridge) openStream(id uint16, addr string, channelID byte) error {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return err
	}

	stream := &proxyStream{
		id:   id,
		conn: conn,
	}

	b.mu.Lock()
	b.streams[id] = stream
	b.mu.Unlock()

	log.Printf("ch %d: socks5 stream %d opened → %s", channelID, id, addr)

	// Read from remote in background
	go b.readStream(stream, channelID)

	return nil
}

// closeStream closes a specific stream.
func (b *socks5Bridge) closeStream(id uint16) {
	b.mu.Lock()
	stream, ok := b.streams[id]
	if ok {
		delete(b.streams, id)
	}
	b.mu.Unlock()

	if stream != nil {
		stream.conn.Close()
	}
}

// readStream reads data from a remote TCP connection into the stream buffer.
func (b *socks5Bridge) readStream(stream *proxyStream, channelID byte) {
	buf := make([]byte, 4096)
	for {
		n, err := stream.conn.Read(buf)
		if n > 0 {
			stream.mu.Lock()
			stream.buf = append(stream.buf, buf[:n]...)
			stream.mu.Unlock()
		}
		if err != nil {
			stream.mu.Lock()
			stream.remoteClosed = true
			stream.mu.Unlock()
			log.Printf("ch %d: socks5 stream %d remote closed", channelID, stream.id)
			return
		}
	}
}

// writeToStream writes data to a specific stream's remote connection.
func (b *socks5Bridge) writeToStream(id uint16, data []byte) error {
	b.mu.Lock()
	stream, ok := b.streams[id]
	b.mu.Unlock()

	if !ok || stream == nil {
		return fmt.Errorf("stream %d not found", id)
	}

	_, err := stream.conn.Write(data)
	return err
}

// readFromStreams collects buffered data from all streams.
// Each chunk in the response: [stream_id 2B][length 2B][data...]
// A zero-length chunk signals that the remote closed the stream.
// Multiple chunks can be packed into a single response.
func (b *socks5Bridge) readFromStreams(maxBytes int) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []byte
	var closedStreams []uint16
	moreData := false
	headerSize := 4 // 2 stream_id + 2 length

	for _, stream := range b.streams {
		stream.mu.Lock()
		if len(stream.buf) > 0 {
			available := maxBytes - len(result) - headerSize
			if available <= 0 {
				stream.mu.Unlock()
				moreData = true
				break
			}
			n := len(stream.buf)
			if n > available {
				n = available
				moreData = true
			}

			chunk := make([]byte, headerSize+n)
			chunk[0] = byte(stream.id >> 8)
			chunk[1] = byte(stream.id)
			chunk[2] = byte(n >> 8)
			chunk[3] = byte(n)
			copy(chunk[4:], stream.buf[:n])
			stream.buf = stream.buf[n:]

			if len(stream.buf) > 0 {
				moreData = true
			}

			result = append(result, chunk...)
		} else if stream.remoteClosed {
			// Buffer drained and remote closed — send close signal
			if len(result)+headerSize <= maxBytes {
				chunk := make([]byte, headerSize)
				chunk[0] = byte(stream.id >> 8)
				chunk[1] = byte(stream.id)
				// length = 0 signals stream close
				closedStreams = append(closedStreams, stream.id)
				result = append(result, chunk...)
			} else {
				moreData = true
			}
		}
		stream.mu.Unlock()

		if len(result) >= maxBytes-headerSize {
			moreData = true
			break
		}
	}

	// Remove fully closed streams
	for _, id := range closedStreams {
		delete(b.streams, id)
	}

	return result, moreData
}

// Close closes all streams.
func (b *socks5Bridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, stream := range b.streams {
		stream.conn.Close()
	}
	b.streams = make(map[uint16]*proxyStream)
}

// handleSocks5Start enables SOCKS5 proxy mode for the session.
func (h *Handler) handleSocks5Start(pkt *protocol.Packet, channelID byte) *protocol.Frame {
	session := h.sessions.Get(channelID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	session.mu.Lock()
	session.Socks5 = newSocks5Bridge()
	session.mu.Unlock()

	log.Printf("ch %d: socks5 proxy enabled", channelID)
	return &protocol.Frame{Payload: []byte("ok")}
}

// handleStreamOpen opens a new proxied TCP connection.
// Payload: [stream_id 2B][addr_type 1B][addr...][port 2B]
func (h *Handler) handleStreamOpen(pkt *protocol.Packet, channelID byte) *protocol.Frame {
	session := h.sessions.Get(channelID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	if session.Socks5 == nil {
		return &protocol.Frame{Flags: protocol.FlagError, Payload: []byte("socks5 not active")}
	}

	if len(pkt.Payload) < 5 {
		return errorFrame()
	}

	streamID := uint16(pkt.Payload[0])<<8 | uint16(pkt.Payload[1])
	addrType := pkt.Payload[2]

	var host string
	var portOffset int

	switch addrType {
	case 0x01: // IPv4
		if len(pkt.Payload) < 2+1+4+2 {
			return errorFrame()
		}
		host = fmt.Sprintf("%d.%d.%d.%d", pkt.Payload[3], pkt.Payload[4], pkt.Payload[5], pkt.Payload[6])
		portOffset = 7
	case 0x03: // Domain
		if len(pkt.Payload) < 2+1+1 {
			return errorFrame()
		}
		domainLen := int(pkt.Payload[3])
		if len(pkt.Payload) < 2+1+1+domainLen+2 {
			return errorFrame()
		}
		host = string(pkt.Payload[4 : 4+domainLen])
		portOffset = 4 + domainLen
	case 0x04: // IPv6
		if len(pkt.Payload) < 2+1+16+2 {
			return errorFrame()
		}
		ip := net.IP(pkt.Payload[3:19])
		host = ip.String()
		portOffset = 19
	default:
		return &protocol.Frame{Flags: protocol.FlagError, Payload: []byte("unsupported address type")}
	}

	port := uint16(pkt.Payload[portOffset])<<8 | uint16(pkt.Payload[portOffset+1])
	addr := fmt.Sprintf("%s:%d", host, port)

	if err := session.Socks5.openStream(streamID, addr, channelID); err != nil {
		log.Printf("ch %d: socks5 stream %d connect failed: %v", channelID, streamID, err)
		return &protocol.Frame{Flags: protocol.FlagError, Payload: []byte(err.Error())}
	}

	return &protocol.Frame{Payload: []byte("ok")}
}

// handleStreamClose closes a proxied TCP connection.
// Payload: [stream_id 2B]
func (h *Handler) handleStreamClose(pkt *protocol.Packet, channelID byte) *protocol.Frame {
	session := h.sessions.Get(channelID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	if session.Socks5 == nil || len(pkt.Payload) < 2 {
		return errorFrame()
	}

	streamID := uint16(pkt.Payload[0])<<8 | uint16(pkt.Payload[1])
	session.Socks5.closeStream(streamID)
	log.Printf("ch %d: socks5 stream %d closed", channelID, streamID)

	return &protocol.Frame{}
}
