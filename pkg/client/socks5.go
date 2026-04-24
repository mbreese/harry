package client

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/mbreese/harry/pkg/protocol"
)

// socks5Stream tracks a single proxied connection.
type socks5Stream struct {
	id   uint16
	conn net.Conn
	mu   sync.Mutex
	buf  []byte // data from local browser, waiting to send upstream
}

// StartSocks5 starts a local SOCKS5 proxy listener and tunnels traffic through DNS.
func (c *Client) StartSocks5(listenAddr string, pollInterval time.Duration) error {
	// Tell server to enable SOCKS5 mode
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdSocks5,
		Counter: c.nextCounter(),
	}
	frame, err := c.sendPacket(pkt, c.channelID)
	if err != nil {
		return fmt.Errorf("socks5 start: %w", err)
	}
	if frame.Flags&protocol.FlagError != 0 {
		return fmt.Errorf("socks5: %s", frame.Payload)
	}

	// Start local SOCKS5 listener
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer listener.Close()

	log.Printf("socks5: listening on %s", listener.Addr())

	var (
		mu      sync.Mutex
		streams = make(map[uint16]*socks5Stream)
		nextID  uint16
	)

	// Accept SOCKS5 connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			mu.Lock()
			nextID++
			id := nextID
			mu.Unlock()

			go func() {
				stream, err := c.handleSocks5Conn(conn, id)
				if err != nil {
					log.Printf("socks5: stream %d handshake failed: %v", id, err)
					conn.Close()
					return
				}

				mu.Lock()
				streams[id] = stream
				mu.Unlock()

				log.Printf("socks5: stream %d connected", id)

				// Read from browser in background
				go func() {
					buf := make([]byte, 4096)
					for {
						n, err := conn.Read(buf)
						if n > 0 {
							stream.mu.Lock()
							stream.buf = append(stream.buf, buf[:n]...)
							stream.mu.Unlock()
						}
						if err != nil {
							closePkt := &protocol.Packet{
								Cmd:     protocol.CmdStreamClose,
								Counter: c.nextCounter(),
								Payload: []byte{byte(id >> 8), byte(id)},
							}
							c.sendPacket(closePkt, c.channelID)

							mu.Lock()
							delete(streams, id)
							mu.Unlock()
							return
						}
					}
				}()
			}()
		}
	}()

	// Main polling loop
	for {
		// Collect upstream data from one stream
		var upstreamData []byte
		mu.Lock()
		for _, stream := range streams {
			stream.mu.Lock()
			if len(stream.buf) > 0 {
				maxChunk := c.MaxUpstreamChunk() - 4 // -4 for stream ID + length prefix
				if maxChunk <= 0 {
					stream.mu.Unlock()
					continue
				}
				n := len(stream.buf)
				if n > maxChunk {
					n = maxChunk
				}
				chunk := make([]byte, 4+n)
				chunk[0] = byte(stream.id >> 8)
				chunk[1] = byte(stream.id)
				chunk[2] = byte(n >> 8)
				chunk[3] = byte(n)
				copy(chunk[4:], stream.buf[:n])
				stream.buf = stream.buf[n:]
				upstreamData = chunk
				stream.mu.Unlock()
				break
			}
			stream.mu.Unlock()
		}
		activeStreams := len(streams)
		mu.Unlock()

		var respFrame *protocol.Frame

		if len(upstreamData) > 0 {
			respFrame, err = c.SendData(upstreamData)
			if err != nil {
				log.Printf("socks5: send error: %v", err)
				time.Sleep(time.Second)
				continue
			}
		} else if activeStreams > 0 {
			// Active streams but no upstream data — poll for downstream
			respFrame, err = c.Poll()
			if err != nil {
				log.Printf("socks5: poll error: %v", err)
				time.Sleep(time.Second)
				continue
			}
		} else {
			// No streams — idle wait
			time.Sleep(pollInterval)
			continue
		}

		// Route downstream data
		if respFrame != nil && len(respFrame.Payload) > 0 {
			c.routeDownstream(respFrame.Payload, streams, &mu)
		}

		// Drain all queued server data
		for respFrame != nil && respFrame.Flags&protocol.FlagMoreData != 0 {
			respFrame, err = c.Poll()
			if err != nil {
				break
			}
			if len(respFrame.Payload) > 0 {
				c.routeDownstream(respFrame.Payload, streams, &mu)
			}
		}

		// Short sleep between polls when active (avoid hammering DNS)
		if len(upstreamData) == 0 && activeStreams > 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// routeDownstream routes server response data to the correct browser connections.
// Data format from server: [stream_id 2B][length 2B][data...] repeated.
func (c *Client) routeDownstream(data []byte, streams map[uint16]*socks5Stream, mu *sync.Mutex) {
	for len(data) >= 4 {
		streamID := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]

		if length > len(data) {
			length = len(data)
		}

		mu.Lock()
		stream, ok := streams[streamID]
		mu.Unlock()

		if ok {
			stream.conn.Write(data[:length])
		}

		data = data[length:]
	}
}

// handleSocks5Conn handles the SOCKS5 handshake for a new connection.
func (c *Client) handleSocks5Conn(conn net.Conn, streamID uint16) (*socks5Stream, error) {
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return nil, fmt.Errorf("greeting read failed")
	}

	if buf[0] != 0x05 {
		return nil, fmt.Errorf("not SOCKS5")
	}

	// Accept no-auth
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return nil, fmt.Errorf("connect request read failed")
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		return nil, fmt.Errorf("only CONNECT supported")
	}

	addrType := buf[3]
	var addrPayload []byte

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return nil, fmt.Errorf("IPv4 request too short")
		}
		addrPayload = buf[3:10]
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return nil, fmt.Errorf("domain request too short")
		}
		addrPayload = buf[3 : 5+domainLen+2]
	case 0x04: // IPv6
		if n < 22 {
			return nil, fmt.Errorf("IPv6 request too short")
		}
		addrPayload = buf[3:22]
	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Send stream open to server
	openPayload := make([]byte, 2+len(addrPayload))
	openPayload[0] = byte(streamID >> 8)
	openPayload[1] = byte(streamID)
	copy(openPayload[2:], addrPayload)

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdStreamOpen,
		Counter: c.nextCounter(),
		Payload: openPayload,
	}

	frame, err := c.sendPacket(pkt, c.channelID)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("stream open: %w", err)
	}

	if frame.Flags&protocol.FlagError != 0 {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("server rejected: %s", frame.Payload)
	}

	// Send SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	return &socks5Stream{
		id:   streamID,
		conn: conn,
	}, nil
}
