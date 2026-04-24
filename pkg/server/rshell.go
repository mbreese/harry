package server

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/mbreese/harry/pkg/protocol"
)

// rshellBridge manages a TCP listener that bridges to a client's reverse shell.
type rshellBridge struct {
	listener  net.Listener
	session   *Session
	mu        sync.Mutex
	conn      net.Conn // active TCP connection (only one at a time)
	buf       []byte   // data from TCP waiting to be sent to client
	tcpRecv   int64    // bytes received from TCP (to send to client)
	tcpSent   int64    // bytes sent to TCP (from client)
}

// handleRShell starts a reverse shell bridge for the client.
func (h *Handler) handleRShell(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	if h.config.RShellAddr == "" {
		log.Printf("client %d: rshell rejected, no rshell address configured", clientID)
		return &protocol.Frame{
			Flags:   protocol.FlagError,
			Payload: []byte("rshell not enabled on server"),
		}
	}

	// Close any existing rshell bridge for this session
	session.mu.Lock()
	if session.RShell != nil {
		session.RShell.Close()
		session.RShell = nil
	}
	session.mu.Unlock()

	// Start the TCP listener
	listener, err := net.Listen("tcp", h.config.RShellAddr)
	if err != nil {
		log.Printf("client %d: rshell listen error: %v", clientID, err)
		return &protocol.Frame{
			Flags:   protocol.FlagError,
			Payload: []byte(fmt.Sprintf("listen error: %v", err)),
		}
	}

	bridge := &rshellBridge{
		listener: listener,
		session:  session,
	}

	// Store bridge in session
	session.mu.Lock()
	session.RShell = bridge
	session.mu.Unlock()

	log.Printf("client %d: rshell listening on %s", clientID, h.config.RShellAddr)

	// Accept connections in background
	go bridge.acceptLoop(clientID)

	return &protocol.Frame{
		Payload: []byte(fmt.Sprintf("listening on %s", listener.Addr().String())),
	}
}

// acceptLoop accepts TCP connections and reads data from them.
func (b *rshellBridge) acceptLoop(clientID byte) {
	defer b.listener.Close()

	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return // listener closed
		}

		b.mu.Lock()
		// Close previous connection if any
		if b.conn != nil {
			b.conn.Close()
		}
		b.conn = conn
		b.mu.Unlock()

		log.Printf("client %d: rshell TCP connection from %s", clientID, conn.RemoteAddr())

		// Read from TCP in background, buffer for client polling
		go b.readTCP(clientID)
	}
}

// readTCP reads data from the TCP connection and buffers it.
func (b *rshellBridge) readTCP(clientID byte) {
	buf := make([]byte, 4096)
	for {
		b.mu.Lock()
		conn := b.conn
		b.mu.Unlock()
		if conn == nil {
			return
		}

		n, err := conn.Read(buf)
		if n > 0 {
			b.mu.Lock()
			b.buf = append(b.buf, buf[:n]...)
			b.tcpRecv += int64(n)
			log.Printf("client %d: rshell tcp_recv=%d tcp_sent=%d", clientID, b.tcpRecv, b.tcpSent)
			b.mu.Unlock()
		}
		if err != nil {
			b.mu.Lock()
			log.Printf("client %d: rshell TCP closed (tcp_recv=%d tcp_sent=%d)", clientID, b.tcpRecv, b.tcpSent)
			b.mu.Unlock()
			return
		}
	}
}

// WriteToTCP writes data received from the client to the TCP connection.
func (b *rshellBridge) WriteToTCP(data []byte) error {
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("no TCP connection")
	}

	n, err := conn.Write(data)
	b.mu.Lock()
	b.tcpSent += int64(n)
	b.mu.Unlock()
	return err
}

// ReadFromTCP reads buffered data from the TCP connection (for sending to client).
func (b *rshellBridge) ReadFromTCP(maxBytes int) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.buf) == 0 {
		return nil, false
	}

	if maxBytes >= len(b.buf) {
		data := b.buf
		b.buf = nil
		return data, false
	}

	data := make([]byte, maxBytes)
	copy(data, b.buf[:maxBytes])
	b.buf = b.buf[maxBytes:]
	return data, len(b.buf) > 0
}

// Close closes the bridge.
func (b *rshellBridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}
	b.listener.Close()
}
