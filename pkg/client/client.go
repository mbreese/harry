// Package client implements the DNS tunnel client.
package client

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mbreese/harry/pkg/crypto"
	"github.com/mbreese/harry/pkg/protocol"

	"github.com/miekg/dns"
)

// Config holds client configuration.
type Config struct {
	Domain      string        // base domain (e.g., "tunnel.example.com")
	Password    string        // shared secret
	Resolver    string        // DNS resolver address (e.g., "8.8.8.8:53")
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

	resp, err := c.sendPacket(pkt, 0) // clientID 0 for connect
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	if resp.Flags&protocol.FlagError != 0 {
		return fmt.Errorf("server returned error on connect")
	}

	if len(resp.Payload) < 1 {
		return fmt.Errorf("no client ID in connect response")
	}

	c.clientID = resp.Payload[0]
	log.Printf("connected with client ID: %d", c.clientID)

	// Run auto-tune
	if err := c.autoTune(); err != nil {
		log.Printf("auto-tune failed, using default size %d: %v", c.tuneSize, err)
	}

	return nil
}

// Poll checks the server for queued data.
func (c *Client) Poll() (*protocol.Response, error) {
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdPoll,
		Counter: c.nextCounter(),
	}
	return c.sendPacket(pkt, c.clientID)
}

// SendData sends upstream data and returns any downstream response.
func (c *Client) SendData(data []byte) (*protocol.Response, error) {
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
	FetchNoRedirect byte = 1 << 0 // Don't follow redirects
)

// FetchURL requests the server to fetch a URL and returns the response.
// flags controls behavior (e.g., FetchNoRedirect).
func (c *Client) FetchURL(url string, flags byte) ([]byte, error) {
	// Payload: [flags 1B] [url...]
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

	var result []byte

	resp, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return nil, err
	}
	if resp.Flags&protocol.FlagError != 0 {
		if len(resp.Payload) > 0 {
			return nil, fmt.Errorf("%s", resp.Payload)
		}
		return nil, fmt.Errorf("server error fetching URL")
	}
	result = append(result, resp.Payload...)

	for resp.Flags&protocol.FlagMoreData != 0 {
		resp, err = c.Poll()
		if err != nil {
			return nil, err
		}
		result = append(result, resp.Payload...)
	}

	return result, nil
}

// ListFiles returns the list of files available on the server.
func (c *Client) ListFiles() ([]string, error) {
	pkt := &protocol.Packet{
		Cmd:     protocol.CmdList,
		Counter: c.nextCounter(),
	}

	var result []byte

	resp, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return nil, err
	}
	if resp.Flags&protocol.FlagError != 0 {
		return nil, fmt.Errorf("server error listing files")
	}
	result = append(result, resp.Payload...)

	for resp.Flags&protocol.FlagMoreData != 0 {
		resp, err = c.Poll()
		if err != nil {
			return nil, err
		}
		result = append(result, resp.Payload...)
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

	var result []byte

	resp, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return nil, err
	}
	if resp.Flags&protocol.FlagError != 0 {
		return nil, fmt.Errorf("file not found: %s", name)
	}

	result = append(result, resp.Payload...)

	for resp.Flags&protocol.FlagMoreData != 0 {
		resp, err = c.Poll()
		if err != nil {
			return nil, err
		}
		result = append(result, resp.Payload...)
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

// UploadFile uploads a local file to the server.
func (c *Client) UploadFile(localPath, remoteName string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Start upload
	encName, err := c.cipher.Encrypt([]byte(remoteName))
	if err != nil {
		return fmt.Errorf("encrypt filename: %w", err)
	}

	pkt := &protocol.Packet{
		Cmd:     protocol.CmdUpload,
		Counter: c.nextCounter(),
		Payload: encName,
	}

	resp, err := c.sendPacket(pkt, c.clientID)
	if err != nil {
		return fmt.Errorf("upload start: %w", err)
	}
	if resp.Flags&protocol.FlagError != 0 {
		return fmt.Errorf("server rejected upload")
	}

	// Send data in chunks
	maxPayload := c.qc.MaxPayload(c.clientID) - c.cipher.Overhead()
	if maxPayload <= 0 {
		return fmt.Errorf("no space for upload data")
	}

	sent := 0
	for sent < len(data) {
		end := sent + maxPayload
		if end > len(data) {
			end = len(data)
		}
		chunk := data[sent:end]

		encrypted, err := c.cipher.Encrypt(chunk)
		if err != nil {
			return fmt.Errorf("encrypt chunk: %w", err)
		}

		pkt := &protocol.Packet{
			Cmd:     protocol.CmdData,
			Counter: c.nextCounter(),
			Payload: encrypted,
		}

		resp, err := c.sendPacket(pkt, c.clientID)
		if err != nil {
			return fmt.Errorf("upload chunk: %w", err)
		}
		if resp.Flags&protocol.FlagError != 0 {
			return fmt.Errorf("server error during upload at byte %d", sent)
		}

		sent = end
		log.Printf("upload: %d/%d bytes", sent, len(data))
	}

	// Signal upload complete with SHA1 hash for verification
	hash := sha1.Sum(data)
	hashHex := fmt.Sprintf("%x", hash)

	encHash, err := c.cipher.Encrypt([]byte(hashHex))
	if err != nil {
		return fmt.Errorf("encrypt hash: %w", err)
	}

	pkt = &protocol.Packet{
		Cmd:     protocol.CmdUploadDone,
		Counter: c.nextCounter(),
		Payload: encHash,
	}
	resp, err = c.sendPacket(pkt, c.clientID)
	if err != nil {
		return fmt.Errorf("upload done: %w", err)
	}
	if resp.Flags&protocol.FlagError != 0 {
		if len(resp.Payload) > 0 {
			return fmt.Errorf("upload verification failed: %s", resp.Payload)
		}
		return fmt.Errorf("server error on upload complete")
	}

	log.Printf("upload complete: %d bytes", len(data))
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

		resp, err := c.sendPacket(pkt, c.clientID)
		if err != nil {
			log.Printf("auto-tune: size %d failed: %v", size, err)
			break
		}

		if resp.Flags&protocol.FlagError != 0 {
			break
		}

		c.tuneSize = size
		log.Printf("auto-tune: confirmed size %d", size)
	}

	return nil
}

// sendPacket encodes a packet as a DNS query and sends it.
func (c *Client) sendPacket(pkt *protocol.Packet, clientID byte) (*protocol.Response, error) {
	query, err := c.qc.EncodeQuery(pkt, clientID)
	if err != nil {
		return nil, fmt.Errorf("encode query: %w", err)
	}

	// Build DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(query), dns.TypeTXT)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false) // Request larger UDP buffer

	// Send query
	dnsClient := &dns.Client{Timeout: 10 * time.Second}
	resp, _, err := dnsClient.Exchange(msg, c.config.Resolver)
	if err != nil {
		return nil, fmt.Errorf("dns exchange: %w", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	// Extract TXT record
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

	// Decode response
	resp2, err := protocol.DecodeResponse(txt)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Decrypt payload if present
	if len(resp2.Payload) > 0 {
		decrypted, err := c.cipher.Decrypt(resp2.Payload)
		if err != nil {
			return nil, fmt.Errorf("decrypt response: %w", err)
		}
		resp2.Payload = decrypted
	}

	return resp2, nil
}

// systemResolver reads the first nameserver from /etc/resolv.conf.
// Falls back to 127.0.0.53:53 if the file can't be read.
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
	return c.counter & 0xFFFFFF // 24 bits
}
