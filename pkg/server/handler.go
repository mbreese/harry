package server

import (
	"crypto/sha1"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mbreese/harry/pkg/crypto"
	"github.com/mbreese/harry/pkg/encoding"
	"github.com/mbreese/harry/pkg/protocol"

	"github.com/miekg/dns"
)

// Handler processes DNS tunnel requests.
type Handler struct {
	config    *Config
	sessions  *SessionManager
	files     *FileStore
	cipher    *crypto.Cipher
	qc        *protocol.QueryConfig
	bootCache *bootstrapCache
}

// Config holds server configuration.
type Config struct {
	Domain    string // base domain (e.g., "a.b.com")
	Password  string // shared secret
	FileDir   string // directory for downloadable files
	UploadDir string // directory for uploaded files
	CacheDir  string // directory for bootstrap cache (empty = temp dir)
	Listen    string // listen address (e.g., ":53")
	TTL       uint32 // DNS TTL (default 1)
	Verbose   bool   // log all queries including stray traffic
}

// New creates a new tunnel server handler.
func New(cfg *Config) (*Handler, error) {
	c, err := crypto.NewCipher(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	if cfg.TTL == 0 {
		cfg.TTL = 1
	}

	return &Handler{
		config:    cfg,
		sessions:  NewSessionManager(),
		files:     NewFileStore(cfg.FileDir),
		cipher:    c,
		qc:        &protocol.QueryConfig{Domain: cfg.Domain},
		bootCache: newBootstrapCache(cfg.CacheDir),
	}, nil
}

// ServeDNS implements the dns.Handler interface.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	src := w.RemoteAddr().String()

	// Strip trailing dot from DNS name
	qname := strings.TrimSuffix(q.Name, ".")
	qnameLower := strings.ToLower(qname)
	domainLower := strings.ToLower(h.config.Domain)

	// Reject queries outside our domain entirely
	if !strings.HasSuffix(qnameLower, "."+domainLower) && qnameLower != domainLower {
		if h.config.Verbose {
			log.Printf("[%s] ignoring query outside domain: %s %s", src, dns.TypeToString[q.Qtype], qname)
		}
		// Don't respond at all — we're not authoritative for other domains
		return
	}

	// Handle SOA queries (resolvers need this to validate our authority)
	if q.Qtype == dns.TypeSOA {
		msg.Answer = append(msg.Answer, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(h.config.Domain),
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      dns.Fqdn("ns." + h.config.Domain),
			Mbox:    dns.Fqdn("admin." + h.config.Domain),
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  60,
		})
		w.WriteMsg(msg)
		return
	}

	// Handle NS queries
	if q.Qtype == dns.TypeNS {
		msg.Answer = append(msg.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(h.config.Domain),
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: dns.Fqdn("ns." + h.config.Domain),
		})
		w.WriteMsg(msg)
		return
	}

	// Only handle TXT queries for tunnel/bootstrap
	if q.Qtype != dns.TypeTXT {
		if h.config.Verbose {
			log.Printf("[%s] ignoring non-TXT query: %s %s", src, dns.TypeToString[q.Qtype], qname)
		}
		msg.Rcode = dns.RcodeNameError
		w.WriteMsg(msg)
		return
	}

	// Handle bootstrap requests (plaintext, no encryption)
	if h.handleBootstrap(qnameLower, domainLower, &q, msg) {
		if h.config.Verbose {
			log.Printf("[%s] bootstrap: %s", src, qname)
		}
		w.WriteMsg(msg)
		return
	}

	// Decode the tunnel query
	pkt, clientID, err := h.qc.DecodeQuery(qname)
	if err != nil {
		if h.config.Verbose {
			log.Printf("[%s] stray query: %s", src, qname)
		}
		msg.Rcode = dns.RcodeNameError
		w.WriteMsg(msg)
		return
	}

	// Decrypt payload if present
	if len(pkt.Payload) > 0 {
		decrypted, err := h.cipher.Decrypt(pkt.Payload)
		if err != nil {
			log.Printf("decrypt error from client %d: %v", clientID, err)
			msg.Rcode = dns.RcodeRefused
			w.WriteMsg(msg)
			return
		}
		pkt.Payload = decrypted
	}

	// Process command
	resp, session := h.processCommand(pkt, clientID, src)

	// Get sequence number
	var seq uint16
	if session != nil {
		seq = session.NextSeq()
	}

	// Encrypt response payload
	var encPayload []byte
	if len(resp.Payload) > 0 {
		encrypted, err := h.cipher.Encrypt(resp.Payload)
		if err != nil {
			log.Printf("encrypt error: %v", err)
			msg.Rcode = dns.RcodeServerFailure
			w.WriteMsg(msg)
			return
		}
		encPayload = encrypted
	}

	// Build frame with CRC and sequence number
	frameData := protocol.MarshalFrame(seq, resp.Flags, encPayload)

	// Encode as TXT record
	txt := encoding.Encode(frameData)

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    h.config.TTL,
		},
		Txt: splitTXT(txt),
	}
	msg.Answer = append(msg.Answer, rr)
	w.WriteMsg(msg)
}

// processCommand handles a decoded packet and returns a response and the session.
func (h *Handler) processCommand(pkt *protocol.Packet, clientID byte, src string) (*protocol.Response, *Session) {
	switch pkt.Cmd {
	case protocol.CmdConnect:
		resp, session := h.handleConnect(src)
		return resp, session
	case protocol.CmdPoll:
		return h.handlePoll(clientID), h.sessions.Get(clientID)
	case protocol.CmdData:
		return h.handleData(pkt, clientID), h.sessions.Get(clientID)
	case protocol.CmdFile:
		return h.handleFile(pkt, clientID), h.sessions.Get(clientID)
	case protocol.CmdTune:
		return h.handleTune(pkt, clientID), h.sessions.Get(clientID)
	case protocol.CmdUpload:
		return h.handleUploadStart(pkt, clientID), h.sessions.Get(clientID)
	case protocol.CmdUploadDone:
		return h.handleUploadDone(pkt, clientID), h.sessions.Get(clientID)
	case protocol.CmdList:
		return h.handleList(clientID), h.sessions.Get(clientID)
	case protocol.CmdFetch:
		return h.handleFetch(pkt, clientID), h.sessions.Get(clientID)
	default:
		log.Printf("unknown command: %c", pkt.Cmd)
		return &protocol.Response{Flags: protocol.FlagError}, nil
	}
}

func (h *Handler) handleConnect(src string) (*protocol.Response, *Session) {
	session, err := h.sessions.NewSession()
	if err != nil {
		log.Printf("[%s] connect error: %v", src, err)
		return &protocol.Response{Flags: protocol.FlagError}, nil
	}
	log.Printf("[%s] new client connected: ID=%d", src, session.ID)
	return &protocol.Response{
		Payload: []byte{session.ID},
	}, session
}

func (h *Handler) handlePoll(clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	// Dequeue data for client
	maxPayload := h.responsePayloadSize(session)
	data, more := session.Dequeue(maxPayload)

	flags := byte(0)
	if more {
		flags |= protocol.FlagMoreData
	}
	return &protocol.Response{
		Flags:   flags,
		Payload: data,
	}
}

func (h *Handler) handleData(pkt *protocol.Packet, clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	// If an upload is active, write data to the upload file
	if session.UploadFile != "" && len(pkt.Payload) > 0 {
		if err := h.appendUpload(session, pkt.Payload); err != nil {
			log.Printf("client %d: upload write error: %v", clientID, err)
			return &protocol.Response{Flags: protocol.FlagError}
		}
	} else if len(pkt.Payload) > 0 {
		log.Printf("client %d: received %d bytes upstream (no active upload)", clientID, len(pkt.Payload))
	}

	// Return any queued downstream data
	maxPayload := h.responsePayloadSize(session)
	data, more := session.Dequeue(maxPayload)

	flags := byte(0)
	if more {
		flags |= protocol.FlagMoreData
	}
	return &protocol.Response{
		Flags:   flags,
		Payload: data,
	}
}

func (h *Handler) handleFile(pkt *protocol.Packet, clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	filename := string(pkt.Payload)
	data, err := h.files.Get(filename)
	if err != nil {
		log.Printf("client %d: file request error: %v", clientID, err)
		return &protocol.Response{Flags: protocol.FlagError}
	}

	// Prepend SHA1 hash (20 bytes) so client can verify integrity
	hash := sha1.Sum(data)
	payload := append(hash[:], data...)

	// Queue the file data for streaming to the client
	session.QueueData(payload)
	log.Printf("client %d: queued file %q (%d bytes, sha1=%x)", clientID, filename, len(data), hash)

	// Return first chunk
	maxPayload := h.responsePayloadSize(session)
	chunk, more := session.Dequeue(maxPayload)

	flags := byte(0)
	if more {
		flags |= protocol.FlagMoreData
	}
	return &protocol.Response{
		Flags:   flags,
		Payload: chunk,
	}
}

func (h *Handler) handleList(clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	names, err := h.files.List()
	if err != nil {
		log.Printf("client %d: list error: %v", clientID, err)
		return &protocol.Response{Flags: protocol.FlagError}
	}

	// Join with newlines
	payload := []byte(strings.Join(names, "\n"))

	// If it fits in one response, send directly
	maxPayload := h.responsePayloadSize(session)
	if len(payload) <= maxPayload {
		return &protocol.Response{Payload: payload}
	}

	// Otherwise queue and stream
	session.QueueData(payload)
	chunk, more := session.Dequeue(maxPayload)
	flags := byte(0)
	if more {
		flags |= protocol.FlagMoreData
	}
	return &protocol.Response{Flags: flags, Payload: chunk}
}

func (h *Handler) handleTune(pkt *protocol.Packet, clientID byte) *protocol.Response {
	session := h.sessions.Get(clientID)
	if session == nil {
		return &protocol.Response{Flags: protocol.FlagError}
	}
	session.LastSeen = now()

	// Payload is the confirmed size from last round
	if len(pkt.Payload) >= 2 {
		confirmed := int(pkt.Payload[0])<<8 | int(pkt.Payload[1])
		session.TuneSize = confirmed
	}

	// Try next size
	var testSize int
	switch session.TuneSize {
	case 255:
		testSize = 512
	case 512:
		testSize = 1000
	default:
		// Already at max or unknown, stay where we are
		return &protocol.Response{Payload: []byte("ok")}
	}

	// Send a response padded to the test size
	payload := make([]byte, testSize)
	payload[0] = byte(testSize >> 8)
	payload[1] = byte(testSize)
	// Fill rest with recognizable pattern
	for i := 2; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	return &protocol.Response{Payload: payload}
}

// responsePayloadSize returns the max response payload in bytes,
// accounting for CRC, sequence number, flags, encryption overhead,
// and base36 encoding expansion.
func (h *Handler) responsePayloadSize(session *Session) int {
	// How many raw bytes fit in TuneSize base36 chars?
	rawCapacity := encoding.MaxDecodedSize(session.TuneSize)
	// Raw layout: [crc32 4B] [seq 2B] [flags 1B] [nonce+ciphertext+tag]
	overhead := protocol.FrameOverhead + h.cipher.Overhead()
	if rawCapacity <= overhead {
		return 0
	}
	return rawCapacity - overhead
}

// splitTXT splits a string into 255-char chunks for DNS TXT records.
func splitTXT(s string) []string {
	var parts []string
	for len(s) > 0 {
		end := 255
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[:end])
		s = s[end:]
	}
	if len(parts) == 0 {
		parts = []string{""}
	}
	return parts
}

func now() time.Time { return time.Now() }
