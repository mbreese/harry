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

	// Process command — returns a frame ready for encoding
	frame := h.processCommand(pkt, clientID, src)

	// Encrypt frame payload
	if len(frame.Payload) > 0 {
		encrypted, err := h.cipher.Encrypt(frame.Payload)
		if err != nil {
			log.Printf("encrypt error: %v", err)
			msg.Rcode = dns.RcodeServerFailure
			w.WriteMsg(msg)
			return
		}
		frame.Payload = encrypted
	}

	// Build wire frame with CRC and encode as TXT record
	txt := encoding.Encode(protocol.MarshalFrame(frame))

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

// errorFrame returns a frame with the error flag set.
func errorFrame() *protocol.Frame {
	return &protocol.Frame{Flags: protocol.FlagError}
}

// processCommand handles a decoded packet and returns a frame for the response.
func (h *Handler) processCommand(pkt *protocol.Packet, clientID byte, src string) *protocol.Frame {
	switch pkt.Cmd {
	case protocol.CmdConnect:
		return h.handleConnect(src)
	case protocol.CmdPoll:
		return h.handlePoll(pkt, clientID)
	case protocol.CmdData:
		return h.handleData(pkt, clientID)
	case protocol.CmdFile:
		return h.handleFile(pkt, clientID)
	case protocol.CmdTune:
		return h.handleTune(pkt, clientID)
	case protocol.CmdUpload:
		return h.handleUploadStart(pkt, clientID)
	case protocol.CmdUploadDone:
		return h.handleUploadDone(pkt, clientID)
	case protocol.CmdList:
		return h.handleList(clientID)
	case protocol.CmdFetch:
		return h.handleFetch(pkt, clientID)
	default:
		log.Printf("unknown command: %c", pkt.Cmd)
		return errorFrame()
	}
}

func (h *Handler) handleConnect(src string) *protocol.Frame {
	session, err := h.sessions.NewSession()
	if err != nil {
		log.Printf("[%s] connect error: %v", src, err)
		return errorFrame()
	}
	log.Printf("[%s] new client connected: ID=%d", src, session.ID)
	return &protocol.Frame{
		Payload: []byte{session.ID},
	}
}

// handlePoll returns the next chunk of an active transfer.
// The client's payload contains: [transfer_id 2B] [last_ack 2B]
// If transfer_id is 0, the client is just polling (no active download).
func (h *Handler) handlePoll(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	// Parse ACK from client payload
	if len(pkt.Payload) < 4 {
		// No ACK data — just a bare poll
		return &protocol.Frame{}
	}

	transferID := uint16(pkt.Payload[0])<<8 | uint16(pkt.Payload[1])
	lastAck := uint16(pkt.Payload[2])<<8 | uint16(pkt.Payload[3])

	t := session.Transfers.Get(transferID)
	if t == nil {
		return errorFrame()
	}

	// Next chunk is lastAck + 1
	nextIdx := lastAck + 1
	if nextIdx >= t.TotalChunks {
		// Transfer complete — clean up
		session.Transfers.Remove(transferID)
		return &protocol.Frame{}
	}

	return h.chunkFrame(t, nextIdx)
}

func (h *Handler) handleData(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	// Deduplicate retried requests (DNS resolver may retry)
	if session.isDuplicate(pkt.Counter) {
		return &protocol.Frame{}
	}

	// If an upload is active, write data to the upload file
	if session.UploadFile != "" && len(pkt.Payload) > 0 {
		if err := h.appendUpload(session, pkt.Payload); err != nil {
			log.Printf("client %d: upload write error: %v", clientID, err)
			return errorFrame()
		}
	} else if len(pkt.Payload) > 0 {
		log.Printf("client %d: received %d bytes upstream (no active upload)", clientID, len(pkt.Payload))
	}

	// ACK the upload chunk
	return &protocol.Frame{}
}

// chunkFrame builds a frame for a specific chunk of a transfer.
func (h *Handler) chunkFrame(t *Transfer, idx uint16) *protocol.Frame {
	chunk := t.GetChunk(idx)
	flags := byte(0)
	if idx < t.TotalChunks-1 {
		flags |= protocol.FlagMoreData
	}
	return &protocol.Frame{
		TransferID: t.ID,
		ChunkIdx:   idx,
		ChunkTotal: t.TotalChunks,
		Flags:      flags,
		Payload:    chunk,
	}
}

func (h *Handler) handleFile(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	filename := string(pkt.Payload)
	data, err := h.files.Get(filename)
	if err != nil {
		log.Printf("client %d: file request error: %v", clientID, err)
		return errorFrame()
	}

	// Prepend SHA1 hash (20 bytes) so client can verify integrity
	hash := sha1.Sum(data)
	payload := append(hash[:], data...)

	// Create a transfer with indexed chunks
	maxPayload := h.responsePayloadSize(session)
	t := session.Transfers.NewTransfer(payload, maxPayload)
	log.Printf("client %d: file %q → transfer %d (%d bytes, %d chunks, sha1=%x)",
		clientID, filename, t.ID, len(data), t.TotalChunks, hash)

	// Return first chunk
	return h.chunkFrame(t, 0)
}

func (h *Handler) handleList(clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
	}
	session.LastSeen = now()

	names, err := h.files.List()
	if err != nil {
		log.Printf("client %d: list error: %v", clientID, err)
		return errorFrame()
	}

	payload := []byte(strings.Join(names, "\n"))
	maxPayload := h.responsePayloadSize(session)
	t := session.Transfers.NewTransfer(payload, maxPayload)
	return h.chunkFrame(t, 0)
}

func (h *Handler) handleTune(pkt *protocol.Packet, clientID byte) *protocol.Frame {
	session := h.sessions.Get(clientID)
	if session == nil {
		return errorFrame()
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
		return &protocol.Frame{Payload: []byte("ok")}
	}

	// Send a test payload sized to fill the target TuneSize
	payload := make([]byte, testSize)
	payload[0] = byte(testSize >> 8)
	payload[1] = byte(testSize)
	for i := 2; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	return &protocol.Frame{Payload: payload}
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
