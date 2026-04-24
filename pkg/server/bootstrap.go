package server

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	// Each TXT string can be up to 255 bytes. We pack multiple strings per
	// response for larger chunks. Using 253 chars per string * 3 strings
	// gives us ~759 chars of base64 per chunk (~569 raw bytes).
	bootTXTStringSize   = 253
	bootStringsPerChunk = 3
	bootChunkSize       = bootTXTStringSize * bootStringsPerChunk
)

// bootstrapCache caches compressed+chunked file data
type bootstrapCache struct {
	mu    sync.RWMutex
	files map[string]*bootstrapFile
}

type bootstrapFile struct {
	chunks      []string // base64 encoded chunks
	totalChunks int
}

func newBootstrapCache() *bootstrapCache {
	return &bootstrapCache{
		files: make(map[string]*bootstrapFile),
	}
}

// getOrLoad gets a cached bootstrap file or loads and compresses it
func (bc *bootstrapCache) getOrLoad(fs *FileStore, name string) (*bootstrapFile, error) {
	bc.mu.RLock()
	if bf, ok := bc.files[name]; ok {
		bc.mu.RUnlock()
		return bf, nil
	}
	bc.mu.RUnlock()

	// Load and compress
	data, err := fs.Get(name)
	if err != nil {
		return nil, err
	}

	// Gzip compress
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Write(data)
	gz.Close()

	compressed := buf.Bytes()
	encoded := base64.StdEncoding.EncodeToString(compressed)

	// Split into chunks
	var chunks []string
	for len(encoded) > 0 {
		end := bootChunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[:end])
		encoded = encoded[end:]
	}

	bf := &bootstrapFile{
		chunks:      chunks,
		totalChunks: len(chunks),
	}

	bc.mu.Lock()
	bc.files[name] = bf
	bc.mu.Unlock()

	log.Printf("bootstrap: cached %q: %d bytes -> %d compressed -> %d chunks",
		name, len(data), len(compressed), len(chunks))

	return bf, nil
}

// handleBootstrap handles plaintext bootstrap DNS requests.
//
// Two-stage bootstrap:
//   - boot.<domain>                    → stage 1: tiny script that fetches stage 2
//   - <n>.s.boot.<domain>              → stage 2 script chunks (full download logic)
//
// File serving:
//   - n.<filename>.boot.<domain>       → number of chunks for a file
//   - <chunk>.<filename>.boot.<domain> → chunk of a file (base64, gzipped)
//
// Returns true if this was a bootstrap request (even if it errored).
func (h *Handler) handleBootstrap(qname, domain string, q *dns.Question, msg *dns.Msg) bool {
	prefix := strings.TrimSuffix(qname, "."+domain)
	if prefix == qname {
		return false
	}

	parts := strings.Split(prefix, ".")

	switch {
	case len(parts) == 1 && parts[0] == "boot":
		// Stage 1: tiny loader that fetches and evals stage 2
		script := h.stage1Script()
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{script}, // must fit in one TXT string
		})
		return true

	case len(parts) == 1 && parts[0] == "boothelp":
		// Human-readable bootstrap instructions
		help := h.bootstrapHelp()
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: splitTXT(help),
		})
		return true

	case len(parts) == 3 && parts[1] == "s" && parts[2] == "boot":
		// Stage 2 script chunks: <n>.s.boot.<domain>
		return h.handleStage2Chunk(parts[0], q, msg)

	case len(parts) == 3 && parts[2] == "boot":
		// File chunks: <chunk-id>.<filename>.boot.<domain>
		return h.handleBootstrapChunk(parts[0], parts[1], q, msg)

	default:
		return false
	}
}

// bootstrapHelp returns human-readable instructions for bootstrapping.
func (h *Handler) bootstrapHelp() string {
	return fmt.Sprintf(
		`Run: dig +short TXT boot.%s | xargs echo | sh`,
		h.config.Domain,
	)
}

// stage1Script returns a tiny script (<255 chars) that fetches and evals stage 2.
// Usage: dig +short TXT boot.<domain> | xargs echo | sh
// IMPORTANT: No double quotes allowed - dig would escape them, breaking xargs.
// Uses system default resolver (no @). Dig resolves via /etc/resolv.conf.
func (h *Handler) stage1Script() string {
	return fmt.Sprintf(
		`i=0;S=;while :;do C=$(dig +short TXT $i.s.boot.%s|xargs);case $C in ?*)S=${S}$C;i=$((i+1));;*)break;;esac;done;eval $S`,
		h.config.Domain,
	)
}

// stage2Script returns the full download script (can be any length, served in chunks).
// IMPORTANT: No double quotes allowed - chunks go through xargs which can't handle escaped quotes.
// Uses sed to strip non-data characters instead of xargs (avoids quoting issues in eval context).
// Uses system default resolver (no @).
func (h *Handler) stage2Script() string {
	return fmt.Sprintf(`D=%s;O=$(uname -s|tr A-Z a-z);A=$(uname -m);case $A in x86_64)A=amd64;;aarch64)A=arm64;;esac;F=harry-$O-$A;echo downloading $F;N=$(dig +short TXT n.$F.boot.$D|head -1|sed s/[^0-9]//g);echo $N chunks;i=0;B=;while [ $i -lt $N ];do C=$(dig +short TXT $i.$F.boot.$D|sed s/[^A-Za-z0-9+/=]//g);B=${B}$C;i=$((i+1));case $((i%%100)) in 0)echo $i/$N;;esac;done;echo;printf %%s $B|base64 -d|gunzip>harry;chmod +x harry;echo done`,
		h.config.Domain)
}

// stage2Chunks splits the stage 2 script into 253-char TXT-safe chunks.
func (h *Handler) stage2Chunks() []string {
	script := h.stage2Script()
	var chunks []string
	for len(script) > 0 {
		end := 253
		if end > len(script) {
			end = len(script)
		}
		chunks = append(chunks, script[:end])
		script = script[end:]
	}
	return chunks
}

func (h *Handler) handleStage2Chunk(idxStr string, q *dns.Question, msg *dns.Msg) bool {
	chunks := h.stage2Chunks()

	var idx int
	if _, err := fmt.Sscanf(idxStr, "%d", &idx); err != nil {
		msg.Rcode = dns.RcodeNameError
		return true
	}

	if idx < 0 || idx >= len(chunks) {
		// Return empty response (signals end of script to stage 1)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{""},
		})
		return true
	}

	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: []string{chunks[idx]},
	})
	return true
}

func (h *Handler) handleBootstrapChunk(chunkID, filename string, q *dns.Question, msg *dns.Msg) bool {
	bf, err := h.bootCache.getOrLoad(h.files, filename)
	if err != nil {
		log.Printf("bootstrap: file %q not found: %v", filename, err)
		msg.Rcode = dns.RcodeNameError
		return true
	}

	if chunkID == "n" {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{fmt.Sprintf("%d", bf.totalChunks)},
		})
		return true
	}

	var idx int
	if _, err := fmt.Sscanf(chunkID, "%d", &idx); err != nil {
		log.Printf("bootstrap: invalid chunk id %q", chunkID)
		msg.Rcode = dns.RcodeNameError
		return true
	}

	if idx < 0 || idx >= bf.totalChunks {
		log.Printf("bootstrap: chunk %d out of range (0-%d)", idx, bf.totalChunks-1)
		msg.Rcode = dns.RcodeNameError
		return true
	}

	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: splitTXT(bf.chunks[idx]),
	})
	return true
}
