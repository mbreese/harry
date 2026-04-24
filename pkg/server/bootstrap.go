package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	// Each TXT response can contain multiple strings (up to 255 bytes each).
	// We pack 3 strings per chunk for better throughput.
	bootTXTStringSize   = 253
	bootStringsPerChunk = 3
	bootChunkSize       = bootTXTStringSize * bootStringsPerChunk // 759
)

// bootstrapFileInfo holds metadata about a cached bootstrap file.
type bootstrapFileInfo struct {
	totalChunks int
	sha1Hex     string
	origSize    int64
}

// bootstrapCache stores compressed+chunked files on disk.
type bootstrapCache struct {
	mu    sync.RWMutex
	dir   string                       // tmp directory for chunk files
	files map[string]*bootstrapFileInfo // filename -> info
}

func newBootstrapCache(dir string) *bootstrapCache {
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("", "harry-boot-*")
		if err != nil {
			log.Fatalf("failed to create bootstrap cache dir: %v", err)
		}
	} else {
		os.MkdirAll(dir, 0755)
	}
	log.Printf("bootstrap cache: %s", dir)
	return &bootstrapCache{
		dir:   dir,
		files: make(map[string]*bootstrapFileInfo),
	}
}

// chunkPath returns the path for a specific chunk file.
func (bc *bootstrapCache) chunkPath(name string, idx int) string {
	return filepath.Join(bc.dir, fmt.Sprintf("%s.%d", name, idx))
}

// getInfo returns the cached file info, or nil if not cached.
func (bc *bootstrapCache) getInfo(name string) *bootstrapFileInfo {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.files[name]
}

// getChunk reads a single chunk from disk.
func (bc *bootstrapCache) getChunk(name string, idx int) (string, error) {
	data, err := os.ReadFile(bc.chunkPath(name, idx))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ensureLoaded loads and caches a file if not already cached.
func (bc *bootstrapCache) ensureLoaded(fs *FileStore, name string) (*bootstrapFileInfo, error) {
	if info := bc.getInfo(name); info != nil {
		return info, nil
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Double-check
	if info, ok := bc.files[name]; ok {
		return info, nil
	}

	data, err := fs.Get(name)
	if err != nil {
		return nil, err
	}

	// Compute SHA1 of original file
	hash := sha1.Sum(data)
	hashHex := fmt.Sprintf("%x", hash)

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

	// Write chunks to disk
	idx := 0
	for len(encoded) > 0 {
		end := bootChunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[:end]
		encoded = encoded[end:]

		if err := os.WriteFile(bc.chunkPath(name, idx), []byte(chunk), 0600); err != nil {
			return nil, fmt.Errorf("writing chunk %d: %w", idx, err)
		}
		idx++
	}

	info := &bootstrapFileInfo{
		totalChunks: idx,
		sha1Hex:     hashHex,
		origSize:    int64(len(data)),
	}
	bc.files[name] = info

	log.Printf("bootstrap: cached %q to disk: %d bytes -> %d compressed -> %d chunks (sha1=%s)",
		name, len(data), len(compressed), idx, hashHex)

	return info, nil
}

// handleBootstrap handles plaintext bootstrap DNS requests.
//
// Two-stage bootstrap:
//   - boot.<domain>                    → stage 1: tiny script that fetches stage 2
//   - boothelp.<domain>               → human-readable instructions
//   - <n>.s.boot.<domain>              → stage 2 script chunks
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
		script := h.stage1Script()
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
			},
			Txt: []string{script},
		})
		return true

	case len(parts) == 1 && parts[0] == "boothelp":
		help := h.bootstrapHelp()
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
			},
			Txt: splitTXT(help),
		})
		return true

	case len(parts) == 3 && parts[1] == "s" && parts[2] == "boot":
		return h.handleStage2Chunk(parts[0], q, msg)

	case len(parts) == 3 && parts[2] == "boot":
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
func (h *Handler) stage1Script() string {
	return fmt.Sprintf(
		`i=0;S=;while :;do C=$(dig +short TXT $i.s.boot.%s|xargs);case $C in ?*)S=${S}$C;i=$((i+1));;*)break;;esac;done;eval $S`,
		h.config.Domain,
	)
}

// stage2Script returns the full download script.
// No double quotes allowed - chunks go through xargs.
func (h *Handler) stage2Script() string {
	return fmt.Sprintf(`D=%s;O=$(uname -s|tr A-Z a-z);A=$(uname -m);case $A in x86_64)A=amd64;;aarch64)A=arm64;;esac;F=harry-$O-$A;SZ=$(dig +short TXT sz.$F.boot.$D|head -1|tr -dc 0-9);H=$(dig +short TXT sha1.$F.boot.$D|head -1|tr -dc 0-9a-f);echo downloading $F size=$SZ sha1=$H;N=$(dig +short TXT n.$F.boot.$D|head -1|tr -dc 0-9);echo $N chunks;i=0;B=;while [ $i -lt $N ];do C=$(dig +short TXT $i.$F.boot.$D|tr -dc A-Za-z0-9+/=);B=${B}$C;i=$((i+1));case $((i%%100)) in 0)echo $i/$N;;esac;done;echo;printf %%s $B|base64 -d|gunzip>harry;chmod +x harry;set -- $(sha1sum harry 2>/dev/null||shasum harry);G=$1;case $G in $H)echo verified sha1=$G;;*)echo HASH MISMATCH expected=$H got=$G;;esac;echo done`,
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
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
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
			Ttl:    h.config.TTL,
		},
		Txt: []string{chunks[idx]},
	})
	return true
}

func (h *Handler) handleBootstrapChunk(chunkID, filename string, q *dns.Question, msg *dns.Msg) bool {
	info, err := h.bootCache.ensureLoaded(h.files, filename)
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
				Ttl:    h.config.TTL,
			},
			Txt: []string{fmt.Sprintf("%d", info.totalChunks)},
		})
		return true
	}

	// Return file size
	if chunkID == "sz" {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
			},
			Txt: []string{fmt.Sprintf("%d", info.origSize)},
		})
		return true
	}

	// Return file SHA1
	if chunkID == "sha1" {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
			},
			Txt: []string{info.sha1Hex},
		})
		return true
	}

	var idx int
	if _, err := fmt.Sscanf(chunkID, "%d", &idx); err != nil {
		log.Printf("bootstrap: invalid chunk id %q", chunkID)
		msg.Rcode = dns.RcodeNameError
		return true
	}

	if idx < 0 || idx >= info.totalChunks {
		log.Printf("bootstrap: chunk %d out of range (0-%d)", idx, info.totalChunks-1)
		msg.Rcode = dns.RcodeNameError
		return true
	}

	chunk, err := h.bootCache.getChunk(filename, idx)
	if err != nil {
		log.Printf("bootstrap: error reading chunk %d: %v", idx, err)
		msg.Rcode = dns.RcodeServerFailure
		return true
	}

	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    h.config.TTL,
		},
		Txt: splitTXT(chunk),
	})
	return true
}
