# Harry Architecture

## Overview

Harry is a DNS tunneling tool that enables bidirectional data transfer using only DNS TXT record queries. It's designed for environments where DNS is the only available network protocol. Named after the tunnels in The Great Escape.

## Components

```
┌─────────────┐     DNS TXT queries      ┌──────────────┐
│   Client     │ ──────────────────────── │   Server     │
│   (harry)    │ ◄─────────────────────── │ (harry-server)│
│              │     DNS TXT responses    │              │
│  - send/recv │                          │  - File store│
│  - socks5    │                          │  - Uploads   │
│  - rshell    │                          │  - HTTP fetch│
│  - fetch     │                          │  - TCP proxy │
└─────────────┘                          └──────────────┘
```

### Server (`cmd/server`, `pkg/server`)

An authoritative DNS nameserver for a configured domain. Processes DNS TXT queries as tunnel protocol messages. Manages client sessions, file storage, uploads, HTTP proxying, SOCKS5 stream bridging, and reverse shell TCP bridging.

### Client (`cmd/harry`, `pkg/client`)

Encodes commands and data into DNS TXT queries. Decodes server responses from TXT records. Supports file transfer, URL fetching, SOCKS5 proxying, and reverse shell.

## DNS Encoding

### Query Format (Client → Server)

```
<block4>.<block3>.<block2>.<block1>.<domain>

Example: 7a3bc9f0e2...54.x8k2m1...60.j4n7p2...62.q9r5t1...61.t.rtun.dev
```

- Total query length: exactly 253 characters (padded with leading zeros)
- 4 data blocks, base36-encoded (characters: 0-9, a-z)
- **Client ID** (0-63) encoded in the lengths of blocks 1-3:
  - Each block varies between 60-63 characters = 2 bits
  - 3 blocks × 2 bits = 6 bits = 64 possible client IDs
- Block 4 gets the remaining space after subtracting the domain and other blocks
- Base36 is DNS-safe (case-insensitive, no special characters)

### Response Format (Server → Client)

```
DNS TXT record containing base36-encoded frame data.
Split into 255-character TXT strings if needed.
```

## Encryption & Compression

All tunnel traffic is fully encrypted. Nothing is transmitted in plaintext except bootstrap data.

### Pipeline

```
Client sending:
  plaintext packet → gzip compress → AES-256-GCM encrypt → base36 encode → DNS labels

Server receiving:
  DNS labels → base36 decode → AES-256-GCM decrypt → gzip decompress → plaintext packet

Server sending:
  plaintext payload → gzip compress → AES-256-GCM encrypt → frame with CRC → base36 → TXT

Client receiving:
  TXT → base36 → verify CRC → AES-256-GCM decrypt → gzip decompress → plaintext payload
```

### Key Derivation

- Algorithm: PBKDF2 with SHA-256
- Iterations: 100,000
- Key length: 32 bytes (AES-256)
- Salt: SHA-256("harry-salt:" + password), first 16 bytes
- Both client and server derive the same key independently from the shared password

### AES-GCM

- 12-byte random nonce per message (prepended to ciphertext)
- 16-byte authentication tag (appended)
- Total overhead: 28 bytes per encrypted message
- Authentication tag prevents tampering — wrong password = immediate rejection

### Gzip Compression

- Applied before encryption
- Adaptive: only used when compressed size < original size
- Detected on decompression by checking gzip magic bytes (0x1f 0x8b)
- Significant benefit for text-heavy data (HTML, shell output, file listings)

## Packet Format

### Upstream Packet (inside encryption envelope)

```
[cmd 1B] [counter 3B big-endian] [payload...]

cmd:     Command code (single ASCII byte)
counter: 24-bit monotonically increasing counter
         - Cache-busting (changes encoded output every request)
         - Deduplication (server tracks seen counters)
payload: Command-specific data
```

### Command Codes

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| `c` | Connect | (none) | Initial connection, server assigns client ID |
| `p` | Poll | [transfer_id 2B][last_ack 2B] or empty | Request next chunk / check for data |
| `d` | Data | raw data (or [stream_id 2B][len 2B][data] for SOCKS5) | Upstream data transfer |
| `f` | File | filename | Request file download |
| `l` | List | (none) | List available files |
| `h` | Fetch | [flags 1B][url] | Fetch URL via server |
| `u` | Upload | [flags 1B][filename] | Start file upload |
| `U` | UploadDone | [size 4B][sha1 20B] | Complete upload with verification |
| `t` | Tune | [size 2B] | Auto-tune response size |
| `r` | RShell | (none) | Start reverse shell |
| `s` | Socks5 | (none) | Enable SOCKS5 proxy mode |
| `o` | StreamOpen | [stream_id 2B][addr_type 1B][addr][port 2B] | Open SOCKS5 stream |
| `x` | StreamClose | [stream_id 2B] | Close SOCKS5 stream |

### Downstream Frame

```
[CRC32 4B] [transfer_id 2B] [chunk_idx 2B] [chunk_total 2B] [flags 1B] [encrypted_payload]

CRC32:       IEEE CRC32 over everything after it
transfer_id: Identifies the logical transfer (0 for non-transfer responses)
chunk_idx:   Which chunk of the transfer (0-based)
chunk_total: Total chunks (0 for streaming/non-transfer)
flags:       bit 0 = FlagMoreData (server has more queued)
             bit 1 = FlagError
payload:     encrypt(gzip(response_data))
```

## Transfer Protocol

Large data (file downloads, URL fetches, file listings) uses a reliable chunked transfer protocol.

### Flow

```
Client: CmdFile("test.txt")
Server: Creates Transfer{ID=1, chunks=[chunk0, chunk1, ..., chunkN]}
        Returns Frame{TransferID=1, ChunkIdx=0, ChunkTotal=N+1, Payload=chunk0}

Client: CmdPoll(transfer_id=1, last_ack=0)  ← "I got chunk 0, send chunk 1"
Server: Returns Frame{TransferID=1, ChunkIdx=1, ...}

Client: CmdPoll(transfer_id=1, last_ack=1)  ← "I got chunk 1, send chunk 2"
...

Client: CmdPoll(transfer_id=1, last_ack=N)  ← "I got the last chunk"
Server: Transfer complete, cleanup
```

### Implicit ACK/NAK

- Requesting chunk N+1 implicitly ACKs chunk N
- If a response is lost (DNS timeout), the client re-sends the same poll (same last_ack), and the server resends the same chunk
- Server retains all chunks until transfer completes — any chunk can be retransmitted
- No explicit NAK needed

### Deduplication

DNS resolvers may retry requests, causing duplicate processing on the server. Each session tracks a set of seen request counters. If a counter is seen twice, the duplicate is silently dropped (returns empty ACK).

## Session Management

- 64 concurrent sessions max (client IDs 1-63, 0 reserved)
- Client ID encoded in DNS label lengths (no overhead in payload)
- Sessions track:
  - TuneSize (negotiated response capacity)
  - Active transfers (indexed chunk storage)
  - Upload state (filename, byte count)
  - Reverse shell bridge (TCP listener + connection)
  - SOCKS5 bridge (multiplexed stream connections)
  - Seen counters (deduplication map, auto-pruned at 2000 entries)

## Auto-Tune

On connect, the client negotiates the maximum TXT response size:

1. Client sends CmdTune(255) → server responds with 255-byte test payload
2. If received OK, client sends CmdTune(512) → server responds with 512-byte test
3. If received OK, client sends CmdTune(1000) → server responds with 1000-byte test
4. Client uses the largest confirmed size

This adapts to different DNS resolver limits without hardcoding.

## File Transfer

### Download (recv)

1. Client sends CmdFile with filename
2. Server reads file, prepends 20-byte SHA1 hash, splits into chunks
3. Client receives chunks via transfer protocol
4. Client strips SHA1 prefix, computes local hash, verifies match

### Upload (send)

1. Client sends CmdUpload with [flags][filename]
2. Server creates file, returns OK
3. Client sends data in CmdData chunks (each encrypted at transport layer)
4. Client sends CmdUploadDone with [size 4B][sha1 20B]
5. Server reads uploaded file, computes SHA1, verifies match
6. Upload from stdin: size/hash computed on-the-fly, sent in done packet

### Overwrite Protection

- Server rejects uploads if file exists (unless client sends force flag)
- Client rejects downloads if local file exists (unless -f flag)

## SOCKS5 Proxy

### Architecture

```
Browser → SOCKS5 (client:1080) → DNS tunnel → Server → target:port
```

### Stream Multiplexing

Each SOCKS5 connection gets a stream ID (uint16). Data is prefixed with `[stream_id 2B][length 2B]` for proper demuxing.

### Flow

1. Client listens on local SOCKS5 port (default 127.0.0.1:1080)
2. Browser connects, sends SOCKS5 CONNECT request
3. Client handles SOCKS5 handshake locally (no-auth, CONNECT only)
4. Client sends CmdStreamOpen with target address to server
5. Server dials target, creates bidirectional TCP bridge
6. Data flows: browser ↔ client ↔ DNS ↔ server ↔ target
7. On disconnect, CmdStreamClose tears down the stream

### Supported Address Types

- 0x01: IPv4 (4 bytes)
- 0x03: Domain name (1-byte length + name)
- 0x04: IPv6 (16 bytes)

## Reverse Shell

### Architecture

```
Server user (nc localhost:4444) → TCP → Server → DNS → Client → /bin/sh
```

### Flow

1. Server starts with `-rshell 127.0.0.1:4444`
2. Client runs `harry rshell`
3. Client spawns local shell ($SHELL or /bin/sh, login interactive mode)
4. Client sends CmdRShell to server
5. Server opens TCP listener on configured address
6. Someone on the server runs `nc localhost 4444`
7. Keystrokes: TCP → server buffer → DNS response → client → shell stdin
8. Shell output: stdout → client → DNS query → server → TCP

### Adaptive Polling

- Polls every 50ms when data is flowing (last 10 polls had activity)
- Backs off to configured poll interval when idle
- Ctrl-C on client kills the local shell and exits

## Bootstrap

For environments where only `dig` is available, Harry can bootstrap itself over DNS.

### Two-Stage Process

**Stage 1** (single TXT record, <255 chars):
```
dig +short TXT boot.<domain> | xargs echo | sh
```
Returns a tiny shell script that fetches and evals stage 2.

**Stage 2** (multiple TXT chunks):
- Detects OS/arch (uname)
- Fetches correct binary (harry-darwin-arm64, harry-linux-amd64, harry-linux-arm64)
- Downloads in ~3500 chunks of 759 base64 chars each
- Decompresses (gzip) and verifies SHA1
- Shows progress every 100 chunks

### Cache Busting

All bootstrap DNS queries include a random prefix (shell PID) to prevent DNS resolver caching:
```
$$.$i.s.boot.<domain>     (stage 2 chunks)
$P$i.$i.<file>.boot.<domain>  (file data chunks)
```

### Bootstrap Queries

| Query | Response |
|-------|----------|
| `boot.<domain>` | Stage 1 loader script |
| `boothelp.<domain>` | Human-readable instructions |
| `<n>.s.boot.<domain>` | Stage 2 script chunk |
| `n.<file>.boot.<domain>` | Number of chunks for file |
| `sz.<file>.boot.<domain>` | File size |
| `sha1.<file>.boot.<domain>` | File SHA1 hash |
| `<idx>.<file>.boot.<domain>` | File data chunk |

### Disk-Backed Cache

Bootstrap files are compressed, base64-encoded, and split into chunks written to disk (temp dir or `-cache` flag). Only one chunk is read per request — no memory pressure from large binaries.

## DNS Server Behavior

The server acts as an authoritative nameserver:

| Query Type | Response |
|------------|----------|
| SOA | Valid SOA record (resolvers need this) |
| NS | Valid NS record |
| TXT (under domain) | Tunnel protocol / bootstrap |
| Other (A, AAAA, MX...) | NXDOMAIN |
| Outside domain | No response (silent drop) |

## Capacity

### Upstream (client → server)

- DNS query: 253 chars total
- After domain, dots, base36 overhead: ~150 base36 chars for data
- After base36 decode: ~96 raw bytes
- After encryption overhead (28B): ~68 bytes plaintext per query
- With gzip: potentially more for compressible data

### Downstream (server → client)

- TXT record: up to 1000 chars (after auto-tune)
- After frame overhead (CRC 4B + header 7B): ~989 chars for payload
- After base36 decode: ~639 raw bytes
- After encryption overhead (28B): ~611 bytes plaintext per response
- With gzip: potentially more for compressible data

### Throughput

Throughput is limited by DNS round-trip time, not bandwidth:
- Each query/response pair transfers ~68B up + ~611B down
- At ~50ms RTT: ~1.2 KB/s down, ~1.3 KB/s up (theoretical max)
- Real-world with resolver latency: typically 0.5-2 KB/s
