# Harry

DNS tunneling tool for sending and receiving data over DNS TXT record queries. Named after the Great Escape tunnels.

Harry is designed for scenarios where DNS is the only available network protocol. A server acts as an authoritative nameserver for a domain, and clients communicate by making DNS TXT queries.

## Architecture

- **Server (`harry-server`)**: Authoritative DNS server for a configured domain. Manages client sessions, serves files, handles uploads, and proxies HTTP requests.
- **Client (`harry`)**: Encodes data into DNS queries and decodes responses from TXT records.

### Protocol

All tunnel traffic (both directions) is fully encrypted with AES-256-GCM. The key is derived from a shared password via PBKDF2. Data is gzip compressed before encryption when compression reduces size.

On connect, the client auto-tunes the maximum TXT response size (255 → 512 → 1000 bytes).

### Wire Format

**DNS Query (client → server):**
```
<block4>.<block3>.<block2>.<block1>.<domain>

Each block is base36-encoded. Channel ID (0-63) encoded in block 1-3 lengths.
Total query: 253 chars max.

Decoded payload (after base36 decode):
  encrypt( gzip( [cmd 1B] [counter 3B] [payload...] ) )

cmd:     command code (c=connect, p=poll, d=data, f=file, etc.)
counter: 24-bit request counter (cache-busting, dedup)
payload: command-specific data (plaintext before encrypt)
```

**DNS TXT Response (server → client):**
```
base36( [CRC32 4B] [transfer_id 2B] [chunk_idx 2B] [chunk_total 2B] [flags 1B] [encrypted_payload] )

CRC32:        IEEE CRC32 over everything after it (integrity check)
transfer_id:  identifies the logical transfer (file, list, etc.)
chunk_idx:    which chunk of the transfer (0-based)
chunk_total:  total chunks in the transfer
flags:        bit 0 = more data queued, bit 1 = error
payload:      encrypt( gzip( response_data ) )
```

**SOCKS5 Stream Data (multiplexed in payload):**
```
[stream_id 2B] [length 2B] [data...] [stream_id 2B] [length 2B] [data...] ...
```

## Building

```sh
# Build server and client
make all

# Cross-compile stripped client binaries for bootstrap
make bootstrap

# Run tests
make test
```

### Build targets

- `bin/harry-server` — the DNS server
- `bin/harry` — the client
- `make bootstrap` — cross-compile stripped clients (`bin/harry-darwin-arm64`, `bin/harry-linux-amd64`, `bin/harry-linux-arm64`)
- `make release` — cross-compile both client and server for all platforms

## Server

```sh
harry-server \
  -domain tunnel.example.com \
  -password "shared-secret" \
  -listen :53 \
  -files ./files \
  -uploads ./uploads \
  -ttl 1
```

The server must be configured as the authoritative nameserver for the specified domain. Any DNS query under that domain will be handled by the tunnel.

| Flag | Default | Description |
|------|---------|-------------|
| `-domain` | (required) | Base domain for the tunnel |
| `-password` | (required) | Shared secret for encryption |
| `-listen` | `:53` | Listen address (host:port) |
| `-files` | `./files` | Directory for downloadable files |
| `-uploads` | `./uploads` | Directory for uploaded files |
| `-cache` | (temp dir) | Bootstrap cache directory |
| `-rshell` | | TCP listen address for reverse shell (e.g., `127.0.0.1:4444`) |
| `-ttl` | `1` | DNS record TTL |
| `-verbose` | `false` | Log all queries and packet details |

## Client

### Configuration

Flags can be set on the command line or in `~/.harryrc`:

```
domain=tunnel.example.com
password=shared-secret
```

Command line flags override RC file values. Use `-rc /path/to/file` for a custom RC file location.

### Commands

```sh
# List available files on the server
harry list

# Receive a file from the server
harry recv myfile.txt

# Receive to a different local name
harry recv myfile.txt localname.txt

# Receive to stdout
harry recv myfile.txt -

# Send a file to the server
harry send /path/to/local.txt

# Send with a different remote name
harry send /path/to/local.txt remote-name.txt

# Send from stdin
echo "hello" | harry send - greeting.txt
cat data.bin | harry send - data.bin

# Force overwrite existing file
harry -f send /path/to/local.txt
harry -f recv myfile.txt

# Fetch a URL via the server (stdout)
harry fetch http://example.com

# Fetch without following redirects
harry -no-redirect fetch http://google.com

# SOCKS5 proxy (tunnel TCP traffic through DNS)
harry socks5
harry -socks-addr 0.0.0.0:8080 socks5
curl --socks5-hostname 127.0.0.1:1080 http://example.com

# Reverse shell (expose local shell to server)
# Server must be started with: harry-server -rshell 127.0.0.1:4444 ...
harry rshell
# Then on the server: nc localhost 4444

# Bidirectional pipe (stdin/stdout)
harry pipe

# Poll for data (testing)
harry poll
```

| Flag | Default | Description |
|------|---------|-------------|
| `-domain` | | Base domain |
| `-password` | | Shared secret |
| `-resolver` | (system) | DNS resolver address (reads `/etc/resolv.conf` by default) |
| `-poll` | `30s` | Idle poll interval |
| `-f` | `false` | Force overwrite existing file |
| `-v` | `false` | Verbose debug logging |
| `-no-redirect` | `false` | Don't follow HTTP redirects |
| `-socks-addr` | `127.0.0.1:1080` | SOCKS5 listen address |
| `-rc` | `~/.harryrc` | RC file path |

## Bootstrap

If you only have access to `dig`, you can bootstrap the full client over DNS:

```sh
# Step 1: Check the instructions
dig TXT boothelp.tunnel.example.com

# Step 2: Run the bootstrap (uses system resolver)
dig +short TXT boot.tunnel.example.com | xargs echo | sh
```

This will:
1. Detect your OS and architecture
2. Download the correct binary in chunks via DNS TXT queries
3. Decompress and save as `./harry`

The server must have the platform binaries in its files directory. Run `make bootstrap` and copy them:

```sh
cp bin/harry-darwin-arm64 bin/harry-linux-amd64 bin/harry-linux-arm64 files/
```

### Firefox SOCKS5 Setup

To use the SOCKS5 proxy with Firefox:

1. Open **Settings** → **General** → **Network Settings** → **Settings...**
2. Select **Manual proxy configuration**
3. **SOCKS Host**: `127.0.0.1`, **Port**: `1080`
4. Select **SOCKS v5**
5. Check **Proxy DNS when using SOCKS v5** (important — sends domain names through the tunnel)
6. Click **OK**

## DNS Setup

To use Harry, you need two DNS records at your domain registrar:

1. **A record** for the nameserver: `harry-ns.example.com → A → <server IP>`
2. **NS record** delegating the tunnel subdomain: `tunnel.example.com → NS → harry-ns.example.com`

Then run `harry-server` on that IP, listening on port 53.

## Throughput

Upstream (client → server) is limited by DNS query size — roughly 120 bytes per query depending on domain length. Downstream (server → client) is limited by TXT record size — up to ~600 bytes per response after auto-tune and encryption overhead.

File uploads will be slow. Downloads are faster but still constrained by DNS round-trip times.

## Reliability

Responses use a wire frame format with CRC32 integrity checks, transfer IDs, and chunk indexing:

```
[CRC32 4B] [transfer_id 2B] [chunk_idx 2B] [chunk_total 2B] [flags 1B] [encrypted...]
```

- **CRC32** detects DNS-level truncation or corruption
- **Indexed chunks** enable reliable multi-chunk transfers with implicit ACK/NAK
- **Deduplication** handles DNS resolver retries (which can replay requests)
- **SHA1 verification** on file uploads and downloads catches end-to-end corruption

## Security Considerations

**Encrypted (AES-256-GCM, unique random nonce per message):**
- All tunnel traffic in both directions is fully encrypted — command codes, counters, filenames, file data, responses
- Data is gzip compressed before encryption when compression reduces size
- Key derived from shared password via PBKDF2 (100,000 iterations, SHA-256)
- Each encrypted message is unique due to random nonce, making DNS response caching harmless
- An observer sees only the domain name and base36-encoded blobs — no metadata leaks

**Not encrypted (plaintext):**
- Bootstrap script and client binary chunks (served as base64/gzip over DNS)
- Bootstrap metadata queries (file size, SHA1, chunk count)
- SOA/NS responses

**Known limitations:**
- **Traffic analysis**: An observer can see DNS query frequency and sizes to `*.tunnel.example.com`, and can infer activity patterns (uploads vs downloads, approximate file sizes) even without reading payloads
- **Channel exhaustion**: The server supports 64 concurrent channels. There is no authentication on the initial connect — anyone who knows the domain can consume a channel slot (though they cannot decrypt the response without the password)
- **Bootstrap exposure**: Client binaries are served in cleartext over DNS. An observer can see what software is being downloaded during bootstrap
- **No rate limiting**: Failed decryption attempts (wrong password) are not rate-limited. The server rejects them but does not track or block repeated failures
- **Shared secret**: All clients use the same password. There is no per-client authentication or key rotation
