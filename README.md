# Harry

DNS tunneling tool for sending and receiving data over DNS TXT record queries. Named after the Great Escape tunnels.

Harry is designed for scenarios where DNS is the only available network protocol. A server acts as an authoritative nameserver for a domain, and clients communicate by making DNS TXT queries.

## Architecture

- **Server (`harry-server`)**: Authoritative DNS server for a configured domain. Manages client sessions, serves files, handles uploads, and proxies HTTP requests.
- **Client (`harry`)**: Encodes data into DNS queries and decodes responses from TXT records.

### Protocol

Data is encoded into DNS query labels using base36 (DNS-safe, case-insensitive). Each query uses 4 labels with a total domain length of 253 characters. The client ID (0-63) is encoded in the lengths of the first 3 labels (60-63 chars each, 2 bits per label).

All tunnel payloads are encrypted with AES-256-GCM using a key derived from a shared password (PBKDF2).

On connect, the client auto-tunes the maximum TXT response size (255 → 512 → 1000 bytes).

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
- `bin/harry-darwin-arm64` — stripped client for macOS ARM
- `bin/harry-linux-amd64` — stripped client for Linux x86_64
- `bin/harry-linux-arm64` — stripped client for Linux ARM

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
| `-no-redirect` | `false` | Don't follow HTTP redirects |
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

The server must have the platform binaries in its files directory (`harry-darwin-arm64`, `harry-linux-amd64`, `harry-linux-arm64`). Run `make bootstrap` and copy them to the files directory.

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
- All tunnel payloads in both directions — file data, filenames, commands, responses
- Key derived from shared password via PBKDF2 (100,000 iterations, SHA-256)
- Each encrypted message is unique due to random nonce, making DNS response caching harmless

**Not encrypted (plaintext):**
- Bootstrap script and client binary chunks (served as base64/gzip over DNS)
- Bootstrap metadata queries (file size, SHA1, chunk count)
- SOA/NS responses

**Known limitations:**
- **Traffic analysis**: An observer can see DNS query frequency and sizes to `*.tunnel.example.com`, and can infer activity patterns (uploads vs downloads, approximate file sizes) even without reading payloads
- **Session exhaustion**: The server supports 64 concurrent sessions. There is no authentication on the initial connect — anyone who knows the domain can consume a session slot (though they cannot decrypt the response without the password)
- **Bootstrap exposure**: Client binaries are served in cleartext over DNS. An observer can see what software is being downloaded during bootstrap
- **No rate limiting**: Failed decryption attempts (wrong password) are not rate-limited. The server rejects them but does not track or block repeated failures
- **Shared secret**: All clients use the same password. There is no per-client authentication or key rotation
