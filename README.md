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
| `-ttl` | `1` | DNS record TTL |

## Client

### Configuration

Flags can be set on the command line or in `~/.harryrc`:

```
domain=tunnel.example.com
password=shared-secret
resolver=8.8.8.8:53
```

Command line flags override RC file values. Use `-rc /path/to/file` for a custom RC file location.

### Commands

```sh
# List available files on the server
harry list

# Download a file (output to stdout)
harry download myfile.txt

# Download a file to disk
harry -o myfile.txt download myfile.txt

# Upload a file
harry upload /path/to/local.txt

# Upload with a different remote name
harry upload /path/to/local.txt remote-name.txt

# Fetch a URL via the server (output to stdout)
harry fetch http://example.com

# Fetch a URL to a file
harry -o page.html fetch http://example.com

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
| `-resolver` | `8.8.8.8:53` | DNS resolver address |
| `-poll` | `30s` | Idle poll interval |
| `-o` | (stdout) | Output file for download/fetch |
| `-no-redirect` | `false` | Don't follow HTTP redirects |
| `-rc` | `~/.harryrc` | RC file path |

## Bootstrap

If you only have access to `dig`, you can bootstrap the full client over DNS:

```sh
# Step 1: Check the instructions
dig TXT boothelp.tunnel.example.com

# Step 2: Run the bootstrap (set R to your resolver if not 8.8.8.8)
dig +short TXT boot.tunnel.example.com @8.8.8.8 | xargs echo | sh
```

This will:
1. Detect your OS and architecture
2. Download the correct binary in chunks via DNS TXT queries
3. Decompress and save as `./harry`

The server must have the platform binaries in its files directory (`harry-darwin-arm64`, `harry-linux-amd64`, `harry-linux-arm64`). Run `make bootstrap` and copy them to the files directory.

## Throughput

Upstream (client → server) is limited by DNS query size — roughly 120 bytes per query depending on domain length. Downstream (server → client) is limited by TXT record size — up to ~600 bytes per response after auto-tune and encryption overhead.

File uploads will be slow. Downloads are faster but still constrained by DNS round-trip times.
