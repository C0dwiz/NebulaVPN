# NebulaVPN

[Russian version](README_RU.md)

> [!WARNING] 
> ⚠️ IMPORTANT WARNING \
> This project is currently under active development and testing. \
> This software is for TESTING AND EDUCATIONAL PURPOSES ONLY. \
> Do not use in production environments or for any critical operations.

Experimental VPN playground focused on tunneling, encryption, and TLS/HTTPS masking. This codebase is **not production-ready**; use it only for learning and testing.

## How It Works

NebulaVPN implements a secure proxy tunnel with the following architecture:

### Core Components

1. **SOCKS5 Client** - Local proxy that accepts connections from applications
2. **Encryption Layer** - Encrypts all traffic using strong ciphers (AES-256-GCM or ChaCha20-Poly1305)
3. **TLS Transport** - Wraps encrypted traffic in TLS with optional HTTPS masking
4. **VPN Server** - Receives encrypted traffic, decrypts it, and forwards to target destinations

### Protocol Flow

```
Application → SOCKS5 Client → Encryption → TLS/HTTPS Mask → VPN Server → Decryption → Target Internet
```

### Detailed Process

1. **Client Setup**
   - Starts local SOCKS5 proxy on configured port (default: 1080)
   - Connects to VPN server using TLS with certificate verification
   - Optional HTTPS masking disguises traffic as legitimate HTTPS requests

2. **Connection Handling**
   - Application connects to local SOCKS5 proxy
   - Client validates SOCKS5 protocol and extracts target address
   - Target address is encrypted with PBKDF2-derived keys and random salts

3. **Traffic Encryption**
   - Each packet gets unique 32-byte salt for forward secrecy
   - Uses 100,000 PBKDF2 iterations for key derivation
   - Supports AES-256-GCM and ChaCha20-Poly1305 ciphers
   - 12-byte nonces ensure cryptographic security

4. **TLS Transport Layer**
   - Enforces TLS 1.2+ with strong cipher suites only
   - Optional HTTP masking sends fake HTTP requests to disguise traffic
   - Randomized User-Agents and HTTP methods for better obfuscation

5. **Server Processing**
   - Validates client certificates and optional IP whitelists
   - Decrypts packets using extracted salts and derived keys
   - Forwards traffic to actual destinations with timeout protection
   - Implements connection limits and rate limiting

### Security Features

- **Strong Encryption**: PBKDF2 key derivation with per-packet random salts
- **Perfect Forward Secrecy**: Compromise of one packet doesn't affect others
- **TLS Protection**: All inter-server communication encrypted with modern TLS
- **Traffic Obfuscation**: Optional HTTPS masking to bypass deep packet inspection
- **Access Control**: Server-side IP whitelisting and connection limits
- **Input Validation**: Comprehensive validation of all addresses and protocols

### Performance Optimizations

- **Buffer Pooling**: Reuses buffers to reduce garbage collection overhead
- **Concurrent Handling**: Efficient goroutine management with context cancellation
- **Timeout Management**: Configurable timeouts prevent resource exhaustion
- **Memory Efficiency**: Optimized packet structures and copying strategies

## Features (current)

- SOCKS5-style client/server pipeline with encrypted tunnel
- Pluggable encryptors: `aes-256-gcm`, `chacha20-poly1305`
- TLS wrapper with optional HTTPS masking (fake HTTP handshake)
- Connection limits and IP filtering on server side
- Comprehensive configuration with security defaults
- Structured logging and monitoring capabilities

## Quick start (test only)

1. Install Go 1.20+.
2. `cd nebulavpn`
3. Run tests: `go test ./...`
4. Copy `config.yaml.example` to `config.yaml` and adjust values for local testing.

### Example Usage

**Start Server:**
```bash
./server -config config.yaml
```

**Start Client:**
```bash
./client -config config.yaml
```

**Configure Application:**
Set your application to use SOCKS5 proxy at `127.0.0.1:1080`

## Configuration Options

### Server Security Settings
```yaml
server:
  max_connections: 1000        # Maximum concurrent connections
  timeout_seconds: 30         # Connection timeout
  allowed_ips:               # Optional IP whitelist
    - "192.168.1.100"
```

### Client Security Settings
```yaml
client:
  timeout_seconds: 10         # Connection timeout
  retry_attempts: 3           # Connection retry attempts
  tls_skip_verify: false      # Certificate verification
```

### Encryption Settings
```yaml
crypto:
  method: "chacha20-poly1305"  # or "aes-256-gcm"
  password: "strong-password"     # Minimum 8 characters
```

### Traffic Masking
```yaml
http_mask:
  enabled: true
  domain: "cloudflare.com"    # Disguise as legitimate HTTPS
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
```

## Project status

- Work in progress; APIs and behavior can change without notice.
- Intended only for experimentation and internal testing, not for protecting real traffic.
- Comprehensive test coverage with security validation
- Performance optimizations for high-throughput scenarios

## Contributing

Issues and PRs are welcome. Please keep in mind the experimental nature of the project when proposing changes.

### Development Guidelines

- Follow Go best practices and security coding standards
- Add comprehensive tests for new features
- Update documentation for protocol changes
- Ensure backward compatibility when possible

## Security Considerations

This is an experimental project for educational purposes. When using or modifying:

1. **Never use in production** - This code is not security-audited
2. **Understand the protocol** - Each component should be studied separately
3. **Test thoroughly** - Use the provided test suite and add more tests
4. **Monitor connections** - Log and monitor all connections in testing
5. **Keep keys secure** - Use strong, unique passwords for testing

## Architecture Diagram

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │    │  SOCKS5 Client  │    │  VPN Server   │
│               │────│                │────│                │
│ 127.0.0.1:1080│    │  Encryption      │    │  :443 (TLS)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                │
                       ┌─────────────────┐
                       │ Target Internet │
                       │                │
                       └─────────────────┘
```

## License

MIT (see `LICENSE`).