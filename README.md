# NebulaVPN

[Russian version](README_RU.md)

> [!WARNING] 
> ⚠️ IMPORTANT WARNING \
> This project is currently under active development and testing. \
> This software is for TESTING AND EDUCATIONAL PURPOSES ONLY. \
> Do not use in production environments or for any critical operations.


Experimental VPN playground focused on tunneling, encryption, and TLS/HTTPS masking. This codebase is **not production-ready**; use it only for learning and testing.

## Features (current)
- SOCKS5-style client/server pipeline with encrypted tunnel.
- Pluggable encryptors: `aes-256-gcm`, `chacha20-poly1305`.
- TLS wrapper with optional HTTPS masking (fake HTTP handshake).

## Quick start (test only)
1) Install Go 1.20+.
2) `cd nebulavpn`
3) Run tests: `go test ./...`
4) Copy `config.yaml.example` to `config.yaml` and adjust values for local testing.

## Project status
- Work in progress; APIs and behavior can change without notice.
- Intended only for experimentation and internal testing, not for protecting real traffic.

## Contributing
Issues and PRs are welcome. Please keep in mind the experimental nature of the project when proposing changes.

## License
MIT (see `LICENSE`).