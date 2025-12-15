package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"vpn-proxy/internal/config"
	"vpn-proxy/internal/crypto"
	"vpn-proxy/internal/protocol"
	"vpn-proxy/pkg/transport"
	"vpn-proxy/pkg/tunnel"
)

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatal("Config validation failed:", err)
	}

	encryptor, err := crypto.NewEncryptor(cfg.Crypto.Method, cfg.Crypto.Password)
	if err != nil {
		log.Fatal("Failed to create encryptor:", err)
	}

	httpsMask := protocol.NewHTTPSMask(
		cfg.HTTPMask.Enabled,
		cfg.HTTPMask.Domain,
		cfg.HTTPMask.UserAgents,
	)

	tlsWrapper, err := transport.NewTLSWrapper("", "", httpsMask)
	if err != nil {
		log.Fatal("Failed to create TLS wrapper:", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Client.LocalPort))
	if err != nil {
		log.Fatal("Failed to start local proxy:", err)
	}
	defer listener.Close()

	log.Printf("Client started on port %d", cfg.Client.LocalPort)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go handleClientConnection(clientConn, cfg, encryptor, tlsWrapper)
	}
}

func handleClientConnection(clientConn net.Conn, cfg *config.Config,
	encryptor crypto.Encryptor, tlsWrapper *transport.TLSWrapper) {
	defer clientConn.Close()

	serverConn, err := tlsWrapper.Dial("tcp", cfg.Client.ServerAddress)
	if err != nil {
		log.Println("Failed to connect to server:", err)
		return
	}
	defer serverConn.Close()

	log.Println("Connected to server")

	tun := tunnel.NewTunnel(encryptor)

	buf := make([]byte, 256)
	if _, err := clientConn.Read(buf); err != nil {
		log.Println("Failed to read SOCKS5 request:", err)
		return
	}

	clientConn.Write([]byte{0x05, 0x00})

	n, err := clientConn.Read(buf)
	if err != nil {
		log.Println("Failed to read connect request:", err)
		return
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
	case 0x03: // Domain name
		host = string(buf[5 : 5+int(buf[4])])
	case 0x04: // IPv6
		host = net.IP(buf[4:20]).String()
	default:
		log.Println("Unsupported address type")
		return
	}

	port := binary.BigEndian.Uint16(buf[n-2:])
	targetAddr := fmt.Sprintf("%s:%d", host, port)

	log.Printf("Connecting to %s", targetAddr)

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	go func() {
		if err := tun.Pipe(clientConn, serverConn, targetAddr); err != nil {
			log.Println("Client to server error:", err)
		}
	}()

	for {
		data, addr, err := tun.ReadPacket(serverConn)
		if err != nil {
			log.Println("Failed to read packet from server:", err)
			break
		}

		if addr != targetAddr {
			log.Println("Address mismatch")
			continue
		}

		if _, err := clientConn.Write(data); err != nil {
			log.Println("Failed to write to client:", err)
			break
		}
	}
}
