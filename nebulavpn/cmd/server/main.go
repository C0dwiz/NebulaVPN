package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	tlsWrapper, err := transport.NewTLSWrapper(
		cfg.Server.TLS.CertPath,
		cfg.Server.TLS.KeyPath,
		httpsMask,
	)
	if err != nil {
		log.Fatal("Failed to create TLS wrapper:", err)
	}

	listener, err := tlsWrapper.Listen("tcp",
		fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port))
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
	defer listener.Close()

	log.Printf("Server started on %s:%d", cfg.Server.Host, cfg.Server.Port)

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

		go handleServerConnection(clientConn, encryptor)
	}
}

func handleServerConnection(clientConn net.Conn, encryptor crypto.Encryptor) {
	defer clientConn.Close()

	tun := tunnel.NewTunnel(encryptor)

	for {
		data, targetAddr, err := tun.ReadPacket(clientConn)
		if err != nil {
			log.Println("Failed to read packet:", err)
			return
		}

		go forwardToTarget(data, targetAddr, clientConn, tun)
	}
}

func forwardToTarget(data []byte, targetAddr string,
	clientConn net.Conn, tun *tunnel.Tunnel) {

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	if _, err := targetConn.Write(data); err != nil {
		log.Printf("Failed to write to %s: %v", targetAddr, err)
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := targetConn.Read(buf)
		if err != nil {
			break
		}

		if err := tun.WritePacket(clientConn, buf[:n], targetAddr); err != nil {
			log.Printf("Failed to send packet to client: %v", err)
			break
		}
	}
}
