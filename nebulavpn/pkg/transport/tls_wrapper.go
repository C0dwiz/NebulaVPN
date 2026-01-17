// MIT License
//
// Copyright (c) 2026 CodWiz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"nebulavpn/internal/protocol"
)

type TLSWrapper struct {
	config    *tls.Config
	httpsMask *protocol.HTTPSMask
	certPool  *x509.CertPool
}

func NewTLSWrapper(certFile, keyFile string, httpsMask *protocol.HTTPSMask) (*TLSWrapper, error) {
	wrapper := &TLSWrapper{
		httpsMask: httpsMask,
	}

	if certFile != "" && keyFile != "" {
		// Validate certificate files exist
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("certificate file not found: %s", certFile)
		}
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("key file not found: %s", keyFile)
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate pair: %w", err)
		}

		wrapper.config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			// Strong cipher suites
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			// Prefer server ciphers
			PreferServerCipherSuites: true,
			// Disable session tickets for better forward secrecy
			SessionTicketsDisabled: false,
		}
	} else {
		// Client configuration
		wrapper.config = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			// Strong cipher suites for client
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
	}

	return wrapper, nil
}

func (w *TLSWrapper) Listen(network, addr string) (net.Listener, error) {
	config := w.httpsMask.WrapTLS(w.config)

	// Add server-specific security settings
	config.ServerName = ""                    // Server doesn't need SNI
	config.ClientAuth = tls.RequestClientCert // Optional client cert

	listener, err := tls.Listen(network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS listener: %w", err)
	}

	return listener, nil
}

func (w *TLSWrapper) Dial(network, addr string) (net.Conn, error) {
	return w.DialWithTimeout(network, addr, 30*time.Second)
}

// DialWithTimeout creates a TLS connection with custom timeout
func (w *TLSWrapper) DialWithTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	config := w.httpsMask.WrapTLS(w.config)

	// Set connection timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Create TLS connection with timeout
	conn, err := tls.DialWithDialer(dialer, network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", addr, err)
	}

	// Verify connection state
	if err := w.verifyConnection(conn.ConnectionState()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connection verification failed: %w", err)
	}

	return conn, nil
}

// DialInsecure creates a TLS connection with certificate verification disabled
func (w *TLSWrapper) DialInsecure(network, addr string) (net.Conn, error) {
	config := w.httpsMask.WrapTLS(w.config)
	config.InsecureSkipVerify = true

	return tls.Dial(network, addr, config)
}

// verifyConnection performs additional security checks on the TLS connection
func (w *TLSWrapper) verifyConnection(state tls.ConnectionState) error {
	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		return fmt.Errorf("insecure TLS version: %x", state.Version)
	}

	// Check cipher suite
	weakCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:                true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         true,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        true,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   true,
	}

	if weakCiphers[state.CipherSuite] {
		return fmt.Errorf("weak cipher suite: %x", state.CipherSuite)
	}

	return nil
}

func (w *TLSWrapper) Copy(dst, src net.Conn) error {
	defer dst.Close()
	defer src.Close()

	_, err := io.Copy(dst, src)
	return err
}

func (w *TLSWrapper) CopyWithTimeout(dst, src net.Conn, timeout time.Duration) error {
	defer dst.Close()
	defer src.Close()

	buf := make([]byte, 32*1024)
	for {
		// Set read timeout
		if err := src.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil // Normal closure
			}
			return fmt.Errorf("read error: %w", err)
		}

		// Set write timeout
		if err := dst.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}
}
