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

package protocol

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type HTTPSMask struct {
	enabled    bool
	domain     string
	userAgents []string
}

func NewHTTPSMask(enabled bool, domain string, userAgents []string) *HTTPSMask {
	return &HTTPSMask{
		enabled:    enabled,
		domain:     domain,
		userAgents: userAgents,
	}
}

func (h *HTTPSMask) WrapTLS(config *tls.Config) *tls.Config {
	if !h.enabled {
		return config
	}

	if config == nil {
		config = &tls.Config{}
	}

	config.NextProtos = []string{"http/1.1", "h2"}

	if h.domain != "" && config.ServerName == "" {
		config.ServerName = h.domain
	}

	return config
}

func (h *HTTPSMask) CreateFakeHTTPRequest() []byte {
	if !h.enabled || len(h.userAgents) == 0 {
		return nil
	}

	// Use crypto/rand for better randomness
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(h.userAgents))))
	if err != nil {
		// Fallback to simple selection if crypto/rand fails
		n = big.NewInt(0)
	}
	userAgent := h.userAgents[n.Int64()]

	// Randomize HTTP headers for better masking
	methods := []string{"GET", "HEAD", "OPTIONS"}
	m, _ := rand.Int(rand.Reader, big.NewInt(int64(len(methods))))
	method := methods[m.Int64()]

	paths := []string{"/", "/index.html", "/api/v1/status", "/health"}
	p, _ := rand.Int(rand.Reader, big.NewInt(int64(len(paths))))
	path := paths[p.Int64()]

	request := fmt.Sprintf(
		"%s %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
			"Accept-Language: en-US,en;q=0.5\r\n"+
			"Accept-Encoding: gzip, deflate, br\r\n"+
			"Connection: keep-alive\r\n"+
			"Upgrade-Insecure-Requests: 1\r\n"+
			"Cache-Control: max-age=0\r\n"+
			"\r\n",
		method,
		path,
		h.domain,
		userAgent,
	)

	return []byte(request)
}

func (h *HTTPSMask) IsHTTPRequest(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for HTTP methods in a more robust way
	str := strings.ToUpper(string(data[:min(8, len(data))]))
	httpMethods := []string{"GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH "}

	for _, method := range httpMethods {
		if strings.HasPrefix(str, method) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *HTTPSMask) DialTLS(network, addr string, baseConfig *tls.Config) (net.Conn, error) {
	config := h.WrapTLS(baseConfig)

	// Add connection timeout
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TLS connection to %s: %w", addr, err)
	}

	// Send fake HTTP request if masking is enabled
	if fakeRequest := h.CreateFakeHTTPRequest(); fakeRequest != nil {
		if _, err := conn.Write(fakeRequest); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send fake HTTP request: %w", err)
		}
		// Read and discard the response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		conn.Read(buf)                    // Ignore response
		conn.SetReadDeadline(time.Time{}) // Clear deadline
	}

	return conn, nil
}
