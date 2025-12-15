package protocol

import (
	"crypto/tls"
	"fmt"
	"math/rand"
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

	rand.Seed(time.Now().UnixNano())
	userAgent := h.userAgents[rand.Intn(len(h.userAgents))]

	request := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
			"Accept-Language: en-US,en;q=0.5\r\n"+
			"Accept-Encoding: gzip, deflate, br\r\n"+
			"Connection: keep-alive\r\n"+
			"Upgrade-Insecure-Requests: 1\r\n\r\n",
		h.domain,
		userAgent,
	)

	return []byte(request)
}

func (h *HTTPSMask) IsHTTPRequest(data []byte) bool {
	str := strings.ToUpper(string(data[:min(10, len(data))]))
	return strings.HasPrefix(str, "GET ") ||
		strings.HasPrefix(str, "POST ") ||
		strings.HasPrefix(str, "PUT ") ||
		strings.HasPrefix(str, "HEAD ") ||
		strings.HasPrefix(str, "OPTIONS ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *HTTPSMask) DialTLS(network, addr string, baseConfig *tls.Config) (net.Conn, error) {
	config := h.WrapTLS(baseConfig)

	conn, err := tls.Dial(network, addr, config)
	if err != nil {
		return nil, err
	}

	if fakeRequest := h.CreateFakeHTTPRequest(); fakeRequest != nil {
		conn.Write(fakeRequest)
	}

	return conn, nil
}
