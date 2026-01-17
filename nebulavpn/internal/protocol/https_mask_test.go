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
	"crypto/tls"
	"strings"
	"testing"
)

func TestWrapTLSAddsProtosAndServerName(t *testing.T) {
	mask := NewHTTPSMask(true, "example.com", nil)
	cfg := mask.WrapTLS(&tls.Config{})

	if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos not set")
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName = %s, want example.com", cfg.ServerName)
	}
}

func TestWrapTLSDisabledReturnsOriginal(t *testing.T) {
	orig := &tls.Config{ServerName: "keep.me"}
	mask := NewHTTPSMask(false, "ignored", nil)

	got := mask.WrapTLS(orig)
	if got.ServerName != "keep.me" {
		t.Fatalf("unexpected ServerName change: %s", got.ServerName)
	}
}

func TestCreateFakeHTTPRequest(t *testing.T) {
	mask := NewHTTPSMask(true, "example.com", []string{"UA-1", "UA-2"})
	req := mask.CreateFakeHTTPRequest()
	if len(req) == 0 {
		t.Fatalf("expected request bytes")
	}
	body := string(req)
	if !strings.Contains(body, "Host: example.com") || !strings.Contains(body, "User-Agent: ") {
		t.Fatalf("request missing fields: %s", body)
	}

	// Test that it contains valid HTTP methods
	validMethods := []string{"GET ", "HEAD ", "OPTIONS "}
	hasValidMethod := false
	for _, method := range validMethods {
		if strings.Contains(body, method) {
			hasValidMethod = true
			break
		}
	}
	if !hasValidMethod {
		t.Fatalf("request doesn't contain valid HTTP method: %s", body)
	}
}

func TestCreateFakeHTTPRequestDisabled(t *testing.T) {
	mask := NewHTTPSMask(false, "example.com", []string{"UA"})
	if mask.CreateFakeHTTPRequest() != nil {
		t.Fatalf("expected nil when disabled")
	}
	mask = NewHTTPSMask(true, "example.com", nil)
	if mask.CreateFakeHTTPRequest() != nil {
		t.Fatalf("expected nil when no user agents")
	}
}

func TestIsHTTPRequest(t *testing.T) {
	mask := NewHTTPSMask(true, "", nil)

	// Test valid HTTP methods
	validRequests := [][]byte{
		[]byte("GET / HTTP/1.1"),
		[]byte("POST /api HTTP/1.1"),
		[]byte("PUT /data HTTP/1.1"),
		[]byte("HEAD / HTTP/1.1"),
		[]byte("OPTIONS / HTTP/1.1"),
		[]byte("DELETE /resource HTTP/1.1"),
		[]byte("PATCH /resource HTTP/1.1"),
	}

	for _, req := range validRequests {
		if !mask.IsHTTPRequest(req) {
			t.Fatalf("expected %s to be HTTP request", string(req))
		}
	}

	// Test invalid requests
	invalidRequests := [][]byte{
		[]byte("SSH-2.0"),
		[]byte("FTP command"),
		[]byte(""),
		[]byte("NOTHTTP /data"),
		[]byte("random data"),
	}

	for _, req := range invalidRequests {
		if mask.IsHTTPRequest(req) {
			t.Fatalf("did not expect %s to be HTTP request", string(req))
		}
	}
}

func TestHTTPSMaskRequestVariation(t *testing.T) {
	mask := NewHTTPSMask(true, "example.com", []string{"UA-1", "UA-2", "UA-3"})

	// Generate multiple requests to test randomness
	requests := make(map[string]int)
	for i := 0; i < 100; i++ {
		req := mask.CreateFakeHTTPRequest()
		body := string(req)

		// Extract user agent
		start := strings.Index(body, "User-Agent: ")
		if start == -1 {
			t.Fatalf("no User-Agent found in request %d", i)
		}
		start += len("User-Agent: ")
		end := strings.Index(body[start:], "\r\n")
		if end == -1 {
			t.Fatalf("no end of User-Agent found in request %d", i)
		}
		userAgent := body[start : start+end]
		requests[userAgent]++
	}

	// Should have multiple different user agents (due to randomness)
	if len(requests) < 2 {
		t.Fatalf("expected multiple user agents, got %d", len(requests))
	}
}

func TestHTTPSMaskPathVariation(t *testing.T) {
	mask := NewHTTPSMask(true, "example.com", []string{"UA-1"})

	// Generate multiple requests to test path randomness
	paths := make(map[string]int)
	for i := 0; i < 50; i++ {
		req := mask.CreateFakeHTTPRequest()
		body := string(req)

		// Extract path (first line after method)
		lines := strings.Split(body, "\r\n")
		if len(lines) == 0 {
			t.Fatalf("no lines found in request %d", i)
		}
		firstLine := lines[0]
		parts := strings.Fields(firstLine)
		if len(parts) < 2 {
			t.Fatalf("invalid first line: %s", firstLine)
		}
		path := parts[1]
		paths[path]++
	}

	// Should have multiple different paths
	if len(paths) < 2 {
		t.Fatalf("expected multiple paths, got %d", len(paths))
	}
}
