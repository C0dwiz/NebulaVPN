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
	mask := NewHTTPSMask(true, "example.com", []string{"UA-1"})
	req := mask.CreateFakeHTTPRequest()
	if len(req) == 0 {
		t.Fatalf("expected request bytes")
	}
	body := string(req)
	if !strings.Contains(body, "Host: example.com") || !strings.Contains(body, "User-Agent: UA-1") {
		t.Fatalf("request missing fields: %s", body)
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
	if !mask.IsHTTPRequest([]byte("GET / HTTP/1.1")) {
		t.Fatalf("expected GET to be HTTP request")
	}
	if mask.IsHTTPRequest([]byte("SSH-2.0")) {
		t.Fatalf("did not expect SSH to be HTTP request")
	}
}
