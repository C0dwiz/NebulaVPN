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
	"io"
	"net"
	"testing"
	"time"
)

func TestCopy(t *testing.T) {
	w := &TLSWrapper{}
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	done := make(chan struct{})
	go func() {
		err := w.Copy(dst, src)
		if err != nil {
			t.Errorf("Copy error: %v", err)
		}
		close(done)
	}()

	message := []byte("hello")
	if _, err := src.Write(message); err != nil {
		t.Fatalf("write error: %v", err)
	}
	src.Close()

	buf := make([]byte, len(message))
	if _, err := io.ReadFull(dst, buf); err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(buf) != string(message) {
		t.Fatalf("got %q, want %q", buf, message)
	}
	<-done
}

func TestCopyWithTimeout(t *testing.T) {
	w := &TLSWrapper{}
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	done := make(chan struct{})
	go func() {
		err := w.CopyWithTimeout(dst, src, 100*time.Millisecond)
		if err != nil {
			t.Errorf("CopyWithTimeout error: %v", err)
		}
		close(done)
	}()

	message := []byte("ping")
	if _, err := src.Write(message); err != nil {
		t.Fatalf("write error: %v", err)
	}
	src.Close()

	buf := make([]byte, len(message))
	if _, err := io.ReadFull(dst, buf); err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(buf) != string(message) {
		t.Fatalf("got %q, want %q", buf, message)
	}
	<-done
}

func TestNewTLSWrapperWithInvalidFiles(t *testing.T) {
	// Test with non-existent certificate files
	_, err := NewTLSWrapper("nonexistent.crt", "nonexistent.key", nil)
	if err == nil {
		t.Fatalf("expected error for non-existent certificate files")
	}
}

func TestNewTLSWrapperWithoutCerts(t *testing.T) {
	// Test without certificate files (client mode)
	wrapper, err := NewTLSWrapper("", "", nil)
	if err != nil {
		t.Fatalf("unexpected error for client mode: %v", err)
	}
	if wrapper == nil {
		t.Fatalf("expected non-nil wrapper")
	}
}

func TestDialWithTimeout(t *testing.T) {
	wrapper, err := NewTLSWrapper("", "", nil)
	if err != nil {
		t.Fatalf("NewTLSWrapper error: %v", err)
	}

	// Test with invalid address (should timeout)
	_, err = wrapper.DialWithTimeout("tcp", "127.0.0.1:9999", 10*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error for invalid address")
	}
}

func TestDialInsecure(t *testing.T) {
	wrapper, err := NewTLSWrapper("", "", nil)
	if err != nil {
		t.Fatalf("NewTLSWrapper error: %v", err)
	}

	// Test with invalid address (should fail but not hang)
	_, err = wrapper.DialInsecure("tcp", "127.0.0.1:9999")
	if err == nil {
		t.Fatalf("expected error for invalid address")
	}
}
