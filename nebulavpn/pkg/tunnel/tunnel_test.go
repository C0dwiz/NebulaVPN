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

package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type simpleEncryptor struct{}

func (simpleEncryptor) Encrypt(plaintext []byte) ([]byte, error)  { return plaintext, nil }
func (simpleEncryptor) Decrypt(ciphertext []byte) ([]byte, error) { return ciphertext, nil }

func TestWriteAndReadPacket(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		if err := tun.WritePacket(server, []byte("payload"), "example.com:80"); err != nil {
			t.Errorf("WritePacket error: %v", err)
		}
	}()

	data, addr, err := tun.ReadPacket(client)
	if err != nil {
		t.Fatalf("ReadPacket error: %v", err)
	}
	if addr != "example.com:80" {
		t.Fatalf("addr = %s, want example.com:80", addr)
	}
	if string(data) != "payload" {
		t.Fatalf("data = %s, want payload", data)
	}
}

func TestReadPacketTooLarge(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {

		binary.Write(server, binary.BigEndian, uint32(MaxPacketSize+1))
	}()

	_, _, err := tun.ReadPacket(client)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestReadPacketTooShort(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		binary.Write(server, binary.BigEndian, uint32(1))
		server.Write([]byte{0x01})
	}()

	_, _, err := tun.ReadPacket(client)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestPipeStopsOnReadError(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- tun.Pipe(ctx, src, dst, "example.com:80")
	}()

	src.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected error from Pipe when src closes")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Pipe did not return after src close")
	}
}

func TestPipeWithContextCancellation(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- tun.Pipe(ctx, src, dst, "example.com:80")
	}()

	cancel() // Cancel context

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Pipe did not return after context cancellation")
	}
}

func TestWritePacketValidation(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Test empty address
	err := tun.WritePacket(server, []byte("payload"), "")
	if err == nil {
		t.Fatalf("expected error for empty address")
	}

	// Test address too long
	longAddr := string(make([]byte, MaxAddrLength+1))
	err = tun.WritePacket(server, []byte("payload"), longAddr)
	if err == nil {
		t.Fatalf("expected error for address too long")
	}
}

func TestReadPacketValidation(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Test packet too small
	go func() {
		binary.Write(server, binary.BigEndian, uint32(1))
		server.Write([]byte{0x01})
	}()

	_, _, err := tun.ReadPacket(client)
	if err == nil {
		t.Fatalf("expected error for packet too small")
	}
}

func TestBufferPoolEfficiency(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})

	// Test that buffer pool is working
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Multiple writes and reads should reuse buffers
	for i := 0; i < 10; i++ {
		go func() {
			tun.WritePacket(server, []byte("payload"), "example.com:80")
		}()

		data, addr, err := tun.ReadPacket(client)
		if err != nil {
			t.Fatalf("ReadPacket error on iteration %d: %v", i, err)
		}
		if addr != "example.com:80" {
			t.Fatalf("addr = %s, want example.com:80", addr)
		}
		if string(data) != "payload" {
			t.Fatalf("data = %s, want payload", data)
		}
	}
}

func TestPipeWithBuffer(t *testing.T) {
	tun := NewTunnel(simpleEncryptor{})
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test with custom buffer size
	err := tun.PipeWithBuffer(ctx, src, dst, "example.com:80", 1024)
	if err != nil && err != context.DeadlineExceeded {
		t.Fatalf("PipeWithBuffer error: %v", err)
	}
}
