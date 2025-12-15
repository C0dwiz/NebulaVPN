package tunnel

import (
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

	done := make(chan error, 1)
	go func() {
		done <- tun.Pipe(src, dst, "example.com:80")
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
