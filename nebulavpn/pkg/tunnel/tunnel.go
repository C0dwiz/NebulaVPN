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
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"nebulavpn/internal/crypto"
)

const (
	MaxPacketSize = 65535
	BufferSize    = 32 * 1024 // 32KB buffer for optimal performance
	MaxAddrLength = 253       // Maximum hostname length
	ReadTimeout   = 30 * time.Second
	WriteTimeout  = 30 * time.Second
)

type Tunnel struct {
	encryptor crypto.Encryptor
	mu        sync.RWMutex // Thread safety
	pool      sync.Pool    // Buffer pool for performance
}

func NewTunnel(encryptor crypto.Encryptor) *Tunnel {
	return &Tunnel{
		encryptor: encryptor,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, BufferSize)
			},
		},
	}
}

func (t *Tunnel) ReadPacket(conn net.Conn) ([]byte, string, error) {
	// Set read timeout
	if err := conn.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		return nil, "", fmt.Errorf("failed to set read deadline: %w", err)
	}

	var encLen uint32
	if err := binary.Read(conn, binary.BigEndian, &encLen); err != nil {
		return nil, "", fmt.Errorf("failed to read packet length: %w", err)
	}

	if encLen > MaxPacketSize {
		return nil, "", fmt.Errorf("packet too large: %d bytes", encLen)
	}

	if encLen < 2 { // Minimum size for address length
		return nil, "", errors.New("packet too small")
	}

	// Get buffer from pool
	buf := t.pool.Get().([]byte)
	defer t.pool.Put(buf)

	if encLen > uint32(len(buf)) {
		buf = make([]byte, encLen)
	}

	encData := buf[:encLen]
	if _, err := io.ReadFull(conn, encData); err != nil {
		return nil, "", fmt.Errorf("failed to read packet data: %w", err)
	}

	t.mu.RLock()
	decData, err := t.encryptor.Decrypt(encData)
	t.mu.RUnlock()

	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt packet: %w", err)
	}

	if len(decData) < 2 {
		return nil, "", errors.New("decrypted packet too small")
	}

	addrLen := binary.BigEndian.Uint16(decData[:2])
	if addrLen > MaxAddrLength {
		return nil, "", fmt.Errorf("address too long: %d", addrLen)
	}

	if len(decData) < int(2+addrLen) {
		return nil, "", errors.New("packet truncated")
	}

	address := string(decData[2 : 2+addrLen])
	// Validate address format
	if address == "" {
		return nil, "", errors.New("empty address")
	}

	data := decData[2+addrLen:]
	if len(data) == 0 {
		return nil, address, nil // Empty data is allowed
	}

	// Copy data to new slice to avoid referencing pool buffer
	result := make([]byte, len(data))
	copy(result, data)

	return result, address, nil
}

func (t *Tunnel) WritePacket(conn net.Conn, data []byte, address string) error {
	// Validate inputs
	if address == "" {
		return errors.New("address cannot be empty")
	}
	if len(address) > MaxAddrLength {
		return fmt.Errorf("address too long: %d", len(address))
	}

	// Set write timeout
	if err := conn.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	addrBytes := []byte(address)
	packetSize := 2 + len(addrBytes) + len(data)
	if packetSize > MaxPacketSize {
		return fmt.Errorf("packet too large: %d", packetSize)
	}

	packet := make([]byte, packetSize)
	binary.BigEndian.PutUint16(packet[:2], uint16(len(addrBytes)))
	copy(packet[2:], addrBytes)
	copy(packet[2+len(addrBytes):], data)

	t.mu.RLock()
	encData, err := t.encryptor.Encrypt(packet)
	t.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to encrypt packet: %w", err)
	}

	if err := binary.Write(conn, binary.BigEndian, uint32(len(encData))); err != nil {
		return fmt.Errorf("failed to write packet length: %w", err)
	}

	_, err = conn.Write(encData)
	return err
}

func (t *Tunnel) Pipe(ctx context.Context, src, dst net.Conn, targetAddr string) error {
	buf := t.pool.Get().([]byte)
	defer t.pool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set read timeout
		if err := src.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		n, err := src.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil // Normal closure
			}
			return fmt.Errorf("read error: %w", err)
		}

		if n == 0 {
			continue
		}

		if err := t.WritePacket(dst, buf[:n], targetAddr); err != nil {
			return fmt.Errorf("write packet error: %w", err)
		}
	}
}

// PipeWithBuffer provides a buffered pipe for better performance
func (t *Tunnel) PipeWithBuffer(ctx context.Context, src, dst net.Conn, targetAddr string, bufferSize int) error {
	if bufferSize <= 0 {
		bufferSize = BufferSize
	}

	buf := make([]byte, bufferSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set read timeout
		if err := src.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		n, err := src.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil // Normal closure
			}
			return fmt.Errorf("read error: %w", err)
		}

		if n == 0 {
			continue
		}

		if err := t.WritePacket(dst, buf[:n], targetAddr); err != nil {
			return fmt.Errorf("write packet error: %w", err)
		}
	}
}
