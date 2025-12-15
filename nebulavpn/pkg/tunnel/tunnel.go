package tunnel

import (
	"encoding/binary"
	"io"
	"net"

	"vpn-proxy/internal/crypto"
)

const (
	MaxPacketSize = 65535
)

type Tunnel struct {
	encryptor crypto.Encryptor
}

func NewTunnel(encryptor crypto.Encryptor) *Tunnel {
	return &Tunnel{
		encryptor: encryptor,
	}
}

func (t *Tunnel) ReadPacket(conn net.Conn) ([]byte, string, error) {
	var encLen uint32
	if err := binary.Read(conn, binary.BigEndian, &encLen); err != nil {
		return nil, "", err
	}

	if encLen > MaxPacketSize {
		return nil, "", io.ErrShortBuffer
	}

	encData := make([]byte, encLen)
	if _, err := io.ReadFull(conn, encData); err != nil {
		return nil, "", err
	}

	decData, err := t.encryptor.Decrypt(encData)
	if err != nil {
		return nil, "", err
	}

	if len(decData) < 2 {
		return nil, "", io.ErrShortBuffer
	}

	addrLen := binary.BigEndian.Uint16(decData[:2])
	if len(decData) < int(2+addrLen) {
		return nil, "", io.ErrShortBuffer
	}

	address := string(decData[2 : 2+addrLen])
	data := decData[2+addrLen:]

	return data, address, nil
}

func (t *Tunnel) WritePacket(conn net.Conn, data []byte, address string) error {
	addrBytes := []byte(address)
	packet := make([]byte, 2+len(addrBytes)+len(data))

	binary.BigEndian.PutUint16(packet[:2], uint16(len(addrBytes)))
	copy(packet[2:], addrBytes)
	copy(packet[2+len(addrBytes):], data)

	encData, err := t.encryptor.Encrypt(packet)
	if err != nil {
		return err
	}

	if err := binary.Write(conn, binary.BigEndian, uint32(len(encData))); err != nil {
		return err
	}

	_, err = conn.Write(encData)
	return err
}

func (t *Tunnel) Pipe(src, dst net.Conn, targetAddr string) error {
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		if err != nil {
			return err
		}

		if err := t.WritePacket(dst, buf[:n], targetAddr); err != nil {
			return err
		}
	}
}
