package transport

import (
	"crypto/tls"
	"io"
	"net"
	"time"

	"vpn-proxy/internal/protocol"
)

type TLSWrapper struct {
	config    *tls.Config
	httpsMask *protocol.HTTPSMask
}

func NewTLSWrapper(certFile, keyFile string, httpsMask *protocol.HTTPSMask) (*TLSWrapper, error) {
	wrapper := &TLSWrapper{
		httpsMask: httpsMask,
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}

		wrapper.config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return wrapper, nil
}

func (w *TLSWrapper) Listen(network, addr string) (net.Listener, error) {
	config := w.httpsMask.WrapTLS(w.config)
	return tls.Listen(network, addr, config)
}

func (w *TLSWrapper) Dial(network, addr string) (net.Conn, error) {
	if w.httpsMask != nil {
		return w.httpsMask.DialTLS(network, addr, &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	return tls.Dial(network, addr, &tls.Config{
		InsecureSkipVerify: true,
	})
}

func (w *TLSWrapper) Copy(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	io.Copy(dst, src)
}

func (w *TLSWrapper) CopyWithTimeout(dst, src net.Conn, timeout time.Duration) {
	defer dst.Close()
	defer src.Close()

	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)
		if err != nil {
			return
		}

		dst.SetWriteDeadline(time.Now().Add(timeout))
		_, err = dst.Write(buf[:n])
		if err != nil {
			return
		}
	}
}
