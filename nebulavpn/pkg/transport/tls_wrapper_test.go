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
		w.Copy(dst, src)
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
		w.CopyWithTimeout(dst, src, 100*time.Millisecond)
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
