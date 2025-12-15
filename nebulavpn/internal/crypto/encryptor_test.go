package crypto

import (
	"testing"
)

func TestEncryptorRoundTripAES(t *testing.T) {
	e, err := NewEncryptor("aes-256-gcm", "password123")
	if err != nil {
		t.Fatalf("NewEncryptor error: %v", err)
	}

	plain := []byte("hello world")
	enc, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	if len(enc) == 0 {
		t.Fatalf("Encrypt returned empty slice")
	}

	dec, err := e.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if string(dec) != string(plain) {
		t.Fatalf("got %q, want %q", dec, plain)
	}
}

func TestEncryptorRoundTripChaCha20(t *testing.T) {
	e, err := NewEncryptor("chacha20-poly1305", "password123")
	if err != nil {
		t.Fatalf("NewEncryptor error: %v", err)
	}

	plain := []byte("another payload")
	enc, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	dec, err := e.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if string(dec) != string(plain) {
		t.Fatalf("got %q, want %q", dec, plain)
	}
}
