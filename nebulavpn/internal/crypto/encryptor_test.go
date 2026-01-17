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

	// Test with DecryptWithPassword since regular Decrypt returns error
	aesEncryptor, ok := e.(*AESGCMEncryptor)
	if !ok {
		t.Fatalf("Expected AESGCMEncryptor")
	}

	dec, err := aesEncryptor.DecryptWithPassword(enc, "password123")
	if err != nil {
		t.Fatalf("DecryptWithPassword error: %v", err)
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

	// Test with DecryptWithPassword since regular Decrypt returns error
	chachaEncryptor, ok := e.(*ChaCha20Encryptor)
	if !ok {
		t.Fatalf("Expected ChaCha20Encryptor")
	}

	dec, err := chachaEncryptor.DecryptWithPassword(enc, "password123")
	if err != nil {
		t.Fatalf("DecryptWithPassword error: %v", err)
	}
	if string(dec) != string(plain) {
		t.Fatalf("got %q, want %q", dec, plain)
	}
}

func TestEncryptorWithDifferentPasswords(t *testing.T) {
	e1, err := NewEncryptor("aes-256-gcm", "password1")
	if err != nil {
		t.Fatalf("NewEncryptor error: %v", err)
	}

	e2, err := NewEncryptor("aes-256-gcm", "password2")
	if err != nil {
		t.Fatalf("NewEncryptor error: %v", err)
	}

	plain := []byte("test data")
	enc, err := e1.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Try to decrypt with wrong password
	aesEncryptor, ok := e2.(*AESGCMEncryptor)
	if !ok {
		t.Fatalf("Expected AESGCMEncryptor")
	}

	_, err = aesEncryptor.DecryptWithPassword(enc, "password2")
	if err == nil {
		t.Fatalf("Expected decryption to fail with wrong password")
	}
}

func TestEncryptorInvalidPassword(t *testing.T) {
	// Test with short password
	_, err := NewEncryptor("aes-256-gcm", "short")
	// This should not fail - password validation is at config level
	if err != nil {
		t.Fatalf("NewEncryptor with short password should not fail: %v", err)
	}
}

func TestEncryptorInvalidMethod(t *testing.T) {
	// Test with invalid method (should default to AES-256-GCM)
	e, err := NewEncryptor("invalid-method", "password123")
	if err != nil {
		t.Fatalf("NewEncryptor error: %v", err)
	}

	plain := []byte("test data")
	enc, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Should be able to decrypt
	aesEncryptor, ok := e.(*AESGCMEncryptor)
	if !ok {
		t.Fatalf("Expected AESGCMEncryptor")
	}

	dec, err := aesEncryptor.DecryptWithPassword(enc, "password123")
	if err != nil {
		t.Fatalf("DecryptWithPassword error: %v", err)
	}
	if string(dec) != string(plain) {
		t.Fatalf("got %q, want %q", dec, plain)
	}
}

func TestEncryptorSaltUniqueness(t *testing.T) {
	e, err := NewEncryptor("aes-256-gcm", "password123")
	if err != nil {
		t.Fatalf("NewEncryptor error: %v", err)
	}

	plain := []byte("test data")

	// Encrypt twice with same data
	enc1, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	enc2, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Encrypted data should be different due to random salt and nonce
	if string(enc1) == string(enc2) {
		t.Fatalf("Encrypted data should be different due to random salt/nonce")
	}

	// But both should decrypt to the same plaintext
	aesEncryptor, ok := e.(*AESGCMEncryptor)
	if !ok {
		t.Fatalf("Expected AESGCMEncryptor")
	}

	dec1, err := aesEncryptor.DecryptWithPassword(enc1, "password123")
	if err != nil {
		t.Fatalf("DecryptWithPassword error: %v", err)
	}

	dec2, err := aesEncryptor.DecryptWithPassword(enc2, "password123")
	if err != nil {
		t.Fatalf("DecryptWithPassword error: %v", err)
	}

	if string(dec1) != string(plain) || string(dec2) != string(plain) {
		t.Fatalf("Decrypted data doesn't match original")
	}
}
