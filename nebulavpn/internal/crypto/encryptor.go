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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// Key derivation parameters
	PBKDF2Iterations = 100000
	SaltSize         = 32
	NonceSize        = 12
)

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type AESGCMEncryptor struct {
	aead cipher.AEAD
	salt []byte
}

func NewAESGCMEncryptor(password string) (*AESGCMEncryptor, error) {
	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &AESGCMEncryptor{
		aead: aead,
		salt: salt,
	}, nil
}

// NewAESGCMEncryptorWithSalt creates an encryptor with a provided salt (for decryption)
func NewAESGCMEncryptorWithSalt(password string, salt []byte) (*AESGCMEncryptor, error) {
	if len(salt) != SaltSize {
		return nil, errors.New("invalid salt size")
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &AESGCMEncryptor{
		aead: aead,
		salt: salt,
	}, nil
}

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend salt and nonce to ciphertext
	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 0, len(e.salt)+len(nonce)+len(ciphertext))
	result = append(result, e.salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// AESGCMDecryptor provides decryption with password
func (e *AESGCMEncryptor) DecryptWithPassword(ciphertext []byte, password string) ([]byte, error) {
	// Extract salt, nonce, and actual ciphertext
	if len(ciphertext) < SaltSize+NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	salt := ciphertext[:SaltSize]
	nonce := ciphertext[SaltSize : SaltSize+NonceSize]
	actualCiphertext := ciphertext[SaltSize+NonceSize:]

	// Create decryptor with extracted salt
	decryptor, err := NewAESGCMEncryptorWithSalt(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryptor: %w", err)
	}

	return decryptor.aead.Open(nil, nonce, actualCiphertext, nil)
}

// Decrypt method for interface compatibility (requires password to be stored)
func (e *AESGCMEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// This method is kept for interface compatibility but should not be used
	// Use DecryptWithPassword instead
	return nil, errors.New("use DecryptWithPassword method instead")
}

type ChaCha20Encryptor struct {
	aead cipher.AEAD
	salt []byte
}

func NewChaCha20Encryptor(password string) (*ChaCha20Encryptor, error) {
	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 32, sha256.New)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %w", err)
	}

	return &ChaCha20Encryptor{
		aead: aead,
		salt: salt,
	}, nil
}

// NewChaCha20EncryptorWithSalt creates an encryptor with a provided salt (for decryption)
func NewChaCha20EncryptorWithSalt(password string, salt []byte) (*ChaCha20Encryptor, error) {
	if len(salt) != SaltSize {
		return nil, errors.New("invalid salt size")
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 32, sha256.New)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %w", err)
	}

	return &ChaCha20Encryptor{
		aead: aead,
		salt: salt,
	}, nil
}

func (e *ChaCha20Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend salt and nonce to ciphertext
	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 0, len(e.salt)+len(nonce)+len(ciphertext))
	result = append(result, e.salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// ChaCha20Decryptor provides decryption with password
func (e *ChaCha20Encryptor) DecryptWithPassword(ciphertext []byte, password string) ([]byte, error) {
	// Extract salt, nonce, and actual ciphertext
	if len(ciphertext) < SaltSize+NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	salt := ciphertext[:SaltSize]
	nonce := ciphertext[SaltSize : SaltSize+NonceSize]
	actualCiphertext := ciphertext[SaltSize+NonceSize:]

	// Create decryptor with extracted salt
	decryptor, err := NewChaCha20EncryptorWithSalt(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryptor: %w", err)
	}

	return decryptor.aead.Open(nil, nonce, actualCiphertext, nil)
}

// Decrypt method for interface compatibility (requires password to be stored)
func (e *ChaCha20Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// This method is kept for interface compatibility but should not be used
	// Use DecryptWithPassword instead
	return nil, errors.New("use DecryptWithPassword method instead")
}

func NewEncryptor(method, password string) (Encryptor, error) {
	switch method {
	case "aes-256-gcm":
		return NewAESGCMEncryptor(password)
	case "chacha20-poly1305":
		return NewChaCha20Encryptor(password)
	default:
		return NewAESGCMEncryptor(password)
	}
}
