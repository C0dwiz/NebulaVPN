package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type AESGCMEncryptor struct {
	aead cipher.AEAD
}

func NewAESGCMEncryptor(password string) (*AESGCMEncryptor, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESGCMEncryptor{aead: aead}, nil
}

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *AESGCMEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, ciphertext, nil)
}

type ChaCha20Encryptor struct {
	aead cipher.AEAD
}

func NewChaCha20Encryptor(password string) (*ChaCha20Encryptor, error) {
	key := sha256.Sum256([]byte(password))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}

	return &ChaCha20Encryptor{aead: aead}, nil
}

func (e *ChaCha20Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *ChaCha20Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, ciphertext, nil)
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
