package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var (
	ErrInvalidKeyLength     = errors.New("invalid key length: expected 32 bytes")
	ErrInvalidEncryptedData = errors.New("invalid encrypted data")
	ErrInvalidNonceLength   = errors.New("invalid nonce length")
)

type EncryptedData struct {
	Ciphertext []byte
	Nonce      []byte
}

type Cipher struct {
	aead cipher.AEAD
}

func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(plaintext []byte) (*EncryptedData, error) {
	nonce := make([]byte, c.aead.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)
	encryptedData := EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}

	return &encryptedData, nil
}

func (c *Cipher) Decrypt(data *EncryptedData) ([]byte, error) {
	if data == nil {
		return nil, ErrInvalidEncryptedData
	}
	if len(data.Nonce) != c.aead.NonceSize() {
		return nil, ErrInvalidNonceLength
	}

	decrypted, err := c.aead.Open(nil, data.Nonce, data.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
