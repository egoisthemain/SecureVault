package cryptography

import (
	"errors"
)

var (
	ErrInvalidKeyID      = errors.New("invalid keyID")
	ErrActiveKeyNotFound = errors.New("active key not found")
	ErrUnknownKey        = errors.New("unknown key")
)

type Keyring struct {
	activeKeyID string
	ciphers     map[string]*Cipher
}

func NewKeyring(activeKeyID string, keys map[string][]byte) (*Keyring, error) {
	if activeKeyID == "" {
		return nil, ErrInvalidKeyID
	}

	_, ok := keys[activeKeyID]
	if !ok {
		return nil, ErrActiveKeyNotFound
	}

	cipherMap := make(map[string]*Cipher)
	for id, key := range keys {
		if id == "" {
			return nil, ErrInvalidKeyID
		}
		cipher, err := New(key)
		if err != nil {
			return nil, err
		}

		cipherMap[id] = cipher
	}

	return &Keyring{activeKeyID: activeKeyID, ciphers: cipherMap}, nil
}

func (k *Keyring) Active() (string, *Cipher) {
	return k.activeKeyID, k.ciphers[k.activeKeyID]
}

func (k *Keyring) Get(keyID string) (*Cipher, error) {
	cipher, ok := k.ciphers[keyID]
	if ok {
		return cipher, nil
	}

	return nil, ErrUnknownKey
}
