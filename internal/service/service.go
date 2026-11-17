package service

import (
	"context"
	"errors"
	"time"

	"github.com/egoisthemain/SecureVault/internal/cryptography"
	"github.com/egoisthemain/SecureVault/internal/storage"
)

var (
	ErrUnknownKey = errors.New("unknown key")
)

type Service struct {
	store  storage.Store
	cipher *cryptography.Cipher
	keyID  string
}

func New(store storage.Store, cipher *cryptography.Cipher, keyID string) *Service {
	return &Service{store: store, cipher: cipher, keyID: keyID}
}

func (s *Service) Create(ctx context.Context, plaintext []byte) (string, error) {
	id, err := generateID()
	if err != nil {
		return "", err
	}

	encryptedData, err := s.cipher.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	secret := storage.Secret{
		ID:         id,
		Ciphertext: encryptedData.Ciphertext,
		Nonce:      encryptedData.Nonce,
		KeyID:      s.keyID,
		CreatedAt:  time.Now().UTC(),
	}

	err = s.store.Create(ctx, secret)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (s *Service) Get(ctx context.Context, id string) ([]byte, error) {
	secret, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if secret.KeyID != s.keyID {
		return nil, ErrUnknownKey
	}

	encryptedData := cryptography.EncryptedData{
		Ciphertext: secret.Ciphertext,
		Nonce:      secret.Nonce,
	}

	return s.cipher.Decrypt(&encryptedData)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}
