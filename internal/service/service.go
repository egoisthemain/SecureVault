package service

import (
	"context"
	"time"

	"github.com/egoisthemain/SecureVault/internal/cryptography"
	"github.com/egoisthemain/SecureVault/internal/storage"
)

type Service struct {
	store   storage.Store
	keyring *cryptography.Keyring
}

func New(store storage.Store, keyring *cryptography.Keyring) *Service {
	return &Service{store: store, keyring: keyring}
}

func (s *Service) Create(ctx context.Context, plaintext []byte) (string, error) {
	id, err := generateID()
	if err != nil {
		return "", err
	}

	keyID, cipher := s.keyring.Active()

	encryptedData, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	secret := storage.Secret{
		ID:         id,
		Ciphertext: encryptedData.Ciphertext,
		Nonce:      encryptedData.Nonce,
		KeyID:      keyID,
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

	cipher, err := s.keyring.Get(secret.KeyID)
	if err != nil {
		return nil, err
	}

	encryptedData := cryptography.EncryptedData{
		Ciphertext: secret.Ciphertext,
		Nonce:      secret.Nonce,
	}

	return cipher.Decrypt(&encryptedData)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}
