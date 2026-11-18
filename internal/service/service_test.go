package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/egoisthemain/SecureVault/internal/cryptography"
	"github.com/egoisthemain/SecureVault/internal/storage"
)

type memoryStore struct {
	secrets   map[string]storage.Secret
	createErr error
}

var _ storage.Store = (*memoryStore)(nil)

func (m *memoryStore) Create(ctx context.Context, secret storage.Secret) error {
	if m.createErr != nil {
		return m.createErr
	}
	_, ok := m.secrets[secret.ID]
	if ok {
		return storage.ErrAlreadyExists
	}

	m.secrets[secret.ID] = secret
	return nil
}

func (m *memoryStore) Get(ctx context.Context, id string) (storage.Secret, error) {
	secret, ok := m.secrets[id]
	if !ok {
		return storage.Secret{}, storage.ErrNotFound
	}

	return secret, nil
}

func (m *memoryStore) Delete(ctx context.Context, id string) error {
	_, ok := m.secrets[id]
	if !ok {
		return storage.ErrNotFound
	}

	delete(m.secrets, id)
	return nil
}

func TestServiceCreateGet(t *testing.T) {
	store := &memoryStore{
		secrets: make(map[string]storage.Secret),
	}

	plaintext := []byte("hello my pass is 12345")

	keyring, err := cryptography.NewKeyring("test-key", map[string][]byte{
		"test-key": make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc := New(store, keyring)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id, err := svc.Create(ctx, plaintext)
	if err != nil {
		t.Fatalf("error of secret creating: %v", err)
	}
	if id == "" {
		t.Fatalf("id must be non-empty")
	}

	secret, ok := store.secrets[id]
	if !ok {
		t.Fatalf("expected existing secret with id: %v", id)
	}

	if secret.ID != id {
		t.Fatalf("expected ID %q, got %q", id, secret.ID)
	}

	if secret.KeyID != "test-key" {
		t.Fatalf("expected KeyID: %v, got %v", "test-key", secret.KeyID)
	}

	if secret.CreatedAt.IsZero() {
		t.Fatalf("expected non zero CreatedAt")
	}

	if len(secret.Nonce) == 0 {
		t.Fatalf("expected non-empty Nonce")
	}

	if bytes.Equal(secret.Ciphertext, plaintext) {
		t.Fatalf("expected non equal ciphertext and plaintext")
	}

	data, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatalf("getting error: %v", err)
	}

	if !bytes.Equal(data, plaintext) {
		t.Fatalf("expected: %v, got %v", plaintext, data)
	}
}

func TestServiceTamperedCiphertext(t *testing.T) {
	store := &memoryStore{
		secrets: make(map[string]storage.Secret),
	}

	plaintext := []byte("hello my pass is 12345")

	keyring, err := cryptography.NewKeyring("test-key", map[string][]byte{
		"test-key": make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc := New(store, keyring)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id, err := svc.Create(ctx, plaintext)
	if err != nil {
		t.Fatalf("error of secret creating: %v", err)
	}

	secret, ok := store.secrets[id]
	if !ok {
		t.Fatalf("expected existing secret with id: %v", id)
	}

	secret.Ciphertext[0] ^= 1

	store.secrets[id] = secret

	data, err := svc.Get(ctx, id)
	if err == nil {
		t.Fatalf("expected a non nil error")
	}
	if data != nil {
		t.Fatalf("expected empty data, got: %v", data)
	}
}

func TestServiceGetUnknownKey(t *testing.T) {
	store := &memoryStore{
		secrets: make(map[string]storage.Secret),
	}

	plaintext := []byte("hello my pass is 12345")

	keyring, err := cryptography.NewKeyring("test-key", map[string][]byte{
		"test-key": make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc := New(store, keyring)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id, err := svc.Create(ctx, plaintext)
	if err != nil {
		t.Fatalf("error of secret creating: %v", err)
	}

	secret, ok := store.secrets[id]
	if !ok {
		t.Fatalf("expected existing secret with id: %v", id)
	}

	secret.KeyID = "another-key"
	store.secrets[id] = secret

	data, err := svc.Get(ctx, id)
	if !errors.Is(err, cryptography.ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got: %v", err)
	}

	if data != nil {
		t.Fatalf("expected nil data, got: %v", data)
	}
}

func TestServiceGetNotFound(t *testing.T) {
	store := &memoryStore{
		secrets: make(map[string]storage.Secret),
	}

	keyring, err := cryptography.NewKeyring("test-key", map[string][]byte{
		"test-key": make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc := New(store, keyring)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := svc.Get(ctx, "missing-secret")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	if data != nil {
		t.Fatalf("expected nil data, got: %v", data)
	}
}

func TestServiceCreateStorageError(t *testing.T) {
	wantErr := errors.New("storage unvailable")
	store := &memoryStore{
		secrets:   make(map[string]storage.Secret),
		createErr: wantErr,
	}

	plaintext := []byte("hello my pass is 12345")

	keyring, err := cryptography.NewKeyring("test-key", map[string][]byte{
		"test-key": make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc := New(store, keyring)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id, err := svc.Create(ctx, plaintext)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected err: %v, got: %v", wantErr, err)
	}

	if id != "" {
		t.Fatalf("expected empty id")
	}

	if len(store.secrets) != 0 {
		t.Fatalf("expected len(store.secrets) == 0, got: %v", len(store.secrets))
	}
}

func TestServiceKeyRotation(t *testing.T) {
	store := &memoryStore{
		secrets: make(map[string]storage.Secret),
	}

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	keyring, err := cryptography.NewKeyring("key-v1", map[string][]byte{
		"key-v1": key1,
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc1 := New(store, keyring)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldID, err := svc1.Create(ctx, []byte("old-secret"))
	if err != nil {
		t.Fatalf("error of secret creating: %v", err)
	}

	keyring, err = cryptography.NewKeyring("key-v2", map[string][]byte{
		"key-v1": key1,
		"key-v2": key2,
	})
	if err != nil {
		t.Fatalf("error of keyring creating: %v", err)
	}

	svc2 := New(store, keyring)
	newID, err := svc2.Create(ctx, []byte("new-secret"))
	if err != nil {
		t.Fatalf("error of secret creating: %v", err)
	}

	if store.secrets[oldID].KeyID != "key-v1" {
		t.Fatalf("expected key: %v for oldID, got: %v", "key-v1", store.secrets[oldID].KeyID)
	}

	if store.secrets[newID].KeyID != "key-v2" {
		t.Fatalf("expected key: %v for newID, got: %v", "key-v2", store.secrets[newID].KeyID)
	}

	oldData, err := svc2.Get(ctx, oldID)
	if err != nil {
		t.Fatalf("error of oldData reading: %v", err)
	}

	newData, err := svc2.Get(ctx, newID)
	if err != nil {
		t.Fatalf("error of newData reading: %v", err)
	}

	if !bytes.Equal(oldData, []byte("old-secret")) {
		t.Fatalf("expected data: %v, got: %v", "old-secret", string(oldData))
	}

	if !bytes.Equal(newData, []byte("new-secret")) {
		t.Fatalf("expected data: %v, got: %v", "new-secret", string(newData))
	}

}
