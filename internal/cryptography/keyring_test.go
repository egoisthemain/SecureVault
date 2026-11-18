package cryptography

import (
	"bytes"
	"errors"
	"testing"
)

func TestKeyringSelection(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 15

	keys := make(map[string][]byte)
	keys["key-v1"] = key1
	keys["key-v2"] = key2

	keyring, err := NewKeyring("key-v2", keys)
	if err != nil {
		t.Fatalf("creating keyring error: %v", err)
	}

	activeKeyID, cipher := keyring.Active()
	if activeKeyID != "key-v2" {
		t.Fatalf("expected activeKeyID: %v, got %v", "key-v2", activeKeyID)
	}

	if cipher == nil {
		t.Fatalf("expected non-nil cipher")
	}

	oldCipher, err := keyring.Get("key-v1")
	if err != nil {
		t.Fatalf("get old cipher: %v", err)
	}
	if oldCipher == nil {
		t.Fatalf("expected non-nil old cipher")
	}

	plaintext := []byte("hello my pass is 12345")

	encryptedData, err := oldCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("error of encryption: %v", err)
	}

	data, err := oldCipher.Decrypt(encryptedData)
	if err != nil {
		t.Fatalf("error of decryption: %v", err)
	}

	if !bytes.Equal(data, plaintext) {
		t.Fatalf("expected data: %v, got %v", plaintext, data)
	}

	data, err = cipher.Decrypt(encryptedData)
	if err == nil {
		t.Fatalf("expected non-nil err")
	}

	if data != nil {
		t.Fatalf("expected nil data, got %v", data)
	}

	cipher, err = keyring.Get("missing-key")
	if cipher != nil {
		t.Fatalf("expected nil cipher, got %v", cipher)
	}

	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected err: %v, got %v", ErrUnknownKey, err)
	}
}

type TestKeyring struct {
	name     string
	activeID string
	keys     map[string][]byte
	wantErr  error
}

func TestNewKeyringInvalidConfig(t *testing.T) {
	cases := []TestKeyring{
		{
			name:     "empty activeID",
			activeID: "",
			keys: map[string][]byte{
				"key-v1": make([]byte, 32),
			},
			wantErr: ErrInvalidKeyID,
		},
		{
			name:     "activeID not in keys",
			activeID: "key-v1",
			keys: map[string][]byte{
				"key-v2": make([]byte, 32),
			},
			wantErr: ErrActiveKeyNotFound,
		},
		{
			name:     "nil keys and non-empty activeID",
			activeID: "key-v1",
			keys:     nil,
			wantErr:  ErrActiveKeyNotFound,
		},
		{
			name:     "empty id in keys",
			activeID: "key-v1",
			keys: map[string][]byte{
				"key-v1": make([]byte, 32),
				"":       make([]byte, 32),
			},
			wantErr: ErrInvalidKeyID,
		},
		{
			name:     "activeID key length is 31 bytes",
			activeID: "key-v1",
			keys: map[string][]byte{
				"key-v1": make([]byte, 31),
			},
			wantErr: ErrInvalidKeyLength,
		},
		{
			name:     "oldID key length is 31 bytes",
			activeID: "key-v1",
			keys: map[string][]byte{
				"key-v1": make([]byte, 32),
				"key-v2": make([]byte, 31),
			},
			wantErr: ErrInvalidKeyLength,
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			keyring, err := NewKeyring(testcase.activeID, testcase.keys)
			if !errors.Is(err, testcase.wantErr) {
				t.Fatalf("expected err: %v, got: %v", testcase.wantErr, err)
			}

			if keyring != nil {
				t.Fatalf("expected nil keyring, got: %v", keyring)
			}
		})
	}
}
