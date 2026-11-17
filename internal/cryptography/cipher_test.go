package cryptography

import (
	"bytes"
	"errors"
	"testing"
)

type testCaseKey struct {
	name string
	key  []byte
}

type testCaseText struct {
	name string
	text []byte
}

type testCaseDecrypt struct {
	name        string
	testEncrypt *EncryptedData
	wantErr     error
}

func TestNewValidKey(t *testing.T) {
	cases := []testCaseKey{
		{
			name: "valid key",
			key:  []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2"),
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			newCipher, err := New(testcase.key)
			if err != nil || newCipher == nil {
				t.Fatalf("expected cipher != nil, err == nil, got cipher %v, err %v", newCipher, err)
			}
			if newCipher.aead == nil {
				t.Fatal("expected not empty aead")
			}
		})
	}
}

func TestNewInvalidLength(t *testing.T) {
	cases := []testCaseKey{
		{
			name: "zero length key",
			key:  []byte(""),
		},
		{
			name: "16 length key",
			key:  make([]byte, 16),
		},
		{
			name: "24 length key",
			key:  make([]byte, 24),
		},
		{
			name: "31 length key",
			key:  make([]byte, 31),
		},
		{
			name: "33 length key",
			key:  make([]byte, 33),
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			newCipher, err := New(testcase.key)
			if newCipher != nil || !errors.Is(err, ErrInvalidKeyLength) {
				t.Fatalf("expected nil cipher and ErrInvalidKeyLength, got %v, %v", newCipher, err)
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	cases := []testCaseText{
		{
			name: "valid text",
			text: []byte("hello this is my pass: 123456"),
		},
		{
			name: "empty text",
			text: []byte(""),
		},
	}

	key := []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			encryptedData, err := cipher.Encrypt(testcase.text)
			if err != nil {
				t.Fatalf("nil err expected, got %v", err)
			}
			if encryptedData == nil {
				t.Fatal("expected not nil encryptedData")
			}
			if len(encryptedData.Nonce) != cipher.aead.NonceSize() {
				t.Fatalf("expected nonce length: %v, got %v", cipher.aead.NonceSize(), len(encryptedData.Nonce))
			}
			if len(encryptedData.Ciphertext) != len(testcase.text)+cipher.aead.Overhead() {
				t.Fatalf("expected ciphertext length: %v, got %v", len(testcase.text)+cipher.aead.Overhead(), len(encryptedData.Ciphertext))
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	cases := []testCaseText{
		{
			name: "valid text",
			text: []byte("hello this is my pass: 123456"),
		},
		{
			name: "empty text",
			text: []byte(""),
		},
		{
			name: "binary data",
			text: []byte{0x00, 0xff, 0x80, 0x40},
		},
	}

	key := []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			encryptedData, err := cipher.Encrypt(testcase.text)
			if err != nil {
				t.Fatalf("encryption error: %v", err)
			}
			if encryptedData == nil {
				t.Fatal("expected not nil encryptedData")
			}
			if len(encryptedData.Nonce) != cipher.aead.NonceSize() {
				t.Fatalf("expected nonce length: %v, got %v", cipher.aead.NonceSize(), len(encryptedData.Nonce))
			}
			if len(encryptedData.Ciphertext) != len(testcase.text)+cipher.aead.Overhead() {
				t.Fatalf("expected ciphertext length: %v, got %v", len(testcase.text)+cipher.aead.Overhead(), len(encryptedData.Ciphertext))
			}

			decryptedData, err := cipher.Decrypt(encryptedData)
			if err != nil {
				t.Fatalf("decryption error: %v", err)
			}
			if !bytes.Equal(testcase.text, decryptedData) {
				t.Fatalf("expected equal textes, got plaintext: %v, decrypted: %v", testcase.text, decryptedData)
			}
		})
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	text := []byte("hello my pass is 12345")

	encryptedData, err := cipher.Encrypt(text)
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	encryptedData.Ciphertext[0] ^= 1

	decryptedData, err := cipher.Decrypt(encryptedData)
	if err == nil {
		t.Fatalf("decryption must be with error, got nil")
	}

	if decryptedData != nil {
		t.Fatalf("not nil decryption for tampered text: %v", decryptedData)
	}
}

func TestDecryptTamperedNonce(t *testing.T) {
	key := []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	text := []byte("hello my pass is 12345")

	encryptedData, err := cipher.Encrypt(text)
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	encryptedData.Nonce[0] ^= 1

	decryptedData, err := cipher.Decrypt(encryptedData)
	if err == nil {
		t.Fatalf("decryption must be with error, got nil")
	}

	if decryptedData != nil {
		t.Fatalf("not nil decryption for tampered text: %v", decryptedData)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] ^= 1

	cipher1, err := New(key1)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	cipher2, err := New(key2)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	text := []byte("hello my pass is 12345")

	encryptedData, err := cipher1.Encrypt(text)
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	decryptedData, err := cipher2.Decrypt(encryptedData)
	if err == nil {
		t.Fatalf("decryption must be with error, got nil")
	}

	if decryptedData != nil {
		t.Fatalf("not nil decryption for wrong key: %v", decryptedData)
	}
}

func TestDecryptInvalidData(t *testing.T) {
	key := []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("creating cipher error: %v", err)
	}

	cases := []testCaseDecrypt{
		{
			name:        "nil encryptedData",
			testEncrypt: nil,
			wantErr:     ErrInvalidEncryptedData,
		},
		{
			name:        "empty encryptedData",
			testEncrypt: &EncryptedData{},
			wantErr:     ErrInvalidNonceLength,
		},
		{
			name: "nonce-1",
			testEncrypt: &EncryptedData{
				Nonce: make([]byte, cipher.aead.NonceSize()-1),
			},
			wantErr: ErrInvalidNonceLength,
		},
		{
			name: "nonce+1",
			testEncrypt: &EncryptedData{
				Nonce: make([]byte, cipher.aead.NonceSize()+1),
			},
			wantErr: ErrInvalidNonceLength,
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			decryptedData, err := cipher.Decrypt(testcase.testEncrypt)
			if !errors.Is(err, testcase.wantErr) {
				t.Fatalf("expected error: %v, got: %v", testcase.wantErr, err)
			}
			if decryptedData != nil {
				t.Fatalf("not nil decryption for wrong nonce: %v", decryptedData)
			}
		})
	}
}

func TestDecryptTruncatedCiphertext(t *testing.T) {
	key := []byte("ABSHGKTJFLD748DHFKCJGH2DJFHCJNS2")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("error of cipher creating: %v", err)
	}

	text := []byte("hello my pass is 12345")

	encryptedData, err := cipher.Encrypt(text)
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	encryptedData.Ciphertext = encryptedData.Ciphertext[:len(encryptedData.Ciphertext)-1]

	decryptedData, err := cipher.Decrypt(encryptedData)
	if err == nil {
		t.Fatalf("decryption must be with error, got nil")
	}

	if decryptedData != nil {
		t.Fatalf("not nil decryption for tampered text: %v", decryptedData)
	}
}
