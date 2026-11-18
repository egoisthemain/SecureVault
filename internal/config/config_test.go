package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLoadSuccess(t *testing.T) {
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("DATABASE_URL", "postgres://test-user:test-pass@localhost/test-db")
	t.Setenv("KEY_ID", "test-key")
	t.Setenv("ENCRYPTION_KEYS", fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 32)))

	t.Setenv("API_TOKEN", "api-token")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	if cfg.HTTPAddr != "127.0.0.1:8080" {
		t.Fatalf("expected HTTPAddr: %v, got: %v", "127.0.0.1:8080", cfg.HTTPAddr)
	}

	if cfg.DatabaseURL != "postgres://test-user:test-pass@localhost/test-db" {
		t.Fatalf("expected DatabaseURL: %v, got: %v", "postgres://test-user:test-pass@localhost/test-db", cfg.DatabaseURL)
	}

	if cfg.KeyID != "test-key" {
		t.Fatalf("expected KeyID: %v, got: %v", "test-key", cfg.KeyID)
	}

	if len(cfg.EncryptionKeys) != 1 {
		t.Fatalf("expected 1 key, got: %d", len(cfg.EncryptionKeys))
	}

	if !bytes.Equal(cfg.EncryptionKeys["test-key"], bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("unexpected bytes for test-key")
	}

	if cfg.APIToken != "api-token" {
		t.Fatalf("expected APIToken: %v, got: %v", "api-token", cfg.APIToken)
	}
}

type testConfig struct {
	name     string
	addr     string
	url      string
	keyID    string
	encKey   string
	apiToken string
	wantErr  string
}

func TestLoadInvalidConfig(t *testing.T) {
	cases := []testConfig{
		{
			name:     "no db adress",
			addr:     "",
			url:      "",
			keyID:    "test-key",
			encKey:   fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 32)),
			apiToken: "api-token",
			wantErr:  "DATABASE_URL is required",
		},
		{
			name:     "no keyID",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "",
			encKey:   fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 32)),
			apiToken: "api-token",
			wantErr:  "KEY_ID is required",
		},
		{
			name:     "no EncryptionKey",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   "",
			apiToken: "api-token",
			wantErr:  "ENCRYPTION_KEYS is required",
		},
		{
			name:     "no apiToken",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 32)),
			apiToken: "",
			wantErr:  "API_TOKEN is required",
		},
		{
			name:     "invalid hex",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   `{"test-key":"zz"}`,
			apiToken: "api-token",
			wantErr:  "ENCRYPTION_KEY must be valid hex",
		},
		{
			name:     "short EncryptionKey",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 31)),
			apiToken: "api-token",
			wantErr:  "invalid key length: expected 32 bytes",
		},
		{
			name:     "long key",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 33)),
			apiToken: "api-token",
			wantErr:  "invalid key length: expected 32 bytes",
		},
		{
			name:     "active key not in key map",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "missing-key",
			encKey:   fmt.Sprintf(`{"test-key":"%s"}`, strings.Repeat("ab", 32)),
			apiToken: "api-token",
			wantErr:  "KEY_ID must reference an existing encryption key",
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Setenv("HTTP_ADDR", testcase.addr)
			t.Setenv("DATABASE_URL", testcase.url)
			t.Setenv("KEY_ID", testcase.keyID)
			t.Setenv("ENCRYPTION_KEYS", testcase.encKey)
			t.Setenv("API_TOKEN", testcase.apiToken)

			_, err := Load()
			if err == nil {
				t.Fatalf("expected error: %v, got: nil", testcase.wantErr)
			}
			if testcase.wantErr != err.Error() {
				t.Fatalf("expected error: %v, got: %v", testcase.wantErr, err.Error())
			}
		})
	}
}

func TestParseEncryptionKeysSuccess(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	keys := map[string]string{
		"key-v1": hex.EncodeToString(key1),
		"key-v2": hex.EncodeToString(key2),
	}

	raw, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("failed to encode keys: %v", err)
	}

	got, err := parseEncryptionKeys(string(raw))
	if err != nil {
		t.Fatalf("failed to parse keys: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected nums of keys: %v, got: %v", 2, len(got))
	}

	if !bytes.Equal(got["key-v1"], key1) {
		t.Fatalf("expected key1: %v, got: %v", key1, got["key-v1"])
	}

	if !bytes.Equal(got["key-v2"], key2) {
		t.Fatalf("expected key2: %v, got: %v", key2, got["key-v2"])
	}
}

type testParseKeys struct {
	name string
	raw  string
}

func TestParseEncryptInvalid(t *testing.T) {
	cases := []testParseKeys{
		{
			name: "empty string",
			raw:  "",
		},
		{
			name: "incorrect json",
			raw:  "{",
		},
		{
			name: "empty json",
			raw:  "{}",
		},
		{
			name: "null",
			raw:  "null",
		},
		{
			name: "[]",
			raw:  "[]",
		},
		{
			name: "wrong value",
			raw:  `{"key-v1":123}`,
		},
		{
			name: "empty ID with valid key",
			raw:  fmt.Sprintf(`{"":"%s"}`, strings.Repeat("ab", 32)),
		},
		{
			name: "invalid hex",
			raw:  `{"key-v1":"zz"}`,
		},
		{
			name: "len = 31",
			raw:  fmt.Sprintf(`{"key-v1":"%s"}`, strings.Repeat("ab", 31)),
		},
		{
			name: "len = 33",
			raw:  fmt.Sprintf(`{"key-v1":"%s"}`, strings.Repeat("ab", 33)),
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			m, err := parseEncryptionKeys(testcase.raw)
			if err == nil {
				t.Fatalf("expected non-nil error")
			}

			if m != nil {
				t.Fatalf("expected nil map")
			}
		})
	}
}
