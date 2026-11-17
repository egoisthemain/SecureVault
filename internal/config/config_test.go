package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoadSuccess(t *testing.T) {
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("DATABASE_URL", "postgres://test-user:test-pass@localhost/test-db")
	t.Setenv("KEY_ID", "test-key")
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("ab", 32))
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

	if !bytes.Equal(cfg.EncryptionKey, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("expected EncryptionKey: %v, got: %v", strings.Repeat("ab", 32), cfg.EncryptionKey)
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
			encKey:   strings.Repeat("ab", 32),
			apiToken: "api-token",
			wantErr:  "DATABASE_URL is required",
		},
		{
			name:     "no keyID",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "",
			encKey:   strings.Repeat("ab", 32),
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
			wantErr:  "ENCRYPTION_KEY is required",
		},
		{
			name:     "no apiToken",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   strings.Repeat("ab", 32),
			apiToken: "",
			wantErr:  "API_TOKEN is required",
		},
		{
			name:     "invalid hex",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   "zz",
			apiToken: "api-token",
			wantErr:  "ENCRYPTION_KEY must be valid hex",
		},
		{
			name:     "short EncryptionKey",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   strings.Repeat("ab", 31),
			apiToken: "api-token",
			wantErr:  "ENCRYPTION_KEY must decode to 32 bytes",
		},
		{
			name:     "long key",
			addr:     "",
			url:      "postgres://test-user:test-pass@localhost/test-db",
			keyID:    "test-key",
			encKey:   strings.Repeat("ab", 33),
			apiToken: "api-token",
			wantErr:  "ENCRYPTION_KEY must decode to 32 bytes",
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Setenv("HTTP_ADDR", testcase.addr)
			t.Setenv("DATABASE_URL", testcase.url)
			t.Setenv("KEY_ID", testcase.keyID)
			t.Setenv("ENCRYPTION_KEY", testcase.encKey)
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
