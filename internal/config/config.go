package config

import (
	"encoding/hex"
	"errors"
	"os"
)

type Config struct {
	HTTPAddr      string
	DatabaseURL   string
	EncryptionKey []byte
	KeyID         string
	APIToken      string
}

func Load() (Config, error) {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}

	keyID := os.Getenv("KEY_ID")
	if keyID == "" {
		return Config{}, errors.New("KEY_ID is required")
	}

	encKey := os.Getenv("ENCRYPTION_KEY")
	if encKey == "" {
		return Config{}, errors.New("ENCRYPTION_KEY is required")
	}

	key, err := hex.DecodeString(encKey)
	if err != nil {
		return Config{}, errors.New("ENCRYPTION_KEY must be valid hex")
	}

	if len(key) != 32 {
		return Config{}, errors.New("ENCRYPTION_KEY must decode to 32 bytes")
	}

	apiToken := os.Getenv("API_TOKEN")
	if apiToken == "" {
		return Config{}, errors.New("API_TOKEN is required")
	}

	return Config{
		HTTPAddr:      addr,
		DatabaseURL:   url,
		KeyID:         keyID,
		EncryptionKey: key,
		APIToken:      apiToken,
	}, nil
}
