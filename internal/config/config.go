package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/egoisthemain/SecureVault/internal/cryptography"
)

type Config struct {
	HTTPAddr       string
	DatabaseURL    string
	EncryptionKeys map[string][]byte
	KeyID          string
	APIToken       string
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

	encKeys := os.Getenv("ENCRYPTION_KEYS")
	if encKeys == "" {
		return Config{}, errors.New("ENCRYPTION_KEYS is required")
	}

	keys, err := parseEncryptionKeys(encKeys)
	if err != nil {
		return Config{}, err
	}

	if _, ok := keys[keyID]; !ok {
		return Config{}, errors.New("KEY_ID must reference an existing encryption key")
	}

	apiToken := os.Getenv("API_TOKEN")
	if apiToken == "" {
		return Config{}, errors.New("API_TOKEN is required")
	}

	return Config{
		HTTPAddr:       addr,
		DatabaseURL:    url,
		KeyID:          keyID,
		EncryptionKeys: keys,
		APIToken:       apiToken,
	}, nil
}

func parseEncryptionKeys(raw string) (map[string][]byte, error) {
	m := make(map[string]string)
	err := json.Unmarshal([]byte(raw), &m)
	if err != nil {
		return nil, errors.New("ENCRYPTION_KEYS must be a JSON object with hex string values")
	}
	if len(m) == 0 {
		return nil, errors.New("ENCRYPTION_KEYS must not be empty")
	}

	res := make(map[string][]byte)

	for keyID, key := range m {
		if keyID == "" {
			return nil, cryptography.ErrInvalidKeyID
		}

		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, errors.New("ENCRYPTION_KEY must be valid hex")
		}

		if len(keyBytes) != 32 {
			return nil, cryptography.ErrInvalidKeyLength
		}

		res[keyID] = keyBytes
	}

	return res, nil
}
