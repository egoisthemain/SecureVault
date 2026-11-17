package storage

import "time"

type Secret struct {
	ID         string
	Ciphertext []byte
	Nonce      []byte
	KeyID      string
	CreatedAt  time.Time
}
