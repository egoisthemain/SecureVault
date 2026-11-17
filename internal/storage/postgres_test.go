package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresConnection(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("error of creating pool: %v", err)
	}
	t.Cleanup(pool.Close)

	err = pool.Ping(ctx)
	if err != nil {
		t.Fatalf("error of connection to pool: %v", err)
	}
}

func TestPostgresCreateGet(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("error of creating pool: %v", err)
	}
	t.Cleanup(pool.Close)

	var secret = Secret{
		ID:         fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Ciphertext: []byte{0x01, 0x02, 0xff, 0x00},
		Nonce: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b},
		KeyID:     "test-key",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}

	p := NewPostgres(pool)

	err = p.Create(ctx, secret)
	if err != nil {
		t.Fatalf("error of create an entry: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := p.Delete(cleanupCtx, secret.ID)
		if err != nil {
			t.Errorf("error of delete entry: %v", err)
		}
	})

	secretGet, err := p.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("error of getting an entry: %v", err)
	}

	if secret.ID != secretGet.ID {
		t.Fatalf("expected secret = %v, got %v", secret, secretGet)
	}
	if !bytes.Equal(secret.Ciphertext, secretGet.Ciphertext) {
		t.Fatalf("expected secret = %v, got %v", secret, secretGet)
	}
	if !bytes.Equal(secret.Nonce, secretGet.Nonce) {
		t.Fatalf("expected secret = %v, got %v", secret, secretGet)
	}
	if secret.KeyID != secretGet.KeyID {
		t.Fatalf("expected secret = %v, got %v", secret, secretGet)
	}
	if !time.Time.Equal(secret.CreatedAt, secretGet.CreatedAt) {
		t.Fatalf("expected secret = %v, got %v", secret, secretGet)
	}
}

func TestPostgresCreateDuplicate(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("error of creating pool: %v", err)
	}
	t.Cleanup(pool.Close)

	var secret = Secret{
		ID:         fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Ciphertext: []byte{0x01, 0x02, 0xff, 0x00},
		Nonce: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b},
		KeyID:     "test-key",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}

	p := NewPostgres(pool)

	err = p.Create(ctx, secret)
	if err != nil {
		t.Fatalf("error of create an entry: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := p.Delete(cleanupCtx, secret.ID)
		if err != nil {
			t.Errorf("error of delete entry: %v", err)
		}
	})

	duplicate := secret
	duplicate.KeyID = "another-key"

	err = p.Create(ctx, duplicate)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("must be duplicate error, got: %v", err)
	}

	secretGet, err := p.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("error of getting an entry: %v", err)
	}

	if secret.KeyID != secretGet.KeyID {
		t.Fatalf("expected keyID: %v, got: %v", secret.KeyID, secretGet.KeyID)
	}
}

func TestPostgresDelete(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("error of creating pool: %v", err)
	}
	t.Cleanup(pool.Close)

	var secret = Secret{
		ID:         fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Ciphertext: []byte{0x01, 0x02, 0xff, 0x00},
		Nonce: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b},
		KeyID:     "test-key",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}

	p := NewPostgres(pool)

	err = p.Create(ctx, secret)
	if err != nil {
		t.Fatalf("error of create an entry: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := p.Delete(cleanupCtx, secret.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup secret: %v", err)
		}
	})

	err = p.Delete(ctx, secret.ID)
	if err != nil {
		t.Fatalf("error delete an entry: %v", err)
	}

	_, err = p.Get(ctx, secret.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	err = p.Delete(ctx, secret.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}
