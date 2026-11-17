package storage

import (
	"context"
	"errors"
)

var (
	ErrNotFound      = errors.New("secret not found")
	ErrAlreadyExists = errors.New("secret already exists")
)

type Store interface {
	Create(ctx context.Context, secret Secret) error
	Get(ctx context.Context, id string) (Secret, error)
	Delete(ctx context.Context, id string) error
}
