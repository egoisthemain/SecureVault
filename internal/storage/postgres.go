package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{
		pool: pool,
	}
}

var _ Store = (*Postgres)(nil)

func (p *Postgres) Create(ctx context.Context, secret Secret) error {
	query := `
		INSERT INTO secrets (id, ciphertext, nonce, key_id, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := p.pool.Exec(ctx, query,
		secret.ID, secret.Ciphertext, secret.Nonce,
		secret.KeyID, secret.CreatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" && pgErr.ConstraintName == "secrets_pkey" {
				return ErrAlreadyExists
			}
		}
		return err
	}

	return nil
}

func (p *Postgres) Get(ctx context.Context, id string) (Secret, error) {
	query := `
		SELECT id, ciphertext, nonce, key_id, created_at
		FROM secrets
		WHERE id = $1
	`
	var secret Secret
	err := p.pool.QueryRow(ctx, query, id).Scan(&secret.ID, &secret.Ciphertext, &secret.Nonce, &secret.KeyID, &secret.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Secret{}, ErrNotFound
		}
		return Secret{}, err
	}

	return secret, nil
}

func (p *Postgres) Delete(ctx context.Context, id string) error {
	query := `
		DELETE FROM secrets
		WHERE id = $1
	`
	tag, err := p.pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
