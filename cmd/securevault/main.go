package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/egoisthemain/SecureVault/internal/config"
	"github.com/egoisthemain/SecureVault/internal/cryptography"
	"github.com/egoisthemain/SecureVault/internal/httpapi"
	"github.com/egoisthemain/SecureVault/internal/service"
	"github.com/egoisthemain/SecureVault/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	err = pool.Ping(ctx)
	if err != nil {
		return err
	}

	log.Print("database connection established")

	keyring, err := cryptography.NewKeyring(cfg.KeyID, cfg.EncryptionKeys)
	if err != nil {
		return err
	}

	store := storage.NewPostgres(pool)

	svc := service.New(store, keyring)

	handler := httpapi.New(svc)

	server := http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpapi.RequireToken(cfg.APIToken, handler.Routes()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-signalCtx.Done():
		log.Print("shutdown signal received")
		stop()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		err = server.Shutdown(shutdownCtx)
		if err != nil {
			log.Printf("HTTP shutdown failed: %v", err)
			server.Close()
			return err
		}

		log.Print("HTTP shutdown completed")
		err = <-serverErr
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}

}

func main() {
	err := run()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	log.Print("application stopped cleanly")
}
