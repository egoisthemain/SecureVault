package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/egoisthemain/SecureVault/internal/storage"
)

type SecretService interface {
	Create(ctx context.Context, plaintext []byte) (string, error)
	Get(ctx context.Context, id string) ([]byte, error)
	Delete(ctx context.Context, id string) error
}

type Handler struct {
	service SecretService
}

type createSecretRequest struct {
	Value string `json:"value"`
}

type createSecretResponse struct {
	ID string `json:"id"`
}

type getSecretResponse struct {
	Value string `json:"value"`
}

func New(service SecretService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) createSecret(w http.ResponseWriter, r *http.Request) {
	var request createSecretRequest
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	err := decoder.Decode(&request)
	if err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if request.Value == "" {
		http.Error(w, "value must not be empty", http.StatusBadRequest)
		return
	}

	var extra any
	err = decoder.Decode(&extra)
	if err != io.EOF {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	id, err := h.service.Create(r.Context(), []byte(request.Value))
	if err != nil {
		http.Error(w, "failed to create secret", http.StatusInternalServerError)
		return
	}

	secretJSON, err := json.Marshal(createSecretResponse{ID: id})
	if err != nil {
		http.Error(w, "failed marshaling", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusCreated)

	_, err = w.Write(secretJSON)
	if err != nil {
		return
	}
}

func (h *Handler) getSecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	id := r.PathValue("id")

	secret, err := h.service.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get secret", http.StatusInternalServerError)
		return
	}

	getResponse, err := json.Marshal(getSecretResponse{Value: string(secret)})
	if err != nil {
		http.Error(w, "failed marshaling", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(getResponse)
	if err != nil {
		return
	}
}

func (h *Handler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	err := h.service.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to delete secret", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /secrets", h.createSecret)
	mux.HandleFunc("GET /secrets/{id}", h.getSecret)
	mux.HandleFunc("DELETE /secrets/{id}", h.deleteSecret)

	return mux
}
