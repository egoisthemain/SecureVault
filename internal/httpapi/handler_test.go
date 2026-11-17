package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egoisthemain/SecureVault/internal/storage"
)

type stubService struct {
	createCalls int
	plaintext   []byte
	id          string
	err         error
	getCalls    int
	getID       string
	getData     []byte
	getErr      error
	deleteCalls int
	deleteID    string
	deleteErr   error
}

var _ SecretService = (*stubService)(nil)

func (s *stubService) Create(ctx context.Context, plaintext []byte) (string, error) {
	s.createCalls++
	s.plaintext = plaintext
	return s.id, s.err
}

func (s *stubService) Get(ctx context.Context, id string) ([]byte, error) {
	s.getCalls++
	s.getID = id
	return s.getData, s.getErr
}

func (s *stubService) Delete(ctx context.Context, id string) error {
	s.deleteCalls++
	s.deleteID = id

	return s.deleteErr
}

func TestCreateSecretSuccess(t *testing.T) {
	stub := &stubService{
		id: "test-id",
	}

	handler := New(stub)

	request := httptest.NewRequest(
		http.MethodPost,
		"/secrets",
		strings.NewReader(`{"value":"my-token"}`),
	)
	recorder := httptest.NewRecorder()

	handler.Routes().ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expected status: %v, got %v", http.StatusCreated, response.StatusCode)
	}

	if response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected header: %v, got %v", "application/json", response.Header.Get("Content-Type"))
	}

	var result createSecretResponse

	err := json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.ID != "test-id" {
		t.Fatalf("decode ID %q: got %q", "test-id", result.ID)
	}

	if stub.createCalls != 1 {
		t.Fatalf("expected createCalls: %v, got %v", 1, stub.createCalls)
	}

	if !bytes.Equal(stub.plaintext, []byte("my-token")) {
		t.Fatalf("expected plaintext: %v, got %v", []byte("my-token"), stub.plaintext)
	}
}

type InvalidBody struct {
	name string
	body string
}

func TestCreateSecretInvalidBody(t *testing.T) {
	cases := []InvalidBody{
		{
			name: "empty body",
			body: "",
		},
		{
			name: "not ended json",
			body: `{"value":`,
		},
		{
			name: "empty secret",
			body: `{"value":""}`,
		},
		{
			name: "no value field",
			body: "{}",
		},
		{
			name: "unknown field",
			body: `{"value":"token","extra":1}`,
		},
		{
			name: "2 json objects",
			body: `{"value":"first"} {"value":"second"}`,
		},
		{
			name: "garbage after json",
			body: `{"value":"token"} garbage`,
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			stub := &stubService{
				id: "test-id",
			}

			handler := New(stub)

			request := httptest.NewRequest(
				http.MethodPost,
				"/secrets",
				strings.NewReader(testcase.body),
			)
			recorder := httptest.NewRecorder()

			handler.createSecret(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected status: %v, got %v", http.StatusBadRequest, response.StatusCode)
			}

			if stub.createCalls != 0 {
				t.Fatalf("expected createCalls: %v, got %v", 0, stub.createCalls)
			}
		})
	}
}

func TestCreateSecretBodyTooLarge(t *testing.T) {
	cases := []InvalidBody{
		{
			name: "large json",
			body: `{"value":"` + strings.Repeat("a", 64*1024) + `"}`,
		},
		{
			name: "large space tail",
			body: `{"value":"token"}` + strings.Repeat(" ", 64*1024),
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			stub := &stubService{
				id: "test-id",
			}

			handler := New(stub)

			request := httptest.NewRequest(
				http.MethodPost,
				"/secrets",
				strings.NewReader(testcase.body),
			)
			recorder := httptest.NewRecorder()

			handler.createSecret(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected status: %v, got %v", http.StatusRequestEntityTooLarge, response.StatusCode)
			}

			if stub.createCalls != 0 {
				t.Fatalf("expected createCalls: %v, got %v", 0, stub.createCalls)
			}
		})
	}
}

func TestCreateSecretServiceError(t *testing.T) {
	stub := &stubService{
		err: errors.New("internal database failure"),
	}

	handler := New(stub)

	request := httptest.NewRequest(
		http.MethodPost,
		"/secrets",
		strings.NewReader(`{"value":"my-token"}`),
	)
	recorder := httptest.NewRecorder()

	handler.createSecret(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status: %v, got %v", http.StatusInternalServerError, response.StatusCode)
	}

	if stub.createCalls != 1 {
		t.Fatalf("expected createCalls: %v, got %v", 1, stub.createCalls)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("body read error: %v", err)
	}

	if !bytes.Equal(body, []byte("failed to create secret\n")) {
		t.Fatalf("expected body: %v, got %v", []byte("failed to create secret\n"), body)
	}
}

func TestGetSecretSuccess(t *testing.T) {
	stub := &stubService{
		getData: []byte("my-token"),
	}

	handler := New(stub)

	request := httptest.NewRequest(
		http.MethodGet,
		"/secrets/test-id",
		nil,
	)
	recorder := httptest.NewRecorder()

	handler.Routes().ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status: %v, got %v", http.StatusOK, response.StatusCode)
	}

	if response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected header: %v, got %v", "application/json", response.Header.Get("Content-Type"))
	}

	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("expected header: %v, got %v", "no-store", response.Header.Get("Cache-Control"))
	}

	var result getSecretResponse

	err := json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.Value != "my-token" {
		t.Fatalf("expected value: %v, got %v", "my-token", result.Value)
	}

	if stub.getCalls != 1 {
		t.Fatalf("expected getCalls: %v, got %v", 1, stub.getCalls)
	}

	if stub.getID != "test-id" {
		t.Fatalf("expected id: %v, got %v", "test-id", stub.getID)
	}
}

type getError struct {
	name   string
	getErr error
	status int
	body   string
}

func TestGetSecretErrors(t *testing.T) {
	cases := []getError{
		{
			name:   "ErrNotFound",
			getErr: storage.ErrNotFound,
			status: http.StatusNotFound,
			body:   "secret not found\n",
		},
		{
			name:   "internal database failure",
			getErr: errors.New("internal database failure"),
			status: http.StatusInternalServerError,
			body:   "failed to get secret\n",
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			stub := &stubService{
				getErr: testcase.getErr,
			}

			handler := New(stub)

			request := httptest.NewRequest(
				http.MethodGet,
				"/secrets/test-id",
				nil,
			)
			recorder := httptest.NewRecorder()

			handler.Routes().ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != testcase.status {
				t.Fatalf("expected status: %v, got %v", testcase.status, response.StatusCode)
			}

			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("expected header: %v, got %v", "no-store", response.Header.Get("Cache-Control"))
			}

			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("body read error: %v", err)
			}

			if !bytes.Equal(body, []byte(testcase.body)) {
				t.Fatalf("expected body: %v, got %v", testcase.body, string(body))
			}

			if stub.getCalls != 1 {
				t.Fatalf("expected getCalls: %v, got %v", 1, stub.getCalls)
			}

			if stub.getID != "test-id" {
				t.Fatalf("expected id: %v, got %v", "test-id", stub.getID)
			}
		})
	}
}

type deleteError struct {
	name      string
	deleteErr error
	status    int
	body      string
}

func TestDeleteSecret(t *testing.T) {
	cases := []deleteError{
		{
			name:      "no error",
			deleteErr: nil,
			status:    http.StatusNoContent,
			body:      "",
		},
		{
			name:      "ErrNotFound",
			deleteErr: storage.ErrNotFound,
			status:    http.StatusNotFound,
			body:      "secret not found\n",
		},
		{
			name:      "internal database failure",
			deleteErr: errors.New("internal database failure"),
			status:    http.StatusInternalServerError,
			body:      "failed to delete secret\n",
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			stub := &stubService{
				deleteErr: testcase.deleteErr,
			}

			handler := New(stub)

			request := httptest.NewRequest(
				http.MethodDelete,
				"/secrets/test-id",
				nil,
			)
			recorder := httptest.NewRecorder()

			handler.Routes().ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != testcase.status {
				t.Fatalf("expected status: %v, got %v", testcase.status, response.StatusCode)
			}

			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("body read error: %v", err)
			}

			if !bytes.Equal(body, []byte(testcase.body)) {
				t.Fatalf("expected body: %v, got %v", testcase.body, string(body))
			}

			if stub.deleteCalls != 1 {
				t.Fatalf("expected deleteCalls: %v, got %v", 1, stub.deleteCalls)
			}

			if stub.deleteID != "test-id" {
				t.Fatalf("expected id: %v, got %v", "test-id", stub.deleteID)
			}
		})
	}
}
