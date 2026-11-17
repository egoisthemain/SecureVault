package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type testToken struct {
	name      string
	token     string
	auth      string
	status    int
	wantCalls int
}

func TestRequireToken(t *testing.T) {
	cases := []testToken{
		{
			name:      "Bearer test-token",
			token:     "test-token",
			auth:      "Bearer test-token",
			status:    http.StatusNoContent,
			wantCalls: 1,
		},
		{
			name:      "bearer test-token",
			token:     "test-token",
			auth:      "bearer test-token",
			status:    http.StatusNoContent,
			wantCalls: 1,
		},
		{
			name:      "empty header",
			token:     "test-token",
			auth:      "",
			status:    http.StatusUnauthorized,
			wantCalls: 0,
		},
		{
			name:      "Bearer",
			token:     "test-token",
			auth:      "Bearer",
			status:    http.StatusUnauthorized,
			wantCalls: 0,
		},
		{
			name:      "Basic test-token",
			token:     "test-token",
			auth:      "Basic test-token",
			status:    http.StatusUnauthorized,
			wantCalls: 0,
		},
		{
			name:      "Bearer wrong-token",
			token:     "test-token",
			auth:      "Bearer wrong-token",
			status:    http.StatusUnauthorized,
			wantCalls: 0,
		},
		{
			name:      "Bearer test-token extra",
			token:     "test-token",
			auth:      "Bearer test-token extra",
			status:    http.StatusUnauthorized,
			wantCalls: 0,
		},
		{
			name:      "empty token",
			token:     "",
			auth:      "Bearer test-token",
			status:    http.StatusUnauthorized,
			wantCalls: 0,
		},
	}

	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			calls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			})

			protected := RequireToken(testcase.token, next)

			request := httptest.NewRequest(
				http.MethodGet,
				"/secrets/test-id",
				nil,
			)

			if testcase.auth != "" {
				request.Header.Set("Authorization", testcase.auth)
			}

			recorder := httptest.NewRecorder()
			protected.ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != testcase.status {
				t.Fatalf("expected status %d, got %d",
					testcase.status, response.StatusCode)
			}

			if calls != testcase.wantCalls {
				t.Fatalf("expected %d calls, got %d", testcase.wantCalls, calls)
			}

			if testcase.status == http.StatusUnauthorized {
				if response.Header.Get("WWW-Authenticate") != "Bearer" {
					t.Fatal("expected WWW-Authenticate: Bearer")
				}
			}
		})
	}
}
