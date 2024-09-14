package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-api-key"}},
			expectedKey:   "test-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header - Missing ApiKey",
			headers:       http.Header{"Authorization": []string{"test-api-key"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed Authorization Header - Empty ApiKey",
			headers:       http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey:   "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("Expected key %q, got %q", tt.expectedKey, key)
			}

			if (err == nil) != (tt.expectedError == nil) {
				t.Errorf("Expected error %v, got %v", tt.expectedError, err)
			} else if err != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("Expected error message %q, got %q", tt.expectedError.Error(), err.Error())
			}
		})
	}
}
