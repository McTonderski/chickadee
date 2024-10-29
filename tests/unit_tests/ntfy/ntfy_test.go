package ntfyclient

import (
	"github.com/AnthonyHewins/gotfy"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"AutomaticCVEResolver/services/ntfy" // Correct import
	"github.com/stretchr/testify/assert"
)

// Mock the HTTP client using httptest
func mockHTTPClient(statusCode int, responseBody string) (*httptest.Server, *http.Client) {
	// Create a mock HTTP server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(responseBody))
	}))

	// Create a custom HTTP client that will use the mock server
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(mockServer.URL)
			},
		},
		Timeout: 5 * time.Second,
	}

	return mockServer, client
}

// Test SendMessage function with a successful response
func TestSendMessage_Success(t *testing.T) {
	// Mock the HTTP server and client
	server, client := mockHTTPClient(http.StatusOK, `{"id": "1234", "topic": "matt_test", "message": "Test Message"}`)
	defer server.Close()

	// Use the constructor to create a NtfyClient
	ntfy, err := ntfyclient.NewNtfyClient(
		server.URL,
		"matt_test",
		"matt",
		"Kwiecien26@",
		5*time.Second,
	)
	assert.NoError(t, err)

	// Use the setter method to override the HTTP client with the mocked one
	ntfy.SetHTTPClient(client)

	// Test SendMessage
	resp, err := ntfy.SendMessage("Test Message", "Test Title")

	// Assert no errors and check the response
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "1234", resp.ID)
}

// Test SendMessage function with an error response (e.g., 500 Internal Server Error)
func TestSendMessage_Error(t *testing.T) {
	// Mock the HTTP server and client
	server, client := mockHTTPClient(http.StatusInternalServerError, `Internal Server Error`)
	defer server.Close()

	// Use the constructor to create a NtfyClient
	ntfy, err := ntfyclient.NewNtfyClient(
		server.URL,
		"matt_test",
		"matt",
		"Kwiecien26@",
		5*time.Second,
	)
	assert.NoError(t, err)

	// Use the setter method to override the HTTP client with the mocked one
	ntfy.SetHTTPClient(client)

	// Test SendMessage
	resp, err := ntfy.SendMessage("Test Message", "Test Title")

	// Assert error and check that response is nil
	assert.Error(t, err)
	assert.Nil(t, resp)
}

// Test SendMessageAsync function with a successful response
func TestSendMessageAsync_Success(t *testing.T) {
	// Mock the HTTP server and client
	server, client := mockHTTPClient(http.StatusOK, `{"id": "1234", "topic": "matt_test", "message": "Test Message"}`)
	defer server.Close()

	// Use the constructor to create a NtfyClient
	ntfy, err := ntfyclient.NewNtfyClient(
		server.URL,
		"matt_test",
		"matt",
		"Kwiecien26@",
		5*time.Second,
	)
	assert.NoError(t, err)

	// Override the HTTP client with the mocked one
	ntfy.SetHTTPClient(client)

	// Create channels to capture async results
	resultChan := make(chan *gotfy.PublishResp, 1)
	errorChan := make(chan error, 1)

	// Test SendMessageAsync
	ntfy.SendMessageAsync("Test Message", "Test Title", resultChan, errorChan)

	// Wait for the result or error
	select {
	case resp := <-resultChan:
		// Assert success and check the response
		assert.NotNil(t, resp)
		assert.Equal(t, "1234", resp.ID)
	case err := <-errorChan:
		t.Fatalf("Expected no error, but got %v", err)
	}
}

// Test SendMessageAsync function with an error response
func TestSendMessageAsync_Error(t *testing.T) {
	// Mock the HTTP server and client
	server, client := mockHTTPClient(http.StatusInternalServerError, `Internal Server Error`)
	defer server.Close()

	// Use the constructor to create a NtfyClient
	ntfy, err := ntfyclient.NewNtfyClient(
		server.URL,
		"matt_test",
		"matt",
		"Kwiecien26@",
		5*time.Second,
	)
	assert.NoError(t, err)

	// Override the HTTP client with the mocked one
	ntfy.SetHTTPClient(client)

	// Create channels to capture async results
	resultChan := make(chan *gotfy.PublishResp, 1)
	errorChan := make(chan error, 1)

	// Test SendMessageAsync
	ntfy.SendMessageAsync("Test Message", "Test Title", resultChan, errorChan)

	// Wait for the result or error
	select {
	case resp := <-resultChan:
		t.Fatalf("Expected error, but got successful response: %v", resp)
	case err := <-errorChan:
		// Assert that an error was returned
		assert.Error(t, err)
	}
}
