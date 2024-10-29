package ntfyclient

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/AnthonyHewins/gotfy"
	"net/http"
	"net/url"
	"time"
)

// NtfyClient holds the information needed to send messages to the Ntfy server
type NtfyClient struct {
	server   *url.URL
	topic    string
	client   *http.Client
	username string
	password string
	timeout  time.Duration // timeout for the message context
}

// NewNtfyClient initializes a new NtfyClient for a specific topic
func NewNtfyClient(serverURL, topic, username, password string, timeout time.Duration) (*NtfyClient, error) {
	// Parse the server URL
	server, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}

	// Create the HTTP client with Basic Authentication
	client := createHTTPClientWithBasicAuth(username, password)

	// Return the initialized NtfyClient with the provided timeout
	return &NtfyClient{
		server:   server,
		topic:    topic,
		client:   client,
		username: username,
		password: password,
		timeout:  timeout,
	}, nil
}

// Define an interface that can be implemented by NtfyClient
type NtfyService interface {
	SendMessage(message, title string) (*gotfy.PublishResp, error)
	SendMessageAsync(message, title string, resultChan chan<- *gotfy.PublishResp, errorChan chan<- error)
}

// Ensure NtfyClient implements the NtfyService interface
var _ NtfyService = &NtfyClient{}

// SendMessage sends a message to the configured topic
// Automatically handles context creation and timeout
func (nc *NtfyClient) SendMessage(message, title string) (*gotfy.PublishResp, error) {
	if nc.topic == "" {
		return nil, errors.New("topic is not set")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), nc.timeout)
	defer cancel()

	// Create the Publisher
	tp, err := gotfy.NewPublisher(nc.server, nc.client)
	if err != nil {
		return nil, err
	}

	// Send the message to the topic
	pubResp, err := tp.SendMessage(ctx, &gotfy.Message{
		Topic:   nc.topic,
		Message: message,
		Title:   title,
	})
	if err != nil {
		return nil, err
	}

	return pubResp, nil
}

// SendMessageAsync runs SendMessage in a goroutine and sends the result to a channel
func (nc *NtfyClient) SendMessageAsync(message, title string, resultChan chan<- *gotfy.PublishResp, errorChan chan<- error) {
	go func() {
		resp, err := nc.SendMessage(message, title)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- resp
	}()
}

// Helper function to create a custom HTTP client with Basic Authentication
func createHTTPClientWithBasicAuth(username, password string) *http.Client {
	auth := username + ":" + password
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	// Create a custom HTTP Client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Wrap the Transport to add the Authorization header to each request
	client.Transport = roundTripperWithAuth(http.DefaultTransport, authHeader)
	return client
}

// Custom roundtripper that injects the Authorization header
func roundTripperWithAuth(rt http.RoundTripper, authHeader string) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("Authorization", authHeader)
		return rt.RoundTrip(req)
	})
}

// RoundTripperFunc allows us to wrap the HTTP transport
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
func (nc *NtfyClient) SetHTTPClient(client *http.Client) {
	nc.client = client
}
