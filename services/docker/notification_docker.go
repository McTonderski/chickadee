package docker

import (
	ntfyclient "AutomaticCVEResolver/services/ntfy"
	"fmt"
)

// NotificationService is a service that sends notifications using NtfyClient
type NotificationService struct {
	ntfy ntfyclient.NtfyService
}

// NewNotificationService creates a new NotificationService
func NewNotificationService(ntfy ntfyclient.NtfyService) *NotificationService {
	return &NotificationService{
		ntfy: ntfy,
	}
}

// SendNotification sends a notification using the Ntfy client
func (s *NotificationService) SendNotification(message, title string) error {
	// Send the message using NtfyClient's SendMessage method
	resp, err := s.ntfy.SendMessage(message, title)
	if err != nil {
		return fmt.Errorf("failed to send notification: %v", err)
	}

	fmt.Printf("Notification sent successfully: %+v\n", resp)
	return nil
}
