package featuregates

import "testing"

func TestWebhookNotificationsDefaultsDisabled(t *testing.T) {
	if !Known(WebhookNotifications) || DefaultStage(WebhookNotifications) != Alpha {
		t.Fatal("WebhookNotifications should be registered as Alpha")
	}
	if New(nil).Enabled(WebhookNotifications) {
		t.Fatal("WebhookNotifications should be disabled by default")
	}
}
