package buildapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
	"github.com/gin-gonic/gin"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	MaxOperationRequestBytes = 4 * 1024 * 1024
	MaxCallbackURLBytes      = 2048
	MaxExternalIDBytes       = 512
)

func validBoundedText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func validateOperationMetadata(externalID string, callback *BuildCallback) error {
	if !validBoundedText(externalID, MaxExternalIDBytes, true) {
		return errors.New("externalId exceeds its size limit or contains control characters")
	}
	if callback == nil {
		return nil
	}
	u, err := url.Parse(callback.URL)
	if err != nil || !validBoundedText(callback.URL, MaxCallbackURLBytes, false) || strings.Contains(callback.URL, " ") ||
		(u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("callback.url must be an HTTP or HTTPS URL without userinfo or a fragment")
	}
	if len(callback.Secret) > base64.StdEncoding.EncodedLen(4096) {
		return errors.New("callback.secret exceeds its size limit")
	}
	secret, err := base64.StdEncoding.Strict().DecodeString(callback.Secret)
	if err != nil || len(secret) < 32 || len(secret) > 4096 {
		return errors.New("callback.secret must encode 32 to 4096 random bytes as base64")
	}
	return nil
}

func validateCallbackPolicy(config *automotivev1alpha1.OperatorConfig, callback *BuildCallback) error {
	if callback == nil {
		return nil
	}
	if config == nil || !featuregates.NewFromConfig(&config.Spec).Enabled(featuregates.WebhookNotifications) {
		return errors.New("webhook notifications are disabled")
	}
	u, err := url.Parse(callback.URL)
	if err != nil || u == nil {
		return errors.New("callback.url must be an HTTP or HTTPS URL without userinfo or a fragment")
	}
	if u.Scheme == "http" && (config.Spec.WebhookNotifications == nil || !config.Spec.WebhookNotifications.AllowHTTP) {
		return errors.New("callback.url must use HTTPS unless webhookNotifications.allowHTTP is enabled")
	}
	return nil
}

func validateCallbackAdmission(
	ctx context.Context,
	k8sClient client.Client,
	namespace string,
	callback *BuildCallback,
) *httpError {
	if callback == nil {
		return nil
	}
	config, err := loadOperatorConfigFn(ctx, k8sClient, namespace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return &httpError{code: http.StatusBadRequest, message: "webhook notifications are disabled"}
		}
		return &httpError{code: http.StatusInternalServerError, message: "failed to load webhook notification policy"}
	}
	if err := validateCallbackPolicy(config, callback); err != nil {
		return &httpError{code: http.StatusBadRequest, message: err.Error()}
	}
	return nil
}

func bindOperationRequest(c *gin.Context, req any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, MaxOperationRequestBytes))
	if err == nil {
		err = json.Unmarshal(body, req)
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "operation request exceeds 4 MiB", "code": "RequestTooLarge"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request", "code": "InvalidRequest"})
		}
		return false
	}
	return true
}
