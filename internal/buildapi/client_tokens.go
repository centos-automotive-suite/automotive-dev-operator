package buildapi

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const (
	clientTokenPrefix = "ado-build-api-client-"
	clientTokenExpiry = 30 * 24 * time.Hour
)

// oidcAuthResult represents the result of OIDC authentication attempt
type oidcAuthResult struct {
	username string
	ok       bool
	err      error
}

func (a *APIServer) authenticateExternalJWT(c *gin.Context, token string, authn authenticator.Token) oidcAuthResult {
	resp, ok, err := authn.AuthenticateToken(c.Request.Context(), token)
	if err != nil {
		a.log.Error(err, "OIDC token validation failed")
		return oidcAuthResult{err: err}
	}
	if !ok || resp == nil || resp.User == nil {
		return oidcAuthResult{ok: false}
	}
	username := strings.TrimSpace(resp.User.GetName())
	if username == "" {
		return oidcAuthResult{ok: false}
	}
	return oidcAuthResult{username: username, ok: true}
}

func (a *APIServer) ensureClientTokenSecret(c *gin.Context, username string, oidcToken string) error {
	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		return err
	}
	secretName := clientTokenPrefix + hashName(username)
	key := types.NamespacedName{Name: secretName, Namespace: resolveNamespace()}

	// Generate internal JWT token
	internalToken, expiresAt, err := a.signClientToken(username)
	if err != nil {
		return err
	}

	existing := &corev1.Secret{}
	if err := k8sClient.Get(c.Request.Context(), key, existing); err == nil {
		// Secret exists, update it with new OIDC token and internal token
		existing.StringData = map[string]string{
			"token":      internalToken,
			"oidc-token": oidcToken, // Store the OIDC token
			"username":   username,
			"issuer":     a.internalJWT.issuer,
			"audience":   a.internalJWT.audience,
			"expires-at": expiresAt.Format(time.RFC3339),
		}
		return k8sClient.Update(c.Request.Context(), existing)
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Create new secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: resolveNamespace(),
			Labels: map[string]string{
				"app.kubernetes.io/name":                        "automotive-dev-operator",
				"app.kubernetes.io/component":                   "build-api",
				"automotive.sdv.cloud.redhat.com/resource-type": "client-token",
			},
			Annotations: map[string]string{
				"automotive.sdv.cloud.redhat.com/username": username,
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"token":      internalToken,
			"oidc-token": oidcToken, // Store the OIDC token from SSO login
			"username":   username,
			"issuer":     a.internalJWT.issuer,
			"audience":   a.internalJWT.audience,
			"expires-at": expiresAt.Format(time.RFC3339),
		},
	}
	return k8sClient.Create(c.Request.Context(), secret)
}

func (a *APIServer) signClientToken(username string) (string, time.Time, error) {
	if a.internalJWT == nil {
		return "", time.Time{}, fmt.Errorf("internal JWT is not configured")
	}

	expiresAt := time.Now().Add(clientTokenExpiry)
	audience := a.internalJWT.audience
	if audience == "" {
		audience = "ado-build-api"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    a.internalJWT.issuer,
		Subject:   username,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	})
	signed, err := token.SignedString(a.internalJWT.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign client token: %w", err)
	}
	return signed, expiresAt, nil
}

func hashName(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}
