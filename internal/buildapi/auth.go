package buildapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	watchpkg "k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (a *APIServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, authType, authErr := a.authenticateRequest(c)
		if authErr != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"reason":  authErr.Reason,
				"details": authErr.Details,
			})
			c.Abort()
			return
		}
		if username != "" {
			c.Set("requester", username)
			c.Set("authType", authType)
		}
		c.Next()
	}
}

// refreshAuthConfigIfNeeded is a safety net for when the background watcher is down.
// Throttles to once per 5 minutes to keep hot paths fast.
func (a *APIServer) refreshAuthConfigIfNeeded() {
	a.authConfigMu.Lock()
	if time.Since(a.lastAuthConfigCheck) < 5*time.Minute {
		a.authConfigMu.Unlock()
		return
	}
	a.lastAuthConfigCheck = time.Now()
	a.authConfigMu.Unlock()

	_ = a.doRefreshAuthConfig()
}

// caRef identifies a Secret or ConfigMap referenced as a CA certificate by a JWT issuer.
type caRef struct {
	namespace   string
	name        string
	isConfigMap bool
}

// caRefsFromConfig returns all CA Secret/ConfigMap refs from an already-fetched OperatorConfig.
func caRefsFromConfig(operatorConfig *automotivev1alpha1.OperatorConfig, defaultNamespace string) []caRef {
	if operatorConfig.Spec.BuildAPI == nil || operatorConfig.Spec.BuildAPI.Authentication == nil {
		return nil
	}

	var refs []caRef
	for _, cfg := range operatorConfig.Spec.BuildAPI.Authentication.JWT {
		issuer := cfg.Issuer
		if issuer.CertificateAuthoritySecret != nil {
			ns := issuer.CertificateAuthoritySecret.Namespace
			if ns == "" {
				ns = defaultNamespace
			}
			refs = append(refs, caRef{namespace: ns, name: issuer.CertificateAuthoritySecret.Name})
		}
		if issuer.CertificateAuthorityConfigMap != nil {
			ns := issuer.CertificateAuthorityConfigMap.Namespace
			if ns == "" {
				ns = defaultNamespace
			}
			refs = append(refs, caRef{namespace: ns, name: issuer.CertificateAuthorityConfigMap.Name, isConfigMap: true})
		}
	}
	return refs
}

// startResourceWatcher watches OperatorConfig and all referenced CA Secrets/ConfigMaps.
// On any change it refreshes the auth config and restarts the session to pick up updated refs.
func (a *APIServer) startResourceWatcher(ctx context.Context) {
	watchClient, err := getWatchClient()
	if err != nil {
		a.log.Error(err, "failed to create watch client, resource watches disabled")
		return
	}

	caRefs := a.doRefreshAuthConfig()

	for {
		if ctx.Err() != nil {
			return
		}

		sessionCtx, cancelSession := context.WithCancel(ctx)
		eventCh := make(chan struct{}, 1)

		namespace := resolveNamespace()
		go a.watchOperatorConfigSession(sessionCtx, watchClient, namespace, eventCh)

		for _, ref := range caRefs {
			go a.watchCARefSession(sessionCtx, watchClient, ref, eventCh)
		}

		select {
		case <-ctx.Done():
			cancelSession()
			return
		case <-eventCh:
			cancelSession()
			caRefs = a.doRefreshAuthConfig()
		}
	}
}

func (a *APIServer) watchOperatorConfigSession(ctx context.Context, watchClient client.WithWatch, namespace string, eventCh chan<- struct{}) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := a.runOperatorConfigWatchOnce(ctx, watchClient, namespace, eventCh); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Error(err, "OperatorConfig watch error, reconnecting in 5s")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (a *APIServer) runOperatorConfigWatchOnce(ctx context.Context, watchClient client.WithWatch, namespace string, eventCh chan<- struct{}) error {
	watcher, err := watchClient.Watch(ctx, &automotivev1alpha1.OperatorConfigList{},
		client.InNamespace(namespace))
	if err != nil {
		return fmt.Errorf("failed to start OperatorConfig watch: %w", err)
	}
	defer watcher.Stop()

	a.log.Info("watching OperatorConfig for changes", "namespace", namespace)
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("OperatorConfig watch channel closed")
			}
			switch event.Type {
			case watchpkg.Modified, watchpkg.Deleted:
				a.log.Info("OperatorConfig changed", "event", event.Type)
				select {
				case eventCh <- struct{}{}:
				default:
				}
			case watchpkg.Error:
				return fmt.Errorf("OperatorConfig watch error event")
			}
		}
	}
}

func (a *APIServer) watchCARefSession(ctx context.Context, watchClient client.WithWatch, ref caRef, eventCh chan<- struct{}) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := a.runCARefWatchOnce(ctx, watchClient, ref, eventCh); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Error(err, "CA ref watch error, reconnecting in 5s", "name", ref.name, "namespace", ref.namespace)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (a *APIServer) runCARefWatchOnce(ctx context.Context, watchClient client.WithWatch, ref caRef, eventCh chan<- struct{}) error {
	var (
		watcher watchpkg.Interface
		err     error
		kind    = "Secret"
	)
	if ref.isConfigMap {
		kind = "ConfigMap"
		watcher, err = watchClient.Watch(ctx, &corev1.ConfigMapList{},
			client.InNamespace(ref.namespace),
			client.MatchingFields{"metadata.name": ref.name})
	} else {
		watcher, err = watchClient.Watch(ctx, &corev1.SecretList{},
			client.InNamespace(ref.namespace),
			client.MatchingFields{"metadata.name": ref.name})
	}
	if err != nil {
		return fmt.Errorf("failed to start %s watch for %s/%s: %w", kind, ref.namespace, ref.name, err)
	}
	defer watcher.Stop()

	a.log.Info("watching CA reference for changes", "kind", kind, "namespace", ref.namespace, "name", ref.name)
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("%s watch channel closed for %s/%s", kind, ref.namespace, ref.name)
			}
			switch event.Type {
			case watchpkg.Modified, watchpkg.Deleted:
				a.log.Info("CA reference changed", "kind", kind, "namespace", ref.namespace, "name", ref.name, "event", event.Type)
				select {
				case eventCh <- struct{}{}:
				default:
				}
			case watchpkg.Error:
				return fmt.Errorf("%s watch error event for %s/%s", kind, ref.namespace, ref.name)
			}
		}
	}
}

// doRefreshAuthConfig reads the OperatorConfig, resolves CA references, and atomically
// swaps the OIDC authenticator if the config changed. Returns the current CA refs so
// the caller can start watches without a second fetch; nil on error.
func (a *APIServer) doRefreshAuthConfig() []caRef {
	namespace := resolveNamespace()
	k8sClient, err := getKubernetesClient()
	if err != nil {
		a.log.Error(err, "failed to get k8s client for auth config refresh", "namespace", namespace)
		return nil
	}

	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	key := types.NamespacedName{Name: "config", Namespace: namespace}
	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer fetchCancel()
	if err := k8sClient.Get(fetchCtx, key, operatorConfig); err != nil {
		a.log.Error(err, "failed to get OperatorConfig during refresh", "namespace", namespace)
		return nil
	}

	refs := caRefsFromConfig(operatorConfig, namespace)

	// Build new config from OperatorConfig, resolving any CA references from Secrets/ConfigMaps.
	var newConfig *AuthenticationConfiguration
	if operatorConfig.Spec.BuildAPI != nil && operatorConfig.Spec.BuildAPI.Authentication != nil {
		auth := operatorConfig.Spec.BuildAPI.Authentication

		refreshCtx, refreshCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer refreshCancel()

		jwtCopy, resolveErr := toUpstreamJWTAuthenticators(refreshCtx, k8sClient, auth.JWT, namespace)
		if resolveErr != nil {
			a.log.Error(resolveErr, "failed to resolve JWT CA references during refresh, keeping existing config")
			return refs
		}

		// Ensure Prefix pointers are non-nil when Claim is set (k8s OIDC authenticator requirement).
		for i := range jwtCopy {
			if jwtCopy[i].ClaimMappings.Username.Claim != "" && jwtCopy[i].ClaimMappings.Username.Prefix == nil {
				emptyPrefix := ""
				jwtCopy[i].ClaimMappings.Username.Prefix = &emptyPrefix
			}
			if jwtCopy[i].ClaimMappings.Groups.Claim != "" && jwtCopy[i].ClaimMappings.Groups.Prefix == nil {
				emptyPrefix := ""
				jwtCopy[i].ClaimMappings.Groups.Prefix = &emptyPrefix
			}
		}

		newConfig = &AuthenticationConfiguration{
			ClientID: auth.ClientID,
			Internal: InternalAuthConfig{Prefix: "internal:"},
			JWT:      jwtCopy,
		}
		if auth.Internal != nil && auth.Internal.Prefix != "" {
			newConfig.Internal.Prefix = auth.Internal.Prefix
		}
	}

	a.authConfigMu.Lock()
	// Compare with existing config first. In the common steady-state case, avoid
	// rebuilding the authenticator entirely.
	if authConfigsEqual(a.authConfig, newConfig) {
		a.authConfigMu.Unlock()
		return refs
	}
	a.authConfigMu.Unlock()

	// Config changed - build authenticator outside lock to avoid blocking
	// concurrent requests on slow network or crypto operations.
	var authn authenticator.Token
	if newConfig != nil {
		authn, err = newJWTAuthenticator(context.Background(), *newConfig)
		if err != nil {
			a.log.Error(err, "failed to create JWT authenticator during refresh, keeping existing config")
			return refs
		}
	}

	a.authConfigMu.Lock()
	defer a.authConfigMu.Unlock()

	// Re-check under lock in case another refresh already applied the same config
	// while authenticator construction was in flight.
	if authConfigsEqual(a.authConfig, newConfig) {
		return refs
	}

	// Config changed - need to recreate authenticator
	a.log.Info("auth config changed, recreating OIDC authenticator")

	if newConfig == nil {
		a.authConfig = nil
		a.externalJWT = nil
		a.internalPrefix = ""
		return refs
	}

	// Update config fields
	a.authConfig = newConfig
	a.internalPrefix = newConfig.Internal.Prefix
	if newConfig.ClientID != "" {
		a.oidcClientID = newConfig.ClientID
	}

	a.externalJWT = authn
	return refs
}

func (a *APIServer) authenticateRequest(c *gin.Context) (string, string, *authError) {
	a.refreshAuthConfigIfNeeded()

	token := extractBearerToken(c)
	if token == "" {
		return "", "", &authError{
			Reason:  "missing_token",
			Details: "No bearer token provided. Set Authorization header with 'Bearer <token>' or use CAIB_TOKEN environment variable.",
		}
	}

	// Track which auth methods were tried for error reporting
	var authAttempts []string
	var oidcError error

	a.authConfigMu.RLock()
	internalJWT := a.internalJWT
	internalPrefix := a.internalPrefix
	externalJWT := a.externalJWT
	a.authConfigMu.RUnlock()

	if internalJWT != nil {
		authAttempts = append(authAttempts, "internal_jwt")
		if subject, ok := validateInternalJWT(token, internalJWT); ok {
			username := subject
			if internalPrefix != "" {
				username = internalPrefix + username
			}
			return username, "internal", nil
		}
	}

	if externalJWT != nil {
		authAttempts = append(authAttempts, "oidc")
		result := a.authenticateExternalJWT(c, token, externalJWT)
		if result.ok {
			if internalJWT != nil {
				if err := a.ensureClientTokenSecret(c, result.username, token); err != nil {
					a.log.Error(err, "failed to ensure client token secret", "username", result.username)
				}
			}
			return result.username, "external", nil
		}
		oidcError = result.err
	}

	// Fallback to kubeconfig TokenReview authentication
	authAttempts = append(authAttempts, "k8s_token_review")

	cfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		a.log.Error(err, "Failed to get REST config for TokenReview fallback")
		return "", "", &authError{
			Reason:  "server_error",
			Details: "Failed to initialize Kubernetes client for token validation. Check build-api logs.",
		}
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		a.log.Error(err, "Failed to create Kubernetes client for TokenReview")
		return "", "", &authError{
			Reason:  "server_error",
			Details: "Failed to create Kubernetes client for token validation. Check build-api logs.",
		}
	}

	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}
	res, err := clientset.AuthenticationV1().TokenReviews().Create(c.Request.Context(), tr, metav1.CreateOptions{})
	if err != nil {
		a.log.Error(err, "TokenReview API call failed")
		return "", "", &authError{
			Reason:  "token_review_failed",
			Details: "Failed to validate token with Kubernetes API. The token may be malformed or the server may have connectivity issues.",
		}
	}
	if res.Status.Authenticated {
		username := res.Status.User.Username
		if username == "" {
			return "", "", &authError{
				Reason:  "invalid_token",
				Details: "Token was authenticated but no username was returned.",
			}
		}
		return username, "k8s", nil
	}

	return "", "", a.buildAuthFailureError(authAttempts, oidcError, res.Status.Error)
}

func (a *APIServer) buildAuthFailureError(authAttempts []string, oidcError error, tokenReviewError string) *authError {
	oidcAttempted := false
	for _, method := range authAttempts {
		if method == "oidc" {
			oidcAttempted = true
			break
		}
	}

	// Log full error details server-side for debugging
	if tokenReviewError != "" {
		a.log.Info("TokenReview authentication failed", "error", tokenReviewError)
	}
	if oidcError != nil {
		a.log.Info("OIDC authentication failed", "error", oidcError.Error())
	}

	if !oidcAttempted {
		return &authError{
			Reason:  "invalid_token",
			Details: "Token validation failed. The token may be expired or invalid. Try 'oc login' to refresh your session, then use 'oc whoami -t' for a fresh token.",
		}
	}

	var details strings.Builder
	details.WriteString("Authentication failed. OIDC is configured on this cluster. ")

	if oidcError != nil {
		details.WriteString("OIDC: token validation failed. ")
	} else {
		details.WriteString("OIDC: token not valid for configured issuer. ")
	}

	if tokenReviewError != "" {
		details.WriteString("Kubernetes fallback: token rejected. ")
	} else {
		details.WriteString("Kubernetes fallback: token rejected (may be expired or invalid). ")
	}

	details.WriteString("If using OIDC, ensure you have a valid OIDC token. Otherwise, try 'oc login' to refresh your session.")

	return &authError{
		Reason:  "invalid_token",
		Details: details.String(),
	}
}

func extractBearerToken(c *gin.Context) string {
	authHeader := c.Request.Header.Get("Authorization")
	token, _ := strings.CutPrefix(authHeader, "Bearer ")
	if token != "" {
		return strings.TrimSpace(token)
	}
	token = c.Request.Header.Get("X-Forwarded-Access-Token")
	if token != "" {
		return strings.TrimSpace(token)
	}
	return ""
}

func (a *APIServer) handleGetAuthConfig(c *gin.Context) {
	a.refreshAuthConfigIfNeeded()

	type OIDCConfigResponse struct {
		ClientID string `json:"clientId,omitempty"`
		JWT      []struct {
			Issuer struct {
				URL       string   `json:"url"`
				Audiences []string `json:"audiences,omitempty"`
			} `json:"issuer"`
			ClaimMappings struct {
				Username struct {
					Claim  string `json:"claim"`
					Prefix string `json:"prefix,omitempty"`
				} `json:"username"`
			} `json:"claimMappings"`
		} `json:"jwt"`
	}

	a.authConfigMu.RLock()
	clientID := a.oidcClientID
	authConfig := a.authConfig
	a.authConfigMu.RUnlock()

	response := OIDCConfigResponse{
		ClientID: clientID,
	}

	if clientID != "" && authConfig != nil {
		clientIDInAudience := false
		for _, jwtConfig := range authConfig.JWT {
			for _, audience := range jwtConfig.Issuer.Audiences {
				if audience == clientID {
					clientIDInAudience = true
					break
				}
			}
		}
		if !clientIDInAudience && len(authConfig.JWT) > 0 {
			a.log.Info("OIDC clientId does not match any JWT audience", "clientId", clientID)
		}
	}

	a.authConfigMu.RLock()
	externalJWTWorking := a.externalJWT != nil
	a.authConfigMu.RUnlock()

	if authConfig != nil && len(authConfig.JWT) > 0 && externalJWTWorking {
		for _, jwtConfig := range authConfig.JWT {
			prefix := ""
			if jwtConfig.ClaimMappings.Username.Prefix != nil {
				prefix = *jwtConfig.ClaimMappings.Username.Prefix
			}
			response.JWT = append(response.JWT, struct {
				Issuer struct {
					URL       string   `json:"url"`
					Audiences []string `json:"audiences,omitempty"`
				} `json:"issuer"`
				ClaimMappings struct {
					Username struct {
						Claim  string `json:"claim"`
						Prefix string `json:"prefix,omitempty"`
					} `json:"username"`
				} `json:"claimMappings"`
			}{
				Issuer: struct {
					URL       string   `json:"url"`
					Audiences []string `json:"audiences,omitempty"`
				}{
					URL:       jwtConfig.Issuer.URL,
					Audiences: jwtConfig.Issuer.Audiences,
				},
				ClaimMappings: struct {
					Username struct {
						Claim  string `json:"claim"`
						Prefix string `json:"prefix,omitempty"`
					} `json:"username"`
				}{
					Username: struct {
						Claim  string `json:"claim"`
						Prefix string `json:"prefix,omitempty"`
					}{
						Claim:  jwtConfig.ClaimMappings.Username.Claim,
						Prefix: prefix,
					},
				},
			})
		}
	}

	if len(response.JWT) == 0 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, response)
}
