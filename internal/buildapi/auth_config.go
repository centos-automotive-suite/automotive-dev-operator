package buildapi

import (
	"context"
	"fmt"
	"os"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	oidcauth "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
)

// AuthenticationConfiguration defines the authentication configuration structure.
// JWT holds the resolved (CA-injected) upstream JWTAuthenticator values ready for
// use by newJWTAuthenticator; CA resolution from Secrets/ConfigMaps happens before
// this struct is populated.
type AuthenticationConfiguration struct {
	ClientID string                              `json:"clientId"`
	Internal InternalAuthConfig                  `json:"internal"`
	JWT      []apiserverv1beta1.JWTAuthenticator `json:"jwt"`
}

// resolveCAForIssuer returns the PEM-encoded CA certificate for the given issuer.
// It checks, in order: inline CertificateAuthority string, CertificateAuthoritySecret,
// CertificateAuthorityConfigMap. Returns an empty string when no CA is configured.
func resolveCAForIssuer(ctx context.Context, k8sClient client.Client, issuer automotivev1alpha1.JWTIssuerConfig, defaultNamespace string) (string, error) {
	if issuer.CertificateAuthority != "" {
		return issuer.CertificateAuthority, nil
	}

	if issuer.CertificateAuthoritySecret != nil {
		ns := issuer.CertificateAuthoritySecret.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		secret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: issuer.CertificateAuthoritySecret.Name, Namespace: ns}, secret); err != nil {
			return "", fmt.Errorf("failed to get CA secret %s/%s: %w", ns, issuer.CertificateAuthoritySecret.Name, err)
		}
		pem, ok := secret.Data[issuer.CertificateAuthoritySecret.Key]
		if !ok {
			return "", fmt.Errorf("key %q not found in secret %s/%s", issuer.CertificateAuthoritySecret.Key, ns, issuer.CertificateAuthoritySecret.Name)
		}
		return string(pem), nil
	}

	if issuer.CertificateAuthorityConfigMap != nil {
		ns := issuer.CertificateAuthorityConfigMap.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		cm := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: issuer.CertificateAuthorityConfigMap.Name, Namespace: ns}, cm); err != nil {
			return "", fmt.Errorf("failed to get CA configmap %s/%s: %w", ns, issuer.CertificateAuthorityConfigMap.Name, err)
		}
		pem, ok := cm.Data[issuer.CertificateAuthorityConfigMap.Key]
		if !ok {
			return "", fmt.Errorf("key %q not found in configmap %s/%s", issuer.CertificateAuthorityConfigMap.Key, ns, issuer.CertificateAuthorityConfigMap.Name)
		}
		return pem, nil
	}

	return "", nil
}

// toUpstreamJWTAuthenticators converts JWTAuthenticatorConfig values to the upstream
// apiserverv1beta1.JWTAuthenticator type expected by the OIDC library, resolving any
// CA references from Secrets or ConfigMaps in the process.
func toUpstreamJWTAuthenticators(ctx context.Context, k8sClient client.Client, configs []automotivev1alpha1.JWTAuthenticatorConfig, namespace string) ([]apiserverv1beta1.JWTAuthenticator, error) {
	logger := log.FromContext(ctx)
	result := make([]apiserverv1beta1.JWTAuthenticator, 0, len(configs))
	for _, cfg := range configs {
		resolvedCA, err := resolveCAForIssuer(ctx, k8sClient, cfg.Issuer, namespace)
		if err != nil {
			logger.Error(err, "failed to resolve CA for OIDC issuer", "issuer", cfg.Issuer.URL)
			return nil, err
		}

		issuer := apiserverv1beta1.Issuer{
			URL:                  cfg.Issuer.URL,
			Audiences:            cfg.Issuer.Audiences,
			AudienceMatchPolicy:  apiserverv1beta1.AudienceMatchPolicyType(cfg.Issuer.AudienceMatchPolicy),
			EgressSelectorType:   apiserverv1beta1.EgressSelectorType(cfg.Issuer.EgressSelectorType),
			CertificateAuthority: resolvedCA,
		}
		if cfg.Issuer.DiscoveryURL != "" {
			issuer.DiscoveryURL = &cfg.Issuer.DiscoveryURL
		}

		upstream := apiserverv1beta1.JWTAuthenticator{
			Issuer:               issuer,
			ClaimMappings:        cfg.ClaimMappings,
			ClaimValidationRules: cfg.ClaimValidationRules,
			UserValidationRules:  cfg.UserValidationRules,
		}
		result = append(result, upstream)
	}
	return result, nil
}

// InternalAuthConfig defines internal authentication configuration.
type InternalAuthConfig struct {
	Prefix string `json:"prefix"`
}

// jwtConfigsEqual compares two JWT authenticator slices to check if they're effectively equal.
// This is used to determine if we need to recreate the OIDC authenticator.
func jwtConfigsEqual(a, b []apiserverv1beta1.JWTAuthenticator) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		// Compare key fields that would affect authentication
		if a[i].Issuer.URL != b[i].Issuer.URL {
			return false
		}
		if a[i].Issuer.CertificateAuthority != b[i].Issuer.CertificateAuthority {
			return false
		}
		if !reflect.DeepEqual(a[i].Issuer.Audiences, b[i].Issuer.Audiences) {
			return false
		}
		if a[i].Issuer.AudienceMatchPolicy != b[i].Issuer.AudienceMatchPolicy {
			return false
		}
		if a[i].Issuer.EgressSelectorType != b[i].Issuer.EgressSelectorType {
			return false
		}
		aDiscoveryURL := ""
		bDiscoveryURL := ""
		if a[i].Issuer.DiscoveryURL != nil {
			aDiscoveryURL = *a[i].Issuer.DiscoveryURL
		}
		if b[i].Issuer.DiscoveryURL != nil {
			bDiscoveryURL = *b[i].Issuer.DiscoveryURL
		}
		if aDiscoveryURL != bDiscoveryURL {
			return false
		}
		if a[i].ClaimMappings.Username.Claim != b[i].ClaimMappings.Username.Claim {
			return false
		}
		if a[i].ClaimMappings.Groups.Claim != b[i].ClaimMappings.Groups.Claim {
			return false
		}
		// Compare prefixes
		aUsernamePrefix := ""
		bUsernamePrefix := ""
		if a[i].ClaimMappings.Username.Prefix != nil {
			aUsernamePrefix = *a[i].ClaimMappings.Username.Prefix
		}
		if b[i].ClaimMappings.Username.Prefix != nil {
			bUsernamePrefix = *b[i].ClaimMappings.Username.Prefix
		}
		if aUsernamePrefix != bUsernamePrefix {
			return false
		}
	}
	return true
}

// authConfigsEqual compares two authentication configurations to check if they're effectively equal.
func authConfigsEqual(a, b *AuthenticationConfiguration) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.ClientID != b.ClientID {
		return false
	}
	if a.Internal.Prefix != b.Internal.Prefix {
		return false
	}
	return jwtConfigsEqual(a.JWT, b.JWT)
}

func newJWTAuthenticator(ctx context.Context, config AuthenticationConfiguration) (authenticator.Token, error) {
	logger := log.FromContext(ctx)
	if len(config.JWT) == 0 {
		logger.Info("No JWT issuers configured")
		return nil, nil
	}

	scheme := runtime.NewScheme()
	_ = apiserver.AddToScheme(scheme)
	_ = apiserverv1beta1.AddToScheme(scheme)

	jwtAuthenticators := make([]authenticator.Token, 0, len(config.JWT))
	for _, jwtAuthenticator := range config.JWT {
		issuerURL := jwtAuthenticator.Issuer.URL
		hasCustomCA := jwtAuthenticator.Issuer.CertificateAuthority != ""

		var oidcCAContent oidcauth.CAContentProvider
		if hasCustomCA {
			var oidcCAError error
			// Try to read CA from file, or use it as inline PEM
			if _, err := os.Stat(jwtAuthenticator.Issuer.CertificateAuthority); err == nil {
				oidcCAContent, oidcCAError = dynamiccertificates.NewDynamicCAContentFromFile(
					"oidc-authenticator",
					jwtAuthenticator.Issuer.CertificateAuthority,
				)
				jwtAuthenticator.Issuer.CertificateAuthority = ""
			} else {
				oidcCAContent, oidcCAError = dynamiccertificates.NewStaticCAContent(
					"oidc-authenticator",
					[]byte(jwtAuthenticator.Issuer.CertificateAuthority),
				)
			}
			if oidcCAError != nil {
				logger.Error(oidcCAError, "Failed to load CA certificate", "issuer", issuerURL)
				return nil, oidcCAError
			}
		}

		var jwtAuthenticatorUnversioned apiserver.JWTAuthenticator
		if err := scheme.Convert(&jwtAuthenticator, &jwtAuthenticatorUnversioned, nil); err != nil {
			logger.Error(err, "Failed to convert JWT authenticator config", "issuer", issuerURL)
			return nil, err
		}

		oidcAuth, err := oidcauth.New(ctx, oidcauth.Options{
			JWTAuthenticator:     jwtAuthenticatorUnversioned,
			CAContentProvider:    oidcCAContent,
			SupportedSigningAlgs: oidcauth.AllValidSigningAlgorithms(),
		})
		if err != nil {
			logger.Error(err, "Failed to create OIDC authenticator", "issuer", issuerURL)
			return nil, err
		}
		jwtAuthenticators = append(jwtAuthenticators, oidcAuth)
	}
	logger.Info("JWT authenticators configured", "count", len(jwtAuthenticators))
	return tokenunion.NewFailOnError(jwtAuthenticators...), nil
}

// loadAuthenticationConfigurationFromOperatorConfig loads authentication configuration directly from OperatorConfig CRD.
// CA certificates referenced via CertificateAuthoritySecret or CertificateAuthorityConfigMap are resolved
// at load time so that CA rotations are picked up on each refresh cycle.
func loadAuthenticationConfigurationFromOperatorConfig(ctx context.Context, k8sClient client.Client, namespace string) (*AuthenticationConfiguration, authenticator.Token, string, error) {
	logger := log.FromContext(ctx)

	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	key := types.NamespacedName{Name: "config", Namespace: namespace}

	if err := k8sClient.Get(ctx, key, operatorConfig); err != nil {
		return nil, nil, "", fmt.Errorf("failed to get OperatorConfig %s/%s: %w", namespace, "config", err)
	}

	// Check if authentication is configured
	if operatorConfig.Spec.BuildAPI == nil {
		return nil, nil, "", nil
	}
	if operatorConfig.Spec.BuildAPI.Authentication == nil {
		return nil, nil, "", nil
	}

	auth := operatorConfig.Spec.BuildAPI.Authentication

	// Convert JWTAuthenticatorConfig → apiserverv1beta1.JWTAuthenticator, resolving any
	// CA references from Secrets or ConfigMaps.
	// On failure we still return the config so the kubeconfig TokenReview fallback stays active.
	jwtCopy, err := toUpstreamJWTAuthenticators(ctx, k8sClient, auth.JWT, namespace)
	if err != nil {
		logger.Error(err, "failed to resolve JWT CA references, OIDC authenticator will be unavailable; kubeconfig auth remains active", "namespace", namespace)
		jwtCopy = nil
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

	config := &AuthenticationConfiguration{
		ClientID: auth.ClientID,
		Internal: InternalAuthConfig{Prefix: "internal:"},
		JWT:      jwtCopy,
	}
	if auth.Internal != nil && auth.Internal.Prefix != "" {
		config.Internal.Prefix = auth.Internal.Prefix
	}

	// Build authenticator from JWT configuration
	authn, err := newJWTAuthenticator(ctx, *config)
	if err != nil {
		logger.Error(err, "failed to create JWT authenticator, will fall back to kubeconfig authentication", "namespace", namespace)
		// Return config with nil authenticator - kubeconfig fallback remains available.
		return config, nil, config.Internal.Prefix, nil
	}

	return config, authn, config.Internal.Prefix, nil
}
