package buildapi

import (
	"context"
	"fmt"
	"os"

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
type AuthenticationConfiguration struct {
	ClientID string                              `json:"clientId"`
	Internal InternalAuthConfig                  `json:"internal"`
	JWT      []apiserverv1beta1.JWTAuthenticator `json:"jwt"`
}

// InternalAuthConfig defines internal authentication configuration.
type InternalAuthConfig struct {
	Prefix string `json:"prefix"`
}

func newJWTAuthenticator(ctx context.Context, config AuthenticationConfiguration) (authenticator.Token, error) {
	if len(config.JWT) == 0 {
		return nil, nil
	}

	scheme := runtime.NewScheme()
	_ = apiserver.AddToScheme(scheme)
	_ = apiserverv1beta1.AddToScheme(scheme)

	jwtAuthenticators := make([]authenticator.Token, 0, len(config.JWT))
	for _, jwtAuthenticator := range config.JWT {
		var oidcCAContent oidcauth.CAContentProvider
		if jwtAuthenticator.Issuer.CertificateAuthority != "" {
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
				return nil, oidcCAError
			}
		}

		var jwtAuthenticatorUnversioned apiserver.JWTAuthenticator
		if err := scheme.Convert(&jwtAuthenticator, &jwtAuthenticatorUnversioned, nil); err != nil {
			return nil, err
		}

		oidcAuth, err := oidcauth.New(ctx, oidcauth.Options{
			JWTAuthenticator:     jwtAuthenticatorUnversioned,
			CAContentProvider:    oidcCAContent,
			SupportedSigningAlgs: oidcauth.AllValidSigningAlgorithms(),
		})
		if err != nil {
			return nil, err
		}
		jwtAuthenticators = append(jwtAuthenticators, oidcAuth)
	}
	return tokenunion.NewFailOnError(jwtAuthenticators...), nil
}

// loadAuthenticationConfigurationFromOperatorConfig loads authentication configuration directly from OperatorConfig CRD.
func loadAuthenticationConfigurationFromOperatorConfig(ctx context.Context, k8sClient client.Client, namespace string) (*AuthenticationConfiguration, authenticator.Token, string, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	key := types.NamespacedName{Name: "config", Namespace: namespace}

	if err := k8sClient.Get(ctx, key, operatorConfig); err != nil {
		return nil, nil, "", fmt.Errorf("failed to get OperatorConfig %s/%s: %w", namespace, "config", err)
	}

	// Check if authentication is configured
	if operatorConfig.Spec.BuildAPI == nil {
		return nil, nil, "", nil // No authentication configured
	}
	if operatorConfig.Spec.BuildAPI.Authentication == nil {
		return nil, nil, "", nil // No authentication configured
	}

	auth := operatorConfig.Spec.BuildAPI.Authentication
	config := &AuthenticationConfiguration{
		ClientID: auth.ClientID,
		Internal: InternalAuthConfig{
			Prefix: "internal:",
		},
		JWT: auth.JWT,
	}

	// Set internal prefix if provided
	if auth.Internal != nil && auth.Internal.Prefix != "" {
		config.Internal.Prefix = auth.Internal.Prefix
	}

	// Build authenticator from JWT configuration
	authn, err := newJWTAuthenticator(ctx, *config)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to create JWT authenticator, will fall back to kubeconfig authentication", "namespace", namespace)
		// Return config with nil authenticator - this allows kubeconfig fallback to work
		return config, nil, config.Internal.Prefix, nil
	}

	return config, authn, config.Internal.Prefix, nil
}
