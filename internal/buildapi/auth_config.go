package buildapi

import (
	"context"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"sigs.k8s.io/yaml"

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

func loadAuthenticationConfigurationFromFile(ctx context.Context, path string) (*AuthenticationConfiguration, authenticator.Token, string, error) {
	if path == "" {
		return nil, nil, "", nil
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil, nil, "", fmt.Errorf("path is a directory, not a file: %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, "", fmt.Errorf("file not found: %s", path)
		}
		return nil, nil, "", fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var config AuthenticationConfiguration

	var wrapped struct {
		Authentication AuthenticationConfiguration `yaml:"authentication" json:"authentication"`
	}
	wrappedErr := yaml.Unmarshal(content, &wrapped)
	if wrappedErr == nil {
		if len(wrapped.Authentication.JWT) > 0 {
			config = wrapped.Authentication
		} else if wrapped.Authentication.Internal.Prefix != "" {
			config = wrapped.Authentication
		} else {
			if err := yaml.Unmarshal(content, &config); err != nil {
				return nil, nil, "", fmt.Errorf("failed to parse auth config: wrapped parse succeeded but JWT empty (jwt_count=0, internal_prefix=%q), direct parse failed: %w. This suggests YAML structure mismatch with Kubernetes JWTAuthenticator format", wrapped.Authentication.Internal.Prefix, err)
			}
		}
	} else {
		if err := yaml.Unmarshal(content, &config); err != nil {
			return nil, nil, "", fmt.Errorf("failed to parse auth config (tried wrapped and direct): wrapped_err=%v, direct_err=%w", wrappedErr, err)
		}
	}

	if len(config.JWT) == 0 {
		var raw struct {
			Authentication struct {
				ClientID string `yaml:"clientId"`
				Internal struct {
					Prefix string `yaml:"prefix"`
				} `yaml:"internal"`
				JWT []struct {
					Issuer struct {
						URL                  string   `yaml:"url"`
						Audiences            []string `yaml:"audiences"`
						CertificateAuthority string   `yaml:"certificateAuthority"`
					} `yaml:"issuer"`
					ClaimMappings struct {
						Username struct {
							Claim  string `yaml:"claim"`
							Prefix string `yaml:"prefix"`
						} `yaml:"username"`
					} `yaml:"claimMappings"`
				} `yaml:"jwt"`
			} `yaml:"authentication"`
		}
		if err := yaml.Unmarshal(content, &raw); err == nil && len(raw.Authentication.JWT) > 0 {
			if config.ClientID == "" {
				config.ClientID = raw.Authentication.ClientID
			}
			if config.Internal.Prefix == "" {
				config.Internal.Prefix = raw.Authentication.Internal.Prefix
			}
			for _, entry := range raw.Authentication.JWT {
				prefix := entry.ClaimMappings.Username.Prefix
				jwt := apiserverv1beta1.JWTAuthenticator{
					Issuer: apiserverv1beta1.Issuer{
						URL:                  entry.Issuer.URL,
						Audiences:            entry.Issuer.Audiences,
						CertificateAuthority: entry.Issuer.CertificateAuthority,
					},
					ClaimMappings: apiserverv1beta1.ClaimMappings{
						Username: apiserverv1beta1.PrefixedClaimOrExpression{
							Claim:  entry.ClaimMappings.Username.Claim,
							Prefix: &prefix,
						},
					},
				}
				config.JWT = append(config.JWT, jwt)
			}
		}
	}

	if config.Internal.Prefix == "" {
		config.Internal.Prefix = "internal:"
	}

	authn, err := newJWTAuthenticator(ctx, config)
	if err != nil {
		return nil, nil, "", err
	}
	return &config, authn, config.Internal.Prefix, nil
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
		var oidcCAContent oidc.CAContentProvider
		if jwtAuthenticator.Issuer.CertificateAuthority != "" {
			var oidcCAError error
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

		oidcAuth, err := oidc.New(ctx, oidc.Options{
			JWTAuthenticator:     jwtAuthenticatorUnversioned,
			CAContentProvider:    oidcCAContent,
			SupportedSigningAlgs: oidc.AllValidSigningAlgorithms(),
		})
		if err != nil {
			return nil, err
		}
		jwtAuthenticators = append(jwtAuthenticators, oidcAuth)
	}
	return tokenunion.NewFailOnError(jwtAuthenticators...), nil
}
