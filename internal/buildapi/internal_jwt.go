package buildapi

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type internalJWTConfig struct {
	issuer   string
	audience string
	key      []byte
}

func loadInternalJWTConfig() (*internalJWTConfig, error) {
	issuer := strings.TrimSpace(os.Getenv("INTERNAL_JWT_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("INTERNAL_JWT_AUDIENCE"))
	key := strings.TrimSpace(os.Getenv("INTERNAL_JWT_KEY"))

	if issuer == "" && audience == "" && key == "" {
		return nil, nil
	}
	if issuer == "" || audience == "" || key == "" {
		return nil, fmt.Errorf("INTERNAL_JWT_ISSUER, INTERNAL_JWT_AUDIENCE, and INTERNAL_JWT_KEY must all be set")
	}

	return &internalJWTConfig{
		issuer:   issuer,
		audience: audience,
		key:      []byte(key),
	}, nil
}

func validateInternalJWT(tokenString string, cfg *internalJWTConfig) (string, bool) {
	// Defensive nil check (function is currently always called after nil check, but safe to guard)
	if cfg == nil {
		return "", false
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return cfg.key, nil
	})
	if err != nil || !token.Valid {
		return "", false
	}

	if claims.Issuer != cfg.issuer {
		return "", false
	}
	if cfg.audience != "" && !audienceContains(claims.Audience, cfg.audience) {
		return "", false
	}
	now := time.Now()
	if claims.ExpiresAt == nil || now.After(claims.ExpiresAt.Time) {
		return "", false
	}
	if claims.NotBefore != nil && now.Before(claims.NotBefore.Time) {
		return "", false
	}

	// Reject tokens with empty subject - they don't represent a valid authenticated identity
	if claims.Subject == "" {
		return "", false
	}

	return claims.Subject, true
}

func audienceContains(audiences jwt.ClaimStrings, audience string) bool {
	for _, entry := range audiences {
		if entry == audience {
			return true
		}
	}
	return false
}
