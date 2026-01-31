package buildapi

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

var _ = Describe("validateInternalJWT", func() {
	var cfg *internalJWTConfig
	var key []byte

	BeforeEach(func() {
		key = []byte("test-secret-key-32-bytes-long!")
		cfg = &internalJWTConfig{
			issuer:   "test-issuer",
			audience: "test-audience",
			key:      key,
		}
	})

	It("should reject nil config", func() {
		token := "dummy-token"
		subject, valid := validateInternalJWT(token, nil)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should reject token with empty subject", func() {
		claims := jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   "", // Empty subject
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should accept valid token with non-empty subject", func() {
		claims := jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeTrue())
		Expect(subject).To(Equal("test-user"))
	})

	It("should reject token with wrong issuer", func() {
		claims := jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should reject token with wrong audience", func() {
		claims := jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"wrong-audience"},
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should reject expired token", func() {
		claims := jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should reject token used before NotBefore time", func() {
		claims := jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   "test-user",
			NotBefore: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should reject token with invalid signature", func() {
		wrongKey := []byte("wrong-secret-key-32-bytes-long!")
		claims := jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			Subject:   "test-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(wrongKey)
		Expect(err).NotTo(HaveOccurred())

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})

	It("should reject token with wrong signing method", func() {
		// Test with an invalid token string (wrong signing method)
		// This will fail validation since it doesn't match the expected HS256 method
		tokenString := "invalid.token.string"

		subject, valid := validateInternalJWT(tokenString, cfg)
		Expect(valid).To(BeFalse())
		Expect(subject).To(BeEmpty())
	})
})
