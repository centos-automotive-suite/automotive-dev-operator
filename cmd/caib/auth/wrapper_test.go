package auth

import (
	"context"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
)

var _ = Describe("CreateClientWithReauth", func() {
	It("should handle nil authToken pointer safely", func() {
		ctx := context.Background()
		client, err := CreateClientWithReauth(ctx, "https://api.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})

	It("should create client with empty token when authToken is empty string", func() {
		ctx := context.Background()
		emptyToken := ""
		client, err := CreateClientWithReauth(ctx, "https://api.example.com", &emptyToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})

	It("should create client with provided token", func() {
		ctx := context.Background()
		token := "test-token"
		client, err := CreateClientWithReauth(ctx, "https://api.example.com", &token)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})

	It("should handle OIDC errors gracefully and still create client", func() {
		ctx := context.Background()
		emptyToken := ""
		// Use invalid server URL to trigger OIDC error
		client, err := CreateClientWithReauth(ctx, "http://invalid-server:9999", &emptyToken)
		// Should still create client even if OIDC fails (auth is optional)
		Expect(err).NotTo(HaveOccurred())
		Expect(client).NotTo(BeNil())
	})
})
