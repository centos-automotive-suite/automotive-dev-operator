package buildapi

import (
	"runtime"
	"strings"
	"testing"
	"time"

	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
)

// An issuer's authenticator discovers its provider in the background until its
// context ends. A failed refresh is retried every poll interval, so when a
// later issuer fails, the authenticators already started must stop, or each
// retry leaves another one polling its issuer for good.
func TestFailedJWTAuthenticatorStopsTheIssuersItStarted(t *testing.T) {
	issuer := func(url, ca string) apiserverv1beta1.JWTAuthenticator {
		return apiserverv1beta1.JWTAuthenticator{
			Issuer: apiserverv1beta1.Issuer{URL: url, Audiences: []string{"ado"}, CertificateAuthority: ca},
			ClaimMappings: apiserverv1beta1.ClaimMappings{
				Username: apiserverv1beta1.PrefixedClaimOrExpression{Claim: "sub", Prefix: new("")},
			},
		}
	}
	before := oidcDiscoveryGoroutines()
	// Nothing listens on these ports, so discovery keeps failing and retrying.
	_, err := newJWTAuthenticator(t.Context(), AuthenticationConfiguration{JWT: []apiserverv1beta1.JWTAuthenticator{
		issuer("https://127.0.0.1:1", ""),
		issuer("https://127.0.0.1:2", "not a certificate"),
	}})
	if err == nil {
		t.Fatal("built an authenticator with an invalid CA")
	}
	deadline := time.Now().Add(3 * time.Second)
	for oidcDiscoveryGoroutines() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d issuer discovery goroutines still run after the failed construction",
				oidcDiscoveryGoroutines()-before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// oidcDiscoveryGoroutines counts the goroutines OIDC authenticators run to
// discover their issuers.
func oidcDiscoveryGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for stack := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(stack, "authenticator/token/oidc.New.func") {
			count++
		}
	}
	return count
}
