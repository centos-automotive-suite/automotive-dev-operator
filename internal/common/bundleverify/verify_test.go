package bundleverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestVerifyBundle_InvalidPEM(t *testing.T) {
	err := VerifyBundle(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM key")
	}
	if got := err.Error(); got == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestVerifyBundle_InvalidRef(t *testing.T) {
	// Valid ECDSA P-256 test key (not a real signing key)
	testPEM := []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY1WtPBgOWxlBCpCIuR7SXPJG1sXD
VmOYGDB0PCBPeJQyaK1FGKs06iDQL4DP6jMzqpNL3D5LkF8bOJCGhIFjQ==
-----END PUBLIC KEY-----`)

	err := VerifyBundle(context.Background(), ":::invalid-ref", testPEM)
	if err == nil {
		t.Fatal("expected error for invalid reference")
	}
}

func newFakeReader(objs ...client.Object) client.Reader {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestVerifyImageKeyless_InvalidRef(t *testing.T) {
	identity := KeylessIdentity{
		Subject: "test@example.com",
		Issuer:  "https://accounts.example.com",
	}
	err := VerifyImageKeyless(context.Background(), ":::invalid-ref", identity)
	if err == nil {
		t.Fatal("expected error for invalid reference")
	}
	if !strings.Contains(err.Error(), "parsing image reference") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyImageKeyless_EmptySubject(t *testing.T) {
	identity := KeylessIdentity{
		Issuer: "https://accounts.example.com",
	}
	err := VerifyImageKeyless(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity)
	if err == nil {
		t.Fatal("expected error for empty subject")
	}
	if !strings.Contains(err.Error(), "Subject or SubjectRegExp") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyImageKeyless_EmptyIssuer(t *testing.T) {
	identity := KeylessIdentity{
		Subject: "test@example.com",
	}
	err := VerifyImageKeyless(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity)
	if err == nil {
		t.Fatal("expected error for empty issuer")
	}
	if !strings.Contains(err.Error(), "Issuer or IssuerRegExp") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyImageKeyless_RegExpAlternatives(t *testing.T) {
	identity := KeylessIdentity{
		SubjectRegExp: ".*@example.com",
		IssuerRegExp:  "https://.*",
	}
	err := VerifyImageKeyless(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity)
	if err == nil {
		t.Fatal("expected error (no Sigstore infra), but validation should pass")
	}
	if strings.Contains(err.Error(), "Subject or SubjectRegExp") || strings.Contains(err.Error(), "Issuer or IssuerRegExp") {
		t.Errorf("identity validation should have passed with RegExp alternatives, got: %v", err)
	}
}

func TestVerifyImageKeyless_CustomRekorURL(t *testing.T) {
	identity := KeylessIdentity{
		Subject:  "test@example.com",
		Issuer:   "https://accounts.example.com",
		RekorURL: "https://rekor.custom.dev",
	}
	err := VerifyImageKeyless(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity)
	if err == nil {
		t.Fatal("expected error for custom RekorURL")
	}
	if !strings.Contains(err.Error(), "custom RekorURL is not yet supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyImageKeyless_EmptyRekorURL(t *testing.T) {
	identity := KeylessIdentity{
		Subject: "test@example.com",
		Issuer:  "https://accounts.example.com",
	}
	err := VerifyImageKeyless(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity)
	if err == nil {
		t.Fatal("expected error (no Sigstore infra), but RekorURL validation should pass")
	}
	if strings.Contains(err.Error(), "RekorURL") {
		t.Errorf("empty RekorURL should be accepted, got: %v", err)
	}
}

func TestTrustedRoot_RetriesOnError(t *testing.T) {
	trustedRootMu.Lock()
	cachedTrustedRoot = nil
	trustedRootMu.Unlock()

	_, err := trustedRoot()
	if err == nil {
		t.Skip("Sigstore TUF root unexpectedly available in test environment")
	}

	_, err2 := trustedRoot()
	if err2 == nil {
		t.Skip("Sigstore TUF root became available on second attempt")
	}
}

func TestVerifyImage_KeylessPath(t *testing.T) {
	apiIdentity := &automotivev1alpha1.CosignKeylessIdentity{
		CertificateIdentity:   "test@example.com",
		CertificateOIDCIssuer: "https://issuer.example.com",
	}
	err := VerifyImage(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", apiIdentity, nil, nil, "default")
	if err == nil {
		t.Fatal("expected error (no Sigstore infra)")
	}
	if strings.Contains(err.Error(), "cosign key reference is not configured") {
		t.Errorf("should use keyless path, not key-based: %v", err)
	}
}

func TestVerifyImage_KeyBasedPath(t *testing.T) {
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "my-key"},
		Key:                  "cosign.pub",
	}
	k := newFakeReader()
	err := VerifyImage(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil, k, ref, "default")
	if err == nil {
		t.Fatal("expected error (ConfigMap not found)")
	}
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "ConfigMap") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyImage_NilKeyless_NilKeyRef(t *testing.T) {
	k := newFakeReader()
	err := VerifyImage(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil, k, nil, "default")
	if err == nil {
		t.Fatal("expected error for nil keyRef")
	}
	if !strings.Contains(err.Error(), "cosign key reference is not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchCosignPublicKey_NilKeyRef(t *testing.T) {
	k := newFakeReader()
	_, err := FetchCosignPublicKey(context.Background(), k, nil, "default")
	if err == nil {
		t.Fatal("expected error for nil keyRef")
	}
	if got := err.Error(); got != "cosign key reference is not configured" {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestFetchCosignPublicKey_EmptyName(t *testing.T) {
	k := newFakeReader()
	ref := &corev1.ConfigMapKeySelector{Key: "cosign.pub"}
	_, err := FetchCosignPublicKey(context.Background(), k, ref, "default")
	if err == nil {
		t.Fatal("expected error for empty ConfigMap name")
	}
}

func TestFetchCosignPublicKey_MissingConfigMap(t *testing.T) {
	k := newFakeReader()
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "no-such-cm"},
		Key:                  "cosign.pub",
	}
	_, err := FetchCosignPublicKey(context.Background(), k, ref, "default")
	if err == nil {
		t.Fatal("expected error for missing ConfigMap")
	}
}

func TestFetchCosignPublicKey_MissingKey(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-key", Namespace: "default"},
		Data:       map[string]string{"wrong-key": "data"},
	}
	k := newFakeReader(cm)
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "my-key"},
		Key:                  "cosign.pub",
	}
	_, err := FetchCosignPublicKey(context.Background(), k, ref, "default")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFetchCosignPublicKey_EmptyPEM(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-key", Namespace: "default"},
		Data:       map[string]string{"cosign.pub": "   "},
	}
	k := newFakeReader(cm)
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "my-key"},
		Key:                  "cosign.pub",
	}
	_, err := FetchCosignPublicKey(context.Background(), k, ref, "default")
	if err == nil {
		t.Fatal("expected error for empty PEM")
	}
	if got := err.Error(); got != `ConfigMap "my-key" key "cosign.pub" is empty` {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestFetchCosignPublicKey_Success(t *testing.T) {
	pem := "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "my-key", Namespace: "default"},
		Data:       map[string]string{"cosign.pub": pem},
	}
	k := newFakeReader(cm)
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "my-key"},
		Key:                  "cosign.pub",
	}
	got, err := FetchCosignPublicKey(context.Background(), k, ref, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != pem {
		t.Errorf("got %q, want %q", string(got), pem)
	}
}

func generateSelfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}, CommonName: "test-fulcio-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestNewTrustedMaterialFromFulcioCA_Valid(t *testing.T) {
	caPEM := generateSelfSignedCAPEM(t)
	tm, err := NewTrustedMaterialFromFulcioCA(caPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cas := tm.FulcioCertificateAuthorities()
	if len(cas) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(cas))
	}
}

func TestNewTrustedMaterialFromFulcioCA_InvalidPEM(t *testing.T) {
	_, err := NewTrustedMaterialFromFulcioCA([]byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewTrustedMaterialFromFulcioCA_InvalidCert(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")})
	_, err := NewTrustedMaterialFromFulcioCA(badPEM)
	if err == nil {
		t.Fatal("expected error for invalid certificate")
	}
	if !strings.Contains(err.Error(), "parsing Fulcio root CA") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyImageKeyless_WithFulcioRootCA(t *testing.T) {
	caPEM := generateSelfSignedCAPEM(t)
	identity := KeylessIdentity{
		Subject:         "test@example.com",
		Issuer:          "https://accounts.example.com",
		FulcioRootCAPEM: caPEM,
	}
	err := VerifyImageKeyless(context.Background(), "quay.io/test/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity)
	if err == nil {
		t.Fatal("expected verification to fail (no matching signature)")
	}
	if strings.Contains(err.Error(), "loading Sigstore trusted root") {
		t.Errorf("should use custom CA, not default TUF root: %v", err)
	}
}

func TestFetchFulcioRootCA_NilRef(t *testing.T) {
	k := newFakeReader()
	_, err := FetchFulcioRootCA(context.Background(), k, nil, "default")
	if err == nil {
		t.Fatal("expected error for nil ref")
	}
}

func TestFetchFulcioRootCA_MissingConfigMap(t *testing.T) {
	k := newFakeReader()
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "no-such-cm"},
		Key:                  "ca.pem",
	}
	_, err := FetchFulcioRootCA(context.Background(), k, ref, "default")
	if err == nil {
		t.Fatal("expected error for missing ConfigMap")
	}
}

func TestFetchFulcioRootCA_Success(t *testing.T) {
	caPEM := generateSelfSignedCAPEM(t)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "fulcio-root", Namespace: "default"},
		Data:       map[string]string{"ca.pem": string(caPEM)},
	}
	k := newFakeReader(cm)
	ref := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "fulcio-root"},
		Key:                  "ca.pem",
	}
	got, err := FetchFulcioRootCA(context.Background(), k, ref, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(caPEM) {
		t.Error("returned PEM does not match input")
	}
}
