// Package bundleverify provides cosign signature verification for OCI images.
package bundleverify

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const sigstoreVerifyTimeout = 30 * time.Second

func fetchPEMFromConfigMap(ctx context.Context, k8sClient client.Reader, ref *corev1.ConfigMapKeySelector, namespace, label string) ([]byte, error) {
	if ref == nil || ref.Name == "" || ref.Key == "" {
		return nil, fmt.Errorf("%s is not configured", label)
	}
	cm := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, cm); err != nil {
		return nil, fmt.Errorf("failed to read %s ConfigMap %q: %w", label, ref.Name, err)
	}
	data, ok := cm.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("ConfigMap %q does not contain key %q", ref.Name, ref.Key)
	}
	if strings.TrimSpace(data) == "" {
		return nil, fmt.Errorf("ConfigMap %q key %q is empty", ref.Name, ref.Key)
	}
	return []byte(data), nil
}

// FetchCosignPublicKey reads a cosign public key (PEM-encoded) from a ConfigMap
// referenced by a ConfigMapKeySelector.
func FetchCosignPublicKey(ctx context.Context, k8sClient client.Reader, keyRef *corev1.ConfigMapKeySelector, namespace string) ([]byte, error) {
	return fetchPEMFromConfigMap(ctx, k8sClient, keyRef, namespace, "cosign key reference")
}

// FetchFulcioRootCA reads a Fulcio root CA certificate (PEM-encoded) from a ConfigMap.
func FetchFulcioRootCA(ctx context.Context, k8sClient client.Reader, ref *corev1.ConfigMapKeySelector, namespace string) ([]byte, error) {
	return fetchPEMFromConfigMap(ctx, k8sClient, ref, namespace, "fulcio root CA reference")
}

// NewTrustedMaterialFromFulcioCA constructs a TrustedMaterial that only trusts
// certificates issued by the given Fulcio root CA.
func NewTrustedMaterialFromFulcioCA(rootCAPEM []byte) (root.TrustedMaterial, error) {
	block, _ := pem.Decode(rootCAPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from Fulcio root CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing Fulcio root CA certificate: %w", err)
	}
	ca := &root.FulcioCertificateAuthority{
		Root:                cert,
		Intermediates:       []*x509.Certificate{},
		ValidityPeriodStart: cert.NotBefore,
		ValidityPeriodEnd:   cert.NotAfter,
	}
	return root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		[]root.CertificateAuthority{ca},
		map[string]*root.TransparencyLog{},
		[]root.TimestampingAuthority{},
		map[string]*root.TransparencyLog{},
	)
}

// VerifyBundle verifies the cosign signature of an OCI image reference using the
// given cosign public key (PEM-encoded). Optional ociremote.Option values are
// forwarded to cosign for registry authentication.
//
// Tries v3 bundle format (OCI referrers) first, falls back to legacy tag-based signatures.
func VerifyBundle(ctx context.Context, bundleRef string, cosignPubKeyPEM []byte, registryOpts ...ociremote.Option) error {
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(cosignPubKeyPEM)
	if err != nil {
		return fmt.Errorf("parsing cosign public key: %w", err)
	}

	verifier, err := signature.LoadDefaultVerifier(pubKey)
	if err != nil {
		return fmt.Errorf("creating verifier: %w", err)
	}

	ref, err := name.ParseReference(bundleRef)
	if err != nil {
		return fmt.Errorf("parsing bundle reference %q: %w", bundleRef, err)
	}

	v3Err := verifyV3Bundles(ctx, ref, verifier, registryOpts)
	if v3Err == nil {
		return nil
	}

	if legacyErr := verifyLegacy(ctx, ref, verifier, registryOpts); legacyErr != nil {
		return fmt.Errorf("verification failed (v3: %v, legacy: %w)", v3Err, legacyErr)
	}
	return nil
}

// KeylessIdentity holds the certificate identity and OIDC issuer for keyless verification.
type KeylessIdentity struct {
	Subject         string
	SubjectRegExp   string
	Issuer          string
	IssuerRegExp    string
	RekorURL        string
	FulcioRootCAPEM []byte
}

// KeylessIdentityFromAPI converts the CRD API type to the internal verification type.
func KeylessIdentityFromAPI(kl *automotivev1alpha1.CosignKeylessIdentity) KeylessIdentity {
	return KeylessIdentity{
		Subject:       kl.CertificateIdentity,
		SubjectRegExp: kl.CertificateIdentityRegExp,
		Issuer:        kl.CertificateOIDCIssuer,
		IssuerRegExp:  kl.CertificateOIDCIssuerRegExp,
		RekorURL:      kl.RekorURL,
	}
}

var (
	cachedTrustedRoot root.TrustedMaterial
	trustedRootMu     sync.Mutex
)

func trustedRoot() (root.TrustedMaterial, error) {
	trustedRootMu.Lock()
	defer trustedRootMu.Unlock()
	if cachedTrustedRoot != nil {
		return cachedTrustedRoot, nil
	}
	tr, err := cosign.TrustedRoot()
	if err != nil {
		return nil, err
	}
	cachedTrustedRoot = tr
	return cachedTrustedRoot, nil
}

// VerifyImageKeyless verifies the cosign signature of an OCI image reference
// using keyless (Fulcio/Rekor) verification. Instead of a static public key, it
// validates the signing certificate's identity and OIDC issuer against the
// Sigstore transparency log.
func VerifyImageKeyless(ctx context.Context, imageRef string, identity KeylessIdentity, registryOpts ...ociremote.Option) error {
	if identity.Subject == "" && identity.SubjectRegExp == "" {
		return fmt.Errorf("keyless identity requires at least one of Subject or SubjectRegExp")
	}
	if identity.Issuer == "" && identity.IssuerRegExp == "" {
		return fmt.Errorf("keyless identity requires at least one of Issuer or IssuerRegExp")
	}
	if identity.RekorURL != "" {
		return fmt.Errorf("custom RekorURL is not yet supported; remove the rekorURL field or leave it empty")
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("parsing image reference %q: %w", imageRef, err)
	}

	var trustedMaterial root.TrustedMaterial
	var ignoreTlog, ignoreSCT bool
	if len(identity.FulcioRootCAPEM) > 0 {
		trustedMaterial, err = NewTrustedMaterialFromFulcioCA(identity.FulcioRootCAPEM)
		if err != nil {
			return fmt.Errorf("building trusted material from Fulcio root CA: %w", err)
		}
		ignoreTlog = true
		ignoreSCT = true
	} else {
		trustedMaterial, err = trustedRoot()
		if err != nil {
			return fmt.Errorf("loading Sigstore trusted root: %w", err)
		}
	}

	checkOpts := &cosign.CheckOpts{
		TrustedMaterial:    trustedMaterial,
		RegistryClientOpts: registryOpts,
		ExperimentalOCI11:  true,
		IgnoreTlog:         ignoreTlog,
		IgnoreSCT:          ignoreSCT,
		Identities: []cosign.Identity{{
			Subject:       identity.Subject,
			SubjectRegExp: identity.SubjectRegExp,
			Issuer:        identity.Issuer,
			IssuerRegExp:  identity.IssuerRegExp,
		}},
	}

	verifyCtx, cancel := context.WithTimeout(ctx, sigstoreVerifyTimeout)
	defer cancel()

	_, _, err = cosign.VerifyImageSignatures(verifyCtx, ref, checkOpts)
	if err != nil {
		return fmt.Errorf("keyless verification failed for %q: %w", imageRef, err)
	}
	return nil
}

// VerifyImage verifies an OCI image signature using either keyless or key-based
// verification depending on the provided configuration. If keyless is non-nil,
// keyless verification is used; otherwise key-based verification is used with the
// cosign public key fetched from the ConfigMap referenced by keyRef.
func VerifyImage(ctx context.Context, imageRef string, keyless *automotivev1alpha1.CosignKeylessIdentity, k8sClient client.Reader, keyRef *corev1.ConfigMapKeySelector, namespace string, registryOpts ...ociremote.Option) error {
	if keyless != nil {
		return VerifyImageKeyless(ctx, imageRef, KeylessIdentityFromAPI(keyless), registryOpts...)
	}
	pubKeyPEM, err := FetchCosignPublicKey(ctx, k8sClient, keyRef, namespace)
	if err != nil {
		return err
	}
	return VerifyBundle(ctx, imageRef, pubKeyPEM, registryOpts...)
}

// verifyV3Bundles fetches sigstore v3 bundles via OCI referrers and verifies with sigstore-go.
func verifyV3Bundles(ctx context.Context, ref name.Reference, verifier signature.Verifier, registryOpts []ociremote.Option) error {
	bundles, hash, err := cosign.GetBundles(ctx, ref, registryOpts)
	if err != nil {
		return fmt.Errorf("fetching v3 bundles: %w", err)
	}
	if len(bundles) == 0 {
		return fmt.Errorf("no v3 bundles found")
	}

	digestHex, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return fmt.Errorf("decoding image digest hex: %w", err)
	}

	co := &cosign.CheckOpts{
		SigVerifier: verifier,
		IgnoreTlog:  true,
		IgnoreSCT:   true,
	}

	artifactDigest := verify.WithArtifactDigest(hash.Algorithm, digestHex)

	for _, bundle := range bundles {
		if _, err := cosign.VerifyNewBundle(ctx, co, artifactDigest, bundle); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no v3 bundle verified successfully for %q", ref.String())
}

// verifyLegacy uses the legacy tag-based cosign verification (v2 compat).
func verifyLegacy(ctx context.Context, ref name.Reference, verifier signature.Verifier, registryOpts []ociremote.Option) error {
	checkOpts := &cosign.CheckOpts{
		SigVerifier:        verifier,
		IgnoreTlog:         true,
		IgnoreSCT:          true,
		ExperimentalOCI11:  true,
		RegistryClientOpts: registryOpts,
	}

	_, _, err := cosign.VerifyImageSignatures(ctx, ref, checkOpts)
	if err != nil {
		return fmt.Errorf("cosign verification failed for %q: %w", ref.String(), err)
	}

	return nil
}
