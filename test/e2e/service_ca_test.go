/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Dot import is standard for Ginkgo
	. "github.com/onsi/gomega"    //nolint:revive // Dot import is standard for Gomega
)

// OpenShift's service CA issues a serving certificate into the Secret a
// Service names, and fills a ConfigMap that asks with the bundle that trusts
// it. The workspace and upload agents serve with those certificates.
const (
	servingCertAnn    = "service.beta.openshift.io/serving-cert-secret-name"
	injectCABundleAnn = "service.beta.openshift.io/inject-cabundle"
	caBundleKey       = "service-ca.crt"
)

// startServiceCA stands in for OpenShift's service CA, which Kind lacks, in
// namespace for as long as the suite runs.
func startServiceCA(namespace string) {
	ca, err := newServiceCA()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	go func() {
		for {
			if err := ca.serve(namespace); err != nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "service CA stand-in: %v\n", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

type serviceCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newServiceCA() (*serviceCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2e service CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &serviceCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

type objectList struct {
	Items []struct {
		Metadata struct {
			Name        string            `json:"name"`
			UID         string            `json:"uid"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	} `json:"items"`
}

// serve issues the certificates and fills the bundles in namespace that are
// asked for and missing.
func (ca *serviceCA) serve(namespace string) error {
	var services, secrets, configMaps objectList
	for resource, list := range map[string]*objectList{"services": &services, "secrets": &secrets, "configmaps": &configMaps} {
		out, err := kubectl(nil, "get", resource, "-n", namespace, "-o", "json")
		if err != nil {
			return err
		}
		if err := json.Unmarshal(out, list); err != nil {
			return fmt.Errorf("listing %s: %w", resource, err)
		}
	}
	existing := map[string]bool{}
	for _, secret := range secrets.Items {
		existing[secret.Metadata.Name] = true
	}
	for _, svc := range services.Items {
		secret := svc.Metadata.Annotations[servingCertAnn]
		if secret == "" || existing[secret] {
			continue
		}
		if err := ca.issue(namespace, svc.Metadata.Name, svc.Metadata.UID, secret); err != nil {
			return fmt.Errorf("issuing %s: %w", secret, err)
		}
	}
	for _, cm := range configMaps.Items {
		if cm.Metadata.Annotations[injectCABundleAnn] != "true" || cm.Data[caBundleKey] == ca.pem {
			continue
		}
		patch, err := json.Marshal(map[string]any{"data": map[string]string{caBundleKey: ca.pem}})
		if err != nil {
			return err
		}
		if _, err := kubectl(nil, "patch", "configmap", cm.Metadata.Name, "-n", namespace, "--type", "merge", "-p", string(patch)); err != nil {
			return err
		}
	}
	return nil
}

// issue writes a serving certificate for service into secret, owned by the
// service as OpenShift's are.
func (ca *serviceCA) issue(namespace, service, uid, secret string) error {
	cert, key, err := ca.servingCert(service + "." + namespace + ".svc")
	if err != nil {
		return err
	}
	manifest, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata": map[string]any{
			"name":            secret,
			"namespace":       namespace,
			"ownerReferences": []map[string]string{{"apiVersion": "v1", "kind": "Service", "name": service, "uid": uid}},
		},
		"stringData": map[string]string{"tls.crt": cert, "tls.key": key},
	})
	if err != nil {
		return err
	}
	_, err = kubectl(manifest, "create", "-f", "-")
	return err
}

// servingCert returns a certificate for host, signed by the CA, and its key,
// both PEM-encoded.
func (ca *serviceCA) servingCert(host string) (cert, key string, err error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host, host + ".cluster.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &private.PublicKey, ca.key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

// kubectl runs kubectl quietly, unlike utils.Run, which logs every command
// and changes the working directory, neither of which suits a loop running
// beside the specs.
func kubectl(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("kubectl", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return nil, fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, exitErr.Stderr)
	}
	if err != nil {
		return nil, fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}
