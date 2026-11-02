package workspaceagent

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// CertificateReloader serves the key pair in certFile and keyFile and reloads
// it when the certificate file changes, as when OpenShift's service CA
// rotates a serving certificate Secret.
type CertificateReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
}

// NewCertificateReloader loads the key pair once, so a bad pair fails startup.
func NewCertificateReloader(certFile, keyFile string) (*CertificateReloader, error) {
	c := &CertificateReloader{certFile: certFile, keyFile: keyFile}
	if _, err := c.GetCertificate(nil); err != nil {
		return nil, err
	}
	return c, nil
}

// GetCertificate implements tls.Config.GetCertificate. If a changed pair
// cannot be loaded, it keeps serving the previous one.
func (c *CertificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := os.Stat(c.certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert != nil && info.ModTime().Equal(c.modTime) {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.modTime = &cert, info.ModTime()
	return c.cert, nil
}
