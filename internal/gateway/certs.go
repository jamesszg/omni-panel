// Package gateway manages the single-:443 L4 multiplexer (rust-rpxy-l4),
// the local PROXY-protocol-aware L7 TLS gateway, ACME certificates, and the
// embedded static OpenSpeedTest fallback.
package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/jamesszg/omni-panel/internal/logger"
)

// CertConfig configures TLS certificates for the L7 gateway.
type CertConfig struct {
	Domain      string
	CertFile    string
	KeyFile     string
	AcmeMode    string // "tls_alpn", "dns_cf", or ""
	AcmeEmail   string
	AcmeCfToken string
}

// CertManager selects between ACME TLS-ALPN-01 certificates, explicit files,
// and an auto-generated self-signed fallback certificate so unknown probes
// still complete TLS and reach the static OpenSpeedTest fallback.
type CertManager struct {
	mu           sync.RWMutex
	certDir      string
	cfg          CertConfig
	fallbackCert *tls.Certificate
	explicitCert *tls.Certificate
	acmeMgr      *autocert.Manager
}

// NewCertManager builds or updates a CertManager storing fallback and ACME caches under certDir.
func NewCertManager(certDir string, cfg CertConfig) (*CertManager, error) {
	m := &CertManager{
		certDir: certDir,
		cfg:     cfg,
	}
	if err := m.Reload(cfg); err != nil {
		return nil, err
	}
	return m, nil
}

// Reload updates certificate sources without replacing the *tls.Config callback pointer.
func (m *CertManager) Reload(cfg CertConfig) error {
	fb, err := ensureFallbackCert(m.certDir, cfg.Domain)
	if err != nil {
		return err
	}

	var exp *tls.Certificate
	if strings.TrimSpace(cfg.CertFile) != "" && strings.TrimSpace(cfg.KeyFile) != "" {
		pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			logger.Warningf("gateway: load explicit cert failed (%s): %v", cfg.CertFile, err)
		} else {
			exp = &pair
		}
	}

	var acmeMgr *autocert.Manager
	if strings.EqualFold(strings.TrimSpace(cfg.AcmeMode), "tls_alpn") && strings.TrimSpace(cfg.Domain) != "" {
		acmeDir := filepath.Join(m.certDir, "acme")
		if err := os.MkdirAll(acmeDir, 0o700); err != nil {
			return fmt.Errorf("create acme cache dir: %w", err)
		}
		acmeMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(acmeDir),
			HostPolicy: autocert.HostWhitelist(strings.TrimSpace(cfg.Domain)),
			Email:      strings.TrimSpace(cfg.AcmeEmail),
		}
	}

	m.mu.Lock()
	m.cfg = cfg
	m.fallbackCert = fb
	m.explicitCert = exp
	m.acmeMgr = acmeMgr
	m.mu.Unlock()
	return nil
}

// TLSConfig returns the dynamic *tls.Config for the L7 listener.
func (m *CertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: m.getCertificate,
	}
}

func (m *CertManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	cfg := m.cfg
	fb := m.fallbackCert
	exp := m.explicitCert
	acmeMgr := m.acmeMgr
	m.mu.RUnlock()

	if acmeMgr != nil && hello != nil {
		isALPNChallenge := slices.Contains(hello.SupportedProtos, acme.ALPNProto)
		if isALPNChallenge || (cfg.Domain != "" && strings.EqualFold(hello.ServerName, cfg.Domain)) {
			if cert, err := acmeMgr.GetCertificate(hello); err == nil && cert != nil {
				return cert, nil
			} else if isALPNChallenge {
				return nil, err
			} else {
				logger.Debugf("gateway: acme cert lookup for %q fell back to local cert: %v", hello.ServerName, err)
			}
		}
	}

	if exp != nil {
		if hello == nil || hello.ServerName == "" || cfg.Domain == "" || strings.EqualFold(hello.ServerName, cfg.Domain) {
			return exp, nil
		}
	}

	return fb, nil
}

func ensureFallbackCert(certDir, domain string) (*tls.Certificate, error) {
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, err
	}
	certPath := filepath.Join(certDir, "fallback.crt")
	keyPath := filepath.Join(certDir, "fallback.key")

	if _, err := os.Stat(certPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			if pair, err3 := tls.LoadX509KeyPair(certPath, keyPath); err3 == nil {
				return &pair, nil
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	cn := strings.TrimSpace(domain)
	if cn == "" {
		cn = "localhost"
	}
	dnsNames := []string{"localhost"}
	if domain != "" && net.ParseIP(domain) == nil && !strings.EqualFold(domain, "localhost") {
		dnsNames = append(dnsNames, domain)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ip := net.ParseIP(domain); ip != nil {
		ips = append(ips, ip)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}
