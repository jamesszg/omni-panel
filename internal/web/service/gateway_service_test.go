package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jamesszg/omni-panel/internal/database/dbtest"
	"github.com/jamesszg/omni-panel/internal/database/model"
)

type mockSubLinkProvider struct{}

func (m *mockSubLinkProvider) SubLinksForSubId(string, string) ([]string, error) {
	return nil, nil
}

func (m *mockSubLinkProvider) LinksForClient(host string, inbound *model.Inbound, email string) []string {
	return []string{"mock://" + email + "@" + host + ":" + string(inbound.Protocol)}
}

func (m *mockSubLinkProvider) LinksForInbounds(string, []*model.Inbound) []string {
	return nil
}

func TestBootstrap443StackAndValidate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	dbtest.InitDB(t, filepath.Join(dir, "x-ui.db"))

	prev := subLinkProvider()
	RegisterSubLinkProvider(&mockSubLinkProvider{})
	t.Cleanup(func() { RegisterSubLinkProvider(prev) })

	gwSvc := &GatewayService{}
	res, err := gwSvc.Bootstrap443Stack("edge.example.com", BootstrapRequest{
		Domain:      "edge.example.com",
		PublicPort:  443,
		RealitySNI:  "www.microsoft.com",
		RealityDest: "www.microsoft.com:443",
		ClientEmail: "wizarduser",
	})
	if err != nil {
		t.Fatalf("Bootstrap443Stack failed: %v", err)
	}
	if len(res.Inbounds) != 3 {
		t.Fatalf("created %d inbounds, want 3 default presets", len(res.Inbounds))
	}
	if res.SubID == "" || res.SubURL == "" {
		t.Fatalf("expected non-empty SubID and SubURL, got %+v", res)
	}
	allInbounds, err := (&InboundService{}).GetInbounds(1)
	if err != nil || len(allInbounds) != 3 {
		t.Fatalf("expected GetInbounds(1) to return 3 user-owned inbounds, got len=%d err=%v", len(allInbounds), err)
	}
	// Calling Bootstrap443Stack a second time must succeed idempotently.
	res2, err := gwSvc.Bootstrap443Stack("edge.example.com", BootstrapRequest{
		Domain:      "edge.example.com",
		PublicPort:  443,
		RealitySNI:  "www.microsoft.com",
		RealityDest: "www.microsoft.com:443",
		ClientEmail: "wizarduser",
	})
	if err != nil || len(res2.Inbounds) != 3 {
		t.Fatalf("repeated Bootstrap443Stack failed: err=%v res=%+v", err, res2)
	}

	// Verify status reflects gatewayEnable=true and domain.
	status, err := gwSvc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if !status.GatewayEnable || status.Domain != "edge.example.com" || status.GatewayRuntime.Topology == nil {
		t.Fatalf("unexpected gateway status: %+v", status)
	}

	// Verify ValidateCandidateInbound rejects invalid Hysteria ALPN.
	vr := gwSvc.ValidateCandidateInbound(&model.Inbound{
		Enable:         true,
		Core:           "singbox",
		Protocol:       model.Hysteria,
		Port:           30999,
		StreamSettings: `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["http/1.1"]}}`,
	})
	if vr.Valid || vr.Error == "" {
		t.Fatalf("expected ValidateCandidateInbound rejection for http/1.1 on Hysteria, got %+v", vr)
	}
}

func TestBootstrap443StackWithExistingCertAndPortRelocation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	dbtest.InitDB(t, filepath.Join(dir, "x-ui.db"))

	prevProvider := subLinkProvider()
	RegisterSubLinkProvider(&mockSubLinkProvider{})
	t.Cleanup(func() { RegisterSubLinkProvider(prevProvider) })

	certRoot := filepath.Join(dir, "root-cert")
	prevRoot := defaultCertSearchRoot
	defaultCertSearchRoot = certRoot
	t.Cleanup(func() { defaultCertSearchRoot = prevRoot })

	domainDir := filepath.Join(certRoot, "xui.example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(443001),
		Subject:      pkix.Name{CommonName: "xui.example.com"},
		DNSNames:     []string{"xui.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey failed: %v", err)
	}
	certPath := filepath.Join(domainDir, "fullchain.pem")
	keyPath := filepath.Join(domainDir, "privkey.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	settingSvc := &SettingService{}
	if err := settingSvc.SetPort(443); err != nil {
		t.Fatalf("SetPort(443) failed: %v", err)
	}

	gwSvc := &GatewayService{}
	statusBefore, err := gwSvc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if !statusBefore.HasPanelCert || statusBefore.CertFile != certPath || statusBefore.Domain != "xui.example.com" {
		t.Fatalf("expected detected x-ui cert & domain before bootstrap, got %+v", statusBefore)
	}

	res, err := gwSvc.Bootstrap443Stack("xui.example.com", BootstrapRequest{
		Domain:      "xui.example.com",
		PublicPort:  443,
		AcmeMode:    "existing-cert",
		PresetIDs:   []string{"singbox-hysteria2-443", "xray-vless-reality-vision-443"},
		RealityDest: "www.microsoft.com:443",
		RealitySNI:  "www.microsoft.com",
	})
	if err != nil {
		t.Fatalf("Bootstrap443Stack with existing x-ui cert failed: %v", err)
	}
	if !res.RestartPanelNeeded {
		t.Fatalf("expected RestartPanelNeeded=true when webPort==443")
	}
	if newPort, _ := settingSvc.GetPort(); newPort == 443 || newPort <= 0 {
		t.Fatalf("expected panel port relocated off 443, got %d", newPort)
	}
	if cf, _ := settingSvc.GetCertFile(); cf != certPath {
		t.Fatalf("expected saved webCertFile=%q, got %q", certPath, cf)
	}
	if kf, _ := settingSvc.GetKeyFile(); kf != keyPath {
		t.Fatalf("expected saved webKeyFile=%q, got %q", keyPath, kf)
	}
	if mode, _ := settingSvc.GetAcmeMode(); mode != "existing_cert" {
		t.Fatalf("expected normalized acmeMode=existing_cert, got %q", mode)
	}

	inbounds, err := (&InboundService{}).GetInbounds(1)
	if err != nil || len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got len=%d err=%v", len(inbounds), err)
	}
	var hy2 *model.Inbound
	for _, ib := range inbounds {
		if ib.Protocol == model.Hysteria {
			hy2 = ib
		}
	}
	if hy2 == nil {
		t.Fatalf("expected hysteria2 inbound, got none")
	}
	var streamObj struct {
		TLSSettings struct {
			Certificates []struct {
				CertificateFile string `json:"certificateFile"`
				KeyFile         string `json:"keyFile"`
			} `json:"certificates"`
		} `json:"tlsSettings"`
	}
	if err := json.Unmarshal([]byte(hy2.StreamSettings), &streamObj); err != nil {
		t.Fatalf("unmarshal hysteria2 StreamSettings: %v", err)
	}
	if len(streamObj.TLSSettings.Certificates) == 0 ||
		streamObj.TLSSettings.Certificates[0].CertificateFile != certPath ||
		streamObj.TLSSettings.Certificates[0].KeyFile != keyPath {
		t.Fatalf("expected hysteria2 inbound streamSettings to reference x-ui cert/key, got %s", hy2.StreamSettings)
	}
}
