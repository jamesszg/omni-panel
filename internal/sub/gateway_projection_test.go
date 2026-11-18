package sub

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamesszg/omni-panel/internal/database/dbtest"
	"github.com/jamesszg/omni-panel/internal/database/model"
)

func TestGatewayProjectionAndNewProtocolShareLinks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	dbtest.InitDB(t, filepath.Join(dir, "x-ui.db"))

	svc := NewSubService("")
	_ = svc.settingService.SetGatewayDomain("edge.example.com")
	_ = svc.settingService.SetGatewayPublicPort(443)
	svc.PrepareForRequest("edge.example.com")

	// 1. VLESS + XHTTP behind L7 TLS gateway on loopback: link must advertise :443 + tls + h2 + gateway domain.
	xhttpIb := &model.Inbound{
		Id:             101,
		Enable:         true,
		Remark:         "XHTTP-L7",
		Core:           "xray",
		Listen:         "127.0.0.1",
		Port:           30102,
		Protocol:       model.VLESS,
		GatewayMode:    "l7_path",
		GatewaySNI:     "edge.example.com",
		GatewayPath:    "/xhttp-abc",
		PublicPort:     443,
		Settings:       `{"clients":[{"id":"11111111-1111-4111-8111-111111111111","email":"xhttp@test","enable":true}]}`,
		StreamSettings: `{"network":"xhttp","security":"none","xhttpSettings":{"path":"/xhttp-abc","mode":"auto"}}`,
	}
	svc.projectThroughFallbackMaster(xhttpIb)
	xhttpLink := svc.GetLink(xhttpIb, "xhttp@test")
	u, err := url.Parse(xhttpLink)
	if err != nil {
		t.Fatalf("parse xhttp link %q: %v", xhttpLink, err)
	}
	if u.Host != "edge.example.com:443" {
		t.Fatalf("xhttp link host = %q, want edge.example.com:443", u.Host)
	}
	if u.Query().Get("security") != "tls" || u.Query().Get("sni") != "edge.example.com" || u.Query().Get("alpn") != "h2" {
		t.Fatalf("unexpected xhttp projected params: %v", u.Query())
	}

	// 2. AnyTLS link behind rust-rpxy-l4 SNI passthrough.
	anytlsIb := &model.Inbound{
		Id:             102,
		Enable:         true,
		Remark:         "AnyTLS",
		Core:           "singbox",
		Listen:         "127.0.0.1",
		Port:           30103,
		Protocol:       model.AnyTLS,
		GatewayMode:    "rpxy_sni",
		GatewaySNI:     "anytls.example.com",
		PublicPort:     443,
		Settings:       `{"clients":[{"password":"secret-pass","email":"anytls@test","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"anytls.example.com","alpn":["h2","http/1.1"]}}`,
	}
	svc.projectThroughFallbackMaster(anytlsIb)
	anytlsLink := svc.GetLink(anytlsIb, "anytls@test")
	if !strings.HasPrefix(anytlsLink, "anytls://secret-pass@edge.example.com:443") || !strings.Contains(anytlsLink, "sni=anytls.example.com") {
		t.Fatalf("unexpected anytls share link: %q", anytlsLink)
	}

	// 3. Sing-box TUIC v5 share link projection.
	tuicIb := &model.Inbound{
		Id:             103,
		Enable:         true,
		Remark:         "TUIC-SB",
		Core:           "singbox",
		Listen:         "127.0.0.1",
		Port:           30104,
		Protocol:       model.TUIC,
		GatewayMode:    "rpxy_quic",
		GatewaySNI:     "tuic.example.com",
		PublicPort:     443,
		Settings:       `{"congestion_control":"bbr","clients":[{"id":"22222222-2222-4222-8222-222222222222","password":"tuic-pw","email":"tuic@test","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"tuic.example.com","alpn":["h3"]}}`,
	}
	svc.projectThroughFallbackMaster(tuicIb)
	tuicLink := svc.GetLink(tuicIb, "tuic@test")
	if !strings.HasPrefix(tuicLink, "tuic://22222222-2222-4222-8222-222222222222:tuic-pw@edge.example.com:443") || !strings.Contains(tuicLink, "alpn=h3") {
		t.Fatalf("unexpected sing-box tuic share link: %q", tuicLink)
	}
}
