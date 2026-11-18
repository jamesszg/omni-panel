package template

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/singbox"
)

func TestAllBuiltInTemplatesInstantiateAndValidate(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())

	templates := GetBuiltInTemplates()
	if len(templates) != 9 {
		t.Fatalf("got %d built-in templates, want 9", len(templates))
	}

	var singboxInbounds []*model.Inbound
	for i, spec := range templates {
		ib, client, err := InstantiateTemplate(spec.ID, InstantiateOptions{
			GatewayDomain: "gw.example.com",
			RealitySNI:    "www.microsoft.com",
			RealityDest:   "www.microsoft.com:443",
			ClientEmail:   "u-" + spec.ID,
			SubID:         "sharedsub",
			LoopbackPort:  30200 + i,
			PublicPort:    443,
		})
		if err != nil {
			t.Fatalf("InstantiateTemplate(%q) failed: %v", spec.ID, err)
		}
		ib.Id = i + 1
		ib.Tag = "tag-" + spec.ID

		warnings, err := ValidateInboundConstraints(ib, nil, "gw.example.com")
		if err != nil {
			t.Fatalf("ValidateInboundConstraints(%q) unexpected error: %v (warnings=%v)", spec.ID, err, warnings)
		}

		sbOut, err := BuildSingboxClientOutbound("gw.example.com", 443, "gw.example.com", ib, client)
		if err != nil {
			t.Fatalf("BuildSingboxClientOutbound(%q) failed: %v", spec.ID, err)
		}
		var outObj map[string]any
		if err := json.Unmarshal([]byte(sbOut), &outObj); err != nil {
			t.Fatalf("BuildSingboxClientOutbound(%q) invalid JSON: %v", spec.ID, err)
		}
		if portVal, _ := outObj["server_port"].(float64); int(portVal) != 443 {
			t.Fatalf("template %q client outbound server_port = %v, want 443", spec.ID, portVal)
		}

		if ib.EffectiveCore() == "singbox" {
			singboxInbounds = append(singboxInbounds, ib)
		}
	}

	raw, err := singbox.BuildConfig(singboxInbounds, 62795, "secret")
	if err != nil {
		t.Fatalf("singbox.BuildConfig failed: %v", err)
	}
	binPath, err := singbox.FindBinary()
	if err != nil {
		t.Skipf("sing-box binary not found: %v", err)
	}
	if err := singbox.ValidateConfig(binPath, raw); err != nil {
		t.Fatalf("singbox.ValidateConfig rejected template outputs: %v\n%s", err, string(raw))
	}
}

func TestValidateInboundConstraintsRejectsAndWarns(t *testing.T) {
	// 1. Hysteria2 with h2 ALPN must be rejected.
	hy2BadALPN := &model.Inbound{
		Id:             1,
		Enable:         true,
		Core:           "singbox",
		Protocol:       model.Hysteria,
		Port:           443,
		StreamSettings: `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h2"]}}`,
	}
	if _, err := ValidateInboundConstraints(hy2BadALPN, nil, "gw.example.com"); err == nil {
		t.Fatal("expected error when Hysteria uses h2 ALPN")
	}

	// 2. WebSocket with h2-only ALPN must be rejected.
	wsBadALPN := &model.Inbound{
		Id:             2,
		Enable:         true,
		Protocol:       model.VLESS,
		Port:           30101,
		StreamSettings: `{"network":"ws","security":"tls","tlsSettings":{"alpn":["h2"]}}`,
	}
	if _, err := ValidateInboundConstraints(wsBadALPN, nil, "gw.example.com"); err == nil {
		t.Fatal("expected error when WS omits http/1.1 ALPN")
	}

	// 3. REALITY SNI matching own gatewayDomain must be rejected.
	realityOwnDom := &model.Inbound{
		Id:             3,
		Enable:         true,
		Protocol:       model.VLESS,
		Port:           30102,
		GatewayMode:    "rpxy_sni",
		GatewaySNI:     "gw.example.com",
		StreamSettings: `{"network":"tcp","security":"reality","realitySettings":{"serverNames":["gw.example.com"]}}`,
	}
	if _, err := ValidateInboundConstraints(realityOwnDom, nil, "gw.example.com"); err == nil {
		t.Fatal("expected error when REALITY uses own gateway domain")
	}

	// 4. Duplicate rpxy_sni host rejected.
	existing := []*model.Inbound{
		{Id: 10, Tag: "existing-sni", Enable: true, Protocol: model.VLESS, GatewayMode: "rpxy_sni", GatewaySNI: "www.microsoft.com"},
		{Id: 11, Tag: "existing-l7", Enable: true, Protocol: model.VLESS, GatewayMode: "l7_path", GatewayPath: "/ws-1"},
		{Id: 12, Tag: "existing-hy2", Enable: true, Protocol: model.Hysteria, Core: "singbox", GatewayMode: "rpxy_quic", PublicPort: 443, GatewaySNI: "hy2.gw.example.com"},
	}
	dupSNI := &model.Inbound{Id: 13, Enable: true, Protocol: model.AnyTLS, GatewayMode: "rpxy_sni", GatewaySNI: "www.microsoft.com"}
	if _, err := ValidateInboundConstraints(dupSNI, existing, "gw.example.com"); err == nil {
		t.Fatal("expected error for duplicate rpxy_sni SNI")
	}

	// 5. Duplicate l7_path rejected.
	dupPath := &model.Inbound{Id: 14, Enable: true, Protocol: model.VLESS, GatewayMode: "l7_path", GatewayPath: "/ws-1"}
	if _, err := ValidateInboundConstraints(dupPath, existing, "gw.example.com"); err == nil {
		t.Fatal("expected error for duplicate l7_path")
	}

	// 6. Second QUIC inbound on :443 warns about LimitIP unavailability.
	tuicSecond := &model.Inbound{
		Id:             15,
		Enable:         true,
		Core:           "singbox",
		Protocol:       model.TUIC,
		Port:           30120,
		PublicPort:     443,
		GatewayMode:    "rpxy_quic",
		GatewaySNI:     "tuic.gw.example.com",
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"alpn":["h3"]}}`,
	}
	warnings, err := ValidateInboundConstraints(tuicSecond, existing, "gw.example.com")
	if err != nil {
		t.Fatalf("unexpected error for second QUIC inbound with distinct SNI: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "LimitIP") {
		t.Fatalf("expected LimitIP warning when sharing :443/UDP, got %v", warnings)
	}
}
