// Package template provides strictly-validated built-in proxy templates,
// constraint validation, one-click stack instantiation, and client share bundles.
package template

import "github.com/jamesszg/omni-panel/internal/database/model"

// TemplateSpec describes a curated, pre-validated proxy configuration template.
type TemplateSpec struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	Core            string         `json:"core"`
	Protocol        model.Protocol `json:"protocol"`
	Transport       string         `json:"transport"`
	Security        string         `json:"security"`
	GatewayMode     string         `json:"gatewayMode"`
	RecommendedALPN []string       `json:"recommendedAlpn,omitempty"`
	DefaultPort     int            `json:"defaultPort"`
	OneClickPreset  bool           `json:"oneClickPreset"`
	Restrictions    []string       `json:"restrictions"`
}

var builtInTemplates = []TemplateSpec{
	{
		ID:              "singbox-hysteria2-443",
		Name:            "Hysteria2 (sing-box · :443 UDP)",
		Description:     "High-throughput QUIC-based Hysteria2 bound to upstream sing-box on :443/UDP.",
		Core:            "singbox",
		Protocol:        model.Hysteria,
		Transport:       "hysteria",
		Security:        "tls",
		GatewayMode:     "rpxy_quic",
		RecommendedALPN: []string{"h3"},
		DefaultPort:     443,
		OneClickPreset:  true,
		Restrictions: []string{
			"Uses QUIC over UDP; ALPN must be 'h3' only (never 'h2' or 'http/1.1').",
			"Binds :443/UDP directly when it is the only QUIC inbound; sharing :443/UDP with another QUIC inbound enables rust-rpxy-l4 mux and disables LimitIP.",
		},
	},
	{
		ID:              "singbox-tuic-v5-443",
		Name:            "TUIC v5 (sing-box · :443 UDP)",
		Description:     "Low-latency 0-RTT QUIC TUIC v5 bound to upstream sing-box with BBR congestion control.",
		Core:            "singbox",
		Protocol:        model.TUIC,
		Transport:       "quic",
		Security:        "tls",
		GatewayMode:     "rpxy_quic",
		RecommendedALPN: []string{"h3"},
		DefaultPort:     443,
		OneClickPreset:  false,
		Restrictions: []string{
			"Uses QUIC over UDP; ALPN must be 'h3' only (never 'h2' or 'http/1.1').",
			"When coexisting with Hysteria2 on :443/UDP, distinct SNIs are required and LimitIP is unavailable behind UDP forwarding.",
		},
	},
	{
		ID:              "singbox-anytls-443",
		Name:            "AnyTLS (sing-box · :443 SNI Passthrough)",
		Description:     "Modern TLS obfuscation protocol on upstream sing-box behind rust-rpxy-l4 SNI routing.",
		Core:            "singbox",
		Protocol:        model.AnyTLS,
		Transport:       "tcp",
		Security:        "tls",
		GatewayMode:     "rpxy_sni",
		RecommendedALPN: []string{"h2", "http/1.1"},
		DefaultPort:     30103,
		OneClickPreset:  false,
		Restrictions: []string{
			"Requires a dedicated gatewaySni distinct from other :443 TCP passthrough inbounds.",
			"Supported exclusively on upstream sing-box core.",
		},
	},
	{
		ID:             "singbox-vless-reality-443",
		Name:           "VLESS + REALITY (sing-box · :443 SNI Passthrough)",
		Description:    "Certificate-free REALITY camouflage on upstream sing-box via rust-rpxy-l4 SNI routing.",
		Core:           "singbox",
		Protocol:       model.VLESS,
		Transport:      "tcp",
		Security:       "reality",
		GatewayMode:    "rpxy_sni",
		DefaultPort:    30104,
		OneClickPreset: false,
		Restrictions: []string{
			"Target/SNI must be a stolen foreign TLS 1.3 + H2 domain, never your own gateway domain.",
			"Uses RawURL unpadded Base64 private keys on sing-box.",
		},
	},
	{
		ID:             "xray-vless-reality-vision-443",
		Name:           "VLESS + REALITY + Vision (Xray · :443 SNI Passthrough)",
		Description:    "Flagship TCP + REALITY + xtls-rprx-vision on Xray-core with PROXY protocol v2 client IP preservation.",
		Core:           "xray",
		Protocol:       model.VLESS,
		Transport:      "tcp",
		Security:       "reality",
		GatewayMode:    "rpxy_sni",
		DefaultPort:    30101,
		OneClickPreset: true,
		Restrictions: []string{
			"Target/SNI must be a foreign TLS 1.3 + H2 domain, never your own gateway domain.",
			"Requires acceptProxyProtocol=true on Xray socket when routed through rust-rpxy-l4.",
		},
	},
	{
		ID:              "xray-vless-xhttp-l7-443",
		Name:            "VLESS + XHTTP (Xray · :443 L7 TLS Gateway)",
		Description:     "CDN-friendly XHTTP transport behind the embedded L7 TLS gateway with zero extra ports.",
		Core:            "xray",
		Protocol:        model.VLESS,
		Transport:       "xhttp",
		Security:        "none",
		GatewayMode:     "l7_path",
		RecommendedALPN: []string{"h2"},
		DefaultPort:     30102,
		OneClickPreset:  true,
		Restrictions: []string{
			"Requires a unique non-root gatewayPath (e.g. /xhttp-...) and a configured gateway domain TLS certificate.",
			"Internal listener terminates plaintext on 127.0.0.1 while :443 L7 gateway handles public TLS.",
		},
	},
	{
		ID:              "xray-vless-ws-l7-443",
		Name:            "VLESS + WebSocket (Xray · :443 L7 TLS Gateway)",
		Description:     "Universal WebSocket transport behind the embedded L7 TLS gateway.",
		Core:            "xray",
		Protocol:        model.VLESS,
		Transport:       "ws",
		Security:        "none",
		GatewayMode:     "l7_path",
		RecommendedALPN: []string{"http/1.1"},
		DefaultPort:     30105,
		OneClickPreset:  false,
		Restrictions: []string{
			"WebSocket Upgrade requires ALPN 'http/1.1' (never h2-only or h3).",
			"Requires a unique gatewayPath distinct from panel/sub paths.",
		},
	},
	{
		ID:              "xray-trojan-grpc-l7-443",
		Name:            "Trojan + gRPC (Xray · :443 L7 TLS Gateway)",
		Description:     "Multiplexed gRPC h2c backend behind the embedded L7 TLS gateway.",
		Core:            "xray",
		Protocol:        model.Trojan,
		Transport:       "grpc",
		Security:        "none",
		GatewayMode:     "l7_path",
		RecommendedALPN: []string{"h2"},
		DefaultPort:     30106,
		OneClickPreset:  false,
		Restrictions: []string{
			"Requires ALPN 'h2' and HTTP/2 cleartext (h2c) between L7 gateway and Xray backend.",
			"Requires a unique gatewayPath matching the gRPC serviceName.",
		},
	},
	{
		ID:             "singbox-shadowtls-v3-443",
		Name:           "ShadowTLS v3 (sing-box · :443 SNI Passthrough)",
		Description:    "ShadowTLS v3 TLS-handshake camouflage on upstream sing-box behind rust-rpxy-l4.",
		Core:           "singbox",
		Protocol:       model.ShadowTLS,
		Transport:      "tcp",
		Security:       "tls",
		GatewayMode:    "rpxy_sni",
		DefaultPort:    30107,
		OneClickPreset: false,
		Restrictions: []string{
			"Supported exclusively on upstream sing-box core.",
			"Requires a dedicated foreign handshake SNI distinct from other :443 TCP passthrough rules.",
		},
	},
}

// GetBuiltInTemplates returns a copy of all curated standard templates.
func GetBuiltInTemplates() []TemplateSpec {
	out := make([]TemplateSpec, len(builtInTemplates))
	for i, tpl := range builtInTemplates {
		if tpl.RecommendedALPN != nil {
			tpl.RecommendedALPN = append([]string(nil), tpl.RecommendedALPN...)
		}
		if tpl.Restrictions != nil {
			tpl.Restrictions = append([]string(nil), tpl.Restrictions...)
		}
		out[i] = tpl
	}
	return out
}

// FindTemplate resolves a built-in template specification by ID.
func FindTemplate(id string) (TemplateSpec, bool) {
	for _, tpl := range builtInTemplates {
		if tpl.ID == id {
			return tpl, true
		}
	}
	return TemplateSpec{}, false
}
