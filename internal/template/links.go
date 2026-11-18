package template

import (
	"encoding/json"
	"strings"

	"github.com/jamesszg/omni-panel/internal/database/model"
)

// ClientShareBundle represents authoritative share artifacts for a single client on an inbound.
type ClientShareBundle struct {
	Email               string   `json:"email"`
	Protocol            string   `json:"protocol"`
	Core                string   `json:"core"`
	URI                 string   `json:"uri"`
	SingboxOutboundJSON string   `json:"singboxOutboundJson,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

// BuildSingboxClientOutbound renders a copy-pasteable upstream sing-box client outbound JSON snippet.
func BuildSingboxClientOutbound(host string, gatewayPort int, gatewayDomain string, ib *model.Inbound, client model.Client) (string, error) {
	if ib == nil {
		return "", nil
	}
	server := strings.TrimSpace(host)
	if ib.ShareAddrStrategy == "custom" && strings.TrimSpace(ib.ShareAddr) != "" {
		server = strings.TrimSpace(ib.ShareAddr)
	}
	if server == "" {
		server = strings.TrimSpace(gatewayDomain)
	}
	if server == "" {
		server = "YOUR_SERVER_HOST"
	}

	port := ib.Port
	if ib.PublicPort > 0 {
		port = ib.PublicPort
	} else if ib.GatewayMode == "rpxy_sni" || ib.GatewayMode == "rpxy_quic" || ib.GatewayMode == "l7_path" {
		if gatewayPort > 0 {
			port = gatewayPort
		} else {
			port = 443
		}
	}

	var stream map[string]any
	_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)
	var settings map[string]any
	_ = json.Unmarshal([]byte(ib.Settings), &settings)

	sni := firstNonEmpty(ib.GatewaySNI, extractTLSSNI(stream), gatewayDomain, server)
	out := map[string]any{
		"tag":         ib.Tag,
		"server":      server,
		"server_port": port,
	}

	switch ib.Protocol {
	case model.Hysteria:
		out["type"] = "hysteria2"
		out["password"] = firstNonEmpty(client.Auth, client.Password, client.ID)
		out["tls"] = map[string]any{
			"enabled":     true,
			"server_name": sni,
			"alpn":        []string{"h3"},
		}
	case model.TUIC:
		out["type"] = "tuic"
		out["uuid"] = client.ID
		out["password"] = firstNonEmpty(client.Password, client.ID)
		out["congestion_control"] = "bbr"
		out["tls"] = map[string]any{
			"enabled":     true,
			"server_name": sni,
			"alpn":        []string{"h3"},
		}
	case model.AnyTLS:
		out["type"] = "anytls"
		out["password"] = firstNonEmpty(client.Password, client.ID)
		out["tls"] = map[string]any{
			"enabled":     true,
			"server_name": sni,
		}
	case model.ShadowTLS:
		out["type"] = "shadowtls"
		out["version"] = 3
		out["password"] = firstNonEmpty(client.Password, client.ID)
		hsServer, _ := settings["handshakeServer"].(string)
		out["tls"] = map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(hsServer, sni),
		}
	case model.VLESS:
		out["type"] = "vless"
		out["uuid"] = client.ID
		if client.Flow != "" && ib.GatewayMode != "l7_path" {
			out["flow"] = client.Flow
		}
		applyClientStreamFields(out, ib, stream, sni)
	case model.Trojan:
		out["type"] = "trojan"
		out["password"] = firstNonEmpty(client.Password, client.ID)
		applyClientStreamFields(out, ib, stream, sni)
	default:
		return "", nil
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func extractTLSSNI(stream map[string]any) string {
	if stream == nil {
		return ""
	}
	if tlsObj, ok := stream["tlsSettings"].(map[string]any); ok {
		if sni, ok2 := tlsObj["serverName"].(string); ok2 && sni != "" {
			return sni
		}
	}
	if rs, ok := stream["realitySettings"].(map[string]any); ok {
		if arr, ok2 := rs["serverNames"].([]any); ok2 && len(arr) > 0 {
			if sni, ok3 := arr[0].(string); ok3 {
				return sni
			}
		}
	}
	return ""
}

func applyClientStreamFields(out map[string]any, ib *model.Inbound, stream map[string]any, sni string) {
	sec, _ := stream["security"].(string)
	if sec == "reality" {
		rs, _ := stream["realitySettings"].(map[string]any)
		rsInner, _ := rs["settings"].(map[string]any)
		pbk, _ := rsInner["publicKey"].(string)
		var sid string
		if sids, ok := rs["shortIds"].([]any); ok && len(sids) > 0 {
			sid, _ = sids[0].(string)
		}
		out["tls"] = map[string]any{
			"enabled":     true,
			"server_name": sni,
			"utls": map[string]any{
				"enabled":     true,
				"fingerprint": "chrome",
			},
			"reality": map[string]any{
				"enabled":    true,
				"public_key": pbk,
				"short_id":   sid,
			},
		}
		return
	}

	if sec == "tls" || ib.GatewayMode == "l7_path" {
		tlsOut := map[string]any{
			"enabled":     true,
			"server_name": sni,
		}
		netType, _ := stream["network"].(string)
		if ib.GatewayMode == "l7_path" {
			switch netType {
			case "ws", "httpupgrade":
				tlsOut["alpn"] = []string{"http/1.1"}
			case "grpc", "xhttp", "http":
				tlsOut["alpn"] = []string{"h2"}
			}
		}
		out["tls"] = tlsOut
	}

	netType, _ := stream["network"].(string)
	switch netType {
	case "ws":
		path := firstNonEmpty(ib.GatewayPath, "/")
		out["transport"] = map[string]any{"type": "ws", "path": path}
	case "httpupgrade":
		path := firstNonEmpty(ib.GatewayPath, "/")
		out["transport"] = map[string]any{"type": "httpupgrade", "path": path}
	case "grpc":
		gs, _ := stream["grpcSettings"].(map[string]any)
		svc, _ := gs["serviceName"].(string)
		out["transport"] = map[string]any{
			"type":         "grpc",
			"service_name": firstNonEmpty(svc, strings.TrimPrefix(ib.GatewayPath, "/")),
		}
	case "xhttp", "http":
		path := firstNonEmpty(ib.GatewayPath, "/")
		out["transport"] = map[string]any{"type": "http", "path": path}
	}
}
