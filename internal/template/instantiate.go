package template

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/jamesszg/omni-panel/internal/database/model"
)

// InstantiateOptions parameterizes creation of an inbound and initial client from a template.
type InstantiateOptions struct {
	GatewayDomain string
	RealityDest   string
	RealitySNI    string
	ClientEmail   string
	SubID         string
	LoopbackPort  int
	PublicPort    int
	Remark        string
	ServerName    string
	CertFile      string
	KeyFile       string
}

func buildInboundTLS(serverName string, alpn []string, opts InstantiateOptions) map[string]any {
	tls := map[string]any{
		"serverName": serverName,
		"alpn":       alpn,
	}
	if certFile := strings.TrimSpace(opts.CertFile); certFile != "" {
		if keyFile := strings.TrimSpace(opts.KeyFile); keyFile != "" {
			tls["certificates"] = []map[string]any{
				{
					"certificateFile": certFile,
					"keyFile":         keyFile,
				},
			}
		}
	}
	return tls
}

// InstantiateTemplate creates a ready-to-save model.Inbound and initial model.Client
// conforming to templateID's protocol, core, and gateway constraints.
func InstantiateTemplate(templateID string, opts InstantiateOptions) (*model.Inbound, model.Client, error) {
	spec, ok := FindTemplate(templateID)
	if !ok {
		return nil, model.Client{}, fmt.Errorf("unknown template %q", templateID)
	}

	email := strings.TrimSpace(opts.ClientEmail)
	if email == "" {
		email = randomToken(4) + "@" + strings.ReplaceAll(spec.ID, "-", ".")
	}
	subID := strings.TrimSpace(opts.SubID)
	if subID == "" {
		subID = randomToken(8)
	}
	pubPort := opts.PublicPort
	if pubPort <= 0 {
		pubPort = 443
	}
	remark := strings.TrimSpace(opts.Remark)
	if remark == "" {
		remark = spec.Name
	}

	realitySNI := strings.TrimSpace(opts.RealitySNI)
	if realitySNI == "" {
		realitySNI = "www.microsoft.com"
	}
	realityDest := strings.TrimSpace(opts.RealityDest)
	if realityDest == "" {
		realityDest = realitySNI + ":443"
	}

	serverName := strings.TrimSpace(opts.ServerName)
	if serverName == "" {
		serverName = strings.TrimSpace(opts.GatewayDomain)
	}

	client := model.Client{
		ID:     uuid.NewString(),
		Email:  email,
		Enable: true,
		SubID:  subID,
	}

	ib := &model.Inbound{
		Enable:     true,
		Remark:     remark,
		Core:       spec.Core,
		Protocol:   spec.Protocol,
		PublicPort: pubPort,
		TemplateId: spec.ID,
		Sniffing:   `{"enabled":true,"destOverride":["http","tls","quic","fakedns"],"metadataOnly":false,"routeOnly":false}`,
	}

	switch spec.ID {
	case "singbox-hysteria2-443":
		ib.Listen = "0.0.0.0"
		ib.Port = opts.LoopbackPort
		if ib.Port <= 0 {
			ib.Port = pubPort
		}
		ib.GatewayMode = "rpxy_quic"
		ib.GatewaySNI = serverName
		client.Auth = randomToken(16)
		ib.Settings = mustJSON(map[string]any{
			"clients": []model.Client{client},
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":     "hysteria",
			"security":    "tls",
			"tlsSettings": buildInboundTLS(serverName, []string{"h3"}, opts),
		})

	case "singbox-tuic-v5-443":
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "rpxy_quic"
		ib.GatewaySNI = firstNonEmpty(serverName, "tuic.example.com")
		client.Password = randomToken(16)
		ib.Settings = mustJSON(map[string]any{
			"congestion_control": "bbr",
			"zero_rtt_handshake": true,
			"clients":            []model.Client{client},
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":     "tcp",
			"security":    "tls",
			"tlsSettings": buildInboundTLS(ib.GatewaySNI, []string{"h3"}, opts),
		})

	case "singbox-anytls-443":
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "rpxy_sni"
		ib.GatewaySNI = firstNonEmpty(serverName, "anytls-"+randomToken(3)+".local")
		client.Password = randomToken(16)
		ib.Settings = mustJSON(map[string]any{
			"paddingScheme": []string{
				"stop=8",
				"0=30-30",
				"1=100-400",
				"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
			},
			"clients": []model.Client{client},
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":     "tcp",
			"security":    "tls",
			"tlsSettings": buildInboundTLS(ib.GatewaySNI, []string{"h2", "http/1.1"}, opts),
		})

	case "singbox-vless-reality-443", "xray-vless-reality-vision-443":
		privKey, pubKey, err := generateX25519KeyPair()
		if err != nil {
			return nil, model.Client{}, err
		}
		shortID := randomToken(4)
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "rpxy_sni"
		ib.GatewaySNI = realitySNI
		client.Flow = "xtls-rprx-vision"
		ib.Settings = mustJSON(map[string]any{
			"clients":    []model.Client{client},
			"decryption": "none",
			"encryption": "none",
		})
		stream := map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"show":        false,
				"dest":        realityDest,
				"target":      realityDest,
				"serverNames": []string{realitySNI},
				"privateKey":  privKey,
				"shortIds":    []string{shortID},
				"settings": map[string]any{
					"publicKey":   pubKey,
					"fingerprint": "chrome",
					"spiderX":     "/",
				},
			},
		}
		if spec.Core == "xray" {
			stream["tcpSettings"] = map[string]any{
				"acceptProxyProtocol": true,
				"header":              map[string]any{"type": "none"},
			}
		}
		ib.StreamSettings = mustJSON(stream)

	case "xray-vless-xhttp-l7-443":
		l7Path := "/xhttp-" + randomToken(4)
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "l7_path"
		ib.GatewaySNI = serverName
		ib.GatewayPath = l7Path
		ib.Settings = mustJSON(map[string]any{
			"clients":    []model.Client{client},
			"decryption": "none",
			"encryption": "none",
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":  "xhttp",
			"security": "none",
			"xhttpSettings": map[string]any{
				"path": l7Path,
				"mode": "auto",
			},
		})

	case "xray-vless-ws-l7-443":
		l7Path := "/ws-" + randomToken(4)
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "l7_path"
		ib.GatewaySNI = serverName
		ib.GatewayPath = l7Path
		ib.Settings = mustJSON(map[string]any{
			"clients":    []model.Client{client},
			"decryption": "none",
			"encryption": "none",
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":  "ws",
			"security": "none",
			"wsSettings": map[string]any{
				"path": l7Path,
			},
		})

	case "xray-trojan-grpc-l7-443":
		svcName := "grpc-" + randomToken(4)
		l7Path := "/" + svcName
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "l7_path"
		ib.GatewaySNI = serverName
		ib.GatewayPath = l7Path
		client.Password = randomToken(16)
		ib.Settings = mustJSON(map[string]any{
			"clients": []model.Client{client},
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":  "grpc",
			"security": "none",
			"grpcSettings": map[string]any{
				"serviceName": svcName,
			},
		})

	case "singbox-shadowtls-v3-443":
		ib.Listen = "127.0.0.1"
		ib.Port = defaultPort(opts.LoopbackPort, spec.DefaultPort)
		ib.GatewayMode = "rpxy_sni"
		ib.GatewaySNI = realitySNI
		client.Password = randomToken(16)
		ib.Settings = mustJSON(map[string]any{
			"handshakeServer": realitySNI,
			"handshakePort":   443,
			"clients":         []model.Client{client},
		})
		ib.StreamSettings = mustJSON(map[string]any{
			"network":  "tcp",
			"security": "tls",
			"tlsSettings": map[string]any{
				"serverName": realitySNI,
			},
		})
	}

	return ib, client, nil
}

func defaultPort(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func randomToken(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateX25519KeyPair() (privStr, pubStr string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privStr = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubStr = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privStr, pubStr, nil
}

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
