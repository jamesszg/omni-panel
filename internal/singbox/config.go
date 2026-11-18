// Package singbox manages upstream SagerNet/sing-box child processes,
// translates omni-panel inbounds into sing-box JSON configurations, validates
// configs via `sing-box check`, and collects per-connection traffic via Clash API.
package singbox

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jamesszg/omni-panel/internal/config"
	"github.com/jamesszg/omni-panel/internal/database/model"
)

var (
	fallbackCertMu   sync.Mutex
	fallbackCertDone bool
)

// FallbackCertPaths returns the shared self-signed certificate paths used when a
// sing-box TLS inbound (e.g., Hysteria2, TUIC, AnyTLS) has no explicit cert configured.
func FallbackCertPaths() (certPath, keyPath string) {
	dir := filepath.Join(config.GetBinFolderPath(), "singbox", "certs")
	return filepath.Join(dir, "fallback.crt"), filepath.Join(dir, "fallback.key")
}

// EnsureFallbackCert guarantees that a self-signed certificate pair exists at FallbackCertPaths.
func EnsureFallbackCert(sni string) (string, string, error) {
	fallbackCertMu.Lock()
	defer fallbackCertMu.Unlock()

	certPath, keyPath := FallbackCertPaths()
	if fallbackCertDone {
		if _, err := os.Stat(certPath); err == nil {
			if _, err2 := os.Stat(keyPath); err2 == nil {
				return certPath, keyPath, nil
			}
		}
	}
	if _, err := os.Stat(certPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			fallbackCertDone = true
			return certPath, keyPath, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return "", "", err
	}
	if sni == "" {
		sni = "localhost"
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	fallbackCertDone = true
	return certPath, keyPath, nil
}

// BuildConfig builds a full upstream sing-box JSON configuration for all enabled
// local inbounds whose EffectiveCore() == "singbox".
func BuildConfig(inbounds []*model.Inbound, clashPort int, clashSecret string) ([]byte, error) {
	if clashPort <= 0 {
		clashPort = 62795
	}

	sbInbounds := make([]map[string]any, 0, len(inbounds))
	for _, ib := range inbounds {
		if ib == nil || !ib.Enable || ib.NodeID != nil {
			continue
		}
		if ib.EffectiveCore() != "singbox" {
			continue
		}
		entry, err := convertInbound(ib)
		if err != nil {
			return nil, fmt.Errorf("inbound %q (%s): %w", ib.Tag, ib.Protocol, err)
		}
		if strings.TrimSpace(ib.ConfigOverride) != "" {
			var override map[string]any
			if err := json.Unmarshal([]byte(ib.ConfigOverride), &override); err != nil {
				return nil, fmt.Errorf("inbound %q configOverride invalid JSON: %w", ib.Tag, err)
			}
			DeepMergeMap(entry, override)
		}
		sbInbounds = append(sbInbounds, entry)
	}

	root := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": fmt.Sprintf("127.0.0.1:%d", clashPort),
				"secret":              clashSecret,
			},
		},
		"inbounds": sbInbounds,
		"outbounds": []map[string]any{
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
	}

	return json.MarshalIndent(root, "", "  ")
}

// DeepMergeMap merges keys from src into dst recursively; slices and scalars in src replace dst.
func DeepMergeMap(dst, src map[string]any) {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok2 := dst[k].(map[string]any); ok2 {
				DeepMergeMap(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}

func convertInbound(ib *model.Inbound) (map[string]any, error) {
	settings := map[string]any{}
	if strings.TrimSpace(ib.Settings) != "" {
		_ = json.Unmarshal([]byte(ib.Settings), &settings)
	}
	stream := map[string]any{}
	if strings.TrimSpace(ib.StreamSettings) != "" {
		_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)
	}

	listen := strings.TrimSpace(ib.Listen)
	if listen == "" {
		listen = "0.0.0.0"
	}

	entry := map[string]any{
		"tag":         ib.Tag,
		"listen":      listen,
		"listen_port": ib.Port,
	}

	clients := extractClients(settings)

	switch ib.Protocol {
	case model.Hysteria:
		return buildHysteria2Inbound(entry, ib, settings, stream, clients)
	case model.TUIC:
		return buildTuicInbound(entry, ib, settings, stream, clients)
	case model.AnyTLS:
		return buildAnytlsInbound(entry, ib, settings, stream, clients)
	case model.ShadowTLS:
		return buildShadowtlsInbound(entry, ib, settings, stream, clients)
	case model.VLESS:
		return buildVlessInbound(entry, ib, stream, clients)
	case model.Trojan:
		return buildTrojanInbound(entry, ib, stream, clients)
	default:
		return nil, fmt.Errorf("protocol %q is not supported by sing-box core", ib.Protocol)
	}
}

type clientWithUUIDAlias struct {
	model.Client
	UUID string `json:"uuid,omitempty"`
}

func extractClients(settings map[string]any) []model.Client {
	raw, err := json.Marshal(settings["clients"])
	if err != nil || string(raw) == "null" {
		return nil
	}
	var aliased []clientWithUUIDAlias
	if err := json.Unmarshal(raw, &aliased); err != nil {
		return nil
	}
	clients := make([]model.Client, len(aliased))
	for i, a := range aliased {
		c := a.Client
		if c.ID == "" && a.UUID != "" {
			c.ID = a.UUID
		}
		clients[i] = c
	}
	return clients
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func buildHysteria2Inbound(entry map[string]any, ib *model.Inbound, settings, stream map[string]any, clients []model.Client) (map[string]any, error) {
	entry["type"] = "hysteria2"
	users := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		pw := firstNonEmpty(c.Auth, c.Password, c.ID)
		if pw == "" {
			continue
		}
		u := map[string]any{"password": pw}
		if c.Email != "" {
			u["name"] = c.Email
		}
		users = append(users, u)
	}
	entry["users"] = users

	if obfs := extractSalamanderObfs(settings, stream); obfs != nil {
		entry["obfs"] = obfs
	}
	if up, ok := asInt(settings["upMbps"]); ok && up > 0 {
		entry["up_mbps"] = up
	}
	if down, ok := asInt(settings["downMbps"]); ok && down > 0 {
		entry["down_mbps"] = down
	}

	tlsObj, err := buildTLSObject(ib, stream, []string{"h3"})
	if err != nil {
		return nil, err
	}
	entry["tls"] = tlsObj
	return entry, nil
}

func extractSalamanderObfs(settings, stream map[string]any) map[string]any {
	if obfsMap, ok := settings["obfs"].(map[string]any); ok {
		if pw, _ := obfsMap["password"].(string); pw != "" {
			return map[string]any{"type": "salamander", "password": pw}
		}
	}
	if fm, ok := stream["finalmask"].(map[string]any); ok {
		if udp, ok := fm["udp"].([]any); ok {
			for _, item := range udp {
				m, _ := item.(map[string]any)
				if m != nil && m["type"] == "salamander" {
					ms, _ := m["settings"].(map[string]any)
					if pw, _ := ms["password"].(string); pw != "" {
						return map[string]any{"type": "salamander", "password": pw}
					}
				}
			}
		}
	}
	return nil
}

func buildTuicInbound(entry map[string]any, ib *model.Inbound, settings, stream map[string]any, clients []model.Client) (map[string]any, error) {
	entry["type"] = "tuic"

	// Support legacy nested settings.server shape as well as flat settings.
	serverBlock := settings
	if srv, ok := settings["server"].(map[string]any); ok {
		serverBlock = srv
	}

	users := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		uid := c.ID
		pw := firstNonEmpty(c.Password, uid)
		if uid == "" {
			continue
		}
		u := map[string]any{
			"uuid":     uid,
			"password": pw,
		}
		if c.Email != "" {
			u["name"] = c.Email
		}
		users = append(users, u)
	}
	entry["users"] = users

	cc, _ := serverBlock["congestion_control"].(string)
	if cc == "" {
		cc = "bbr"
	}
	entry["congestion_control"] = cc

	if z, ok := serverBlock["zero_rtt_handshake"].(bool); ok {
		entry["zero_rtt_handshake"] = z
	}
	if t, ok := asInt(serverBlock["authentication_timeout"]); ok && t > 0 {
		entry["auth_timeout"] = fmt.Sprintf("%ds", t)
	}

	tlsObj, err := buildTLSObjectWithServerFallback(ib, stream, serverBlock, []string{"h3"})
	if err != nil {
		return nil, err
	}
	entry["tls"] = tlsObj
	return entry, nil
}

func buildAnytlsInbound(entry map[string]any, ib *model.Inbound, settings, stream map[string]any, clients []model.Client) (map[string]any, error) {
	entry["type"] = "anytls"
	if ib.GatewayMode == "rpxy_sni" {
		entry["proxy_protocol"] = true
	}
	users := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		pw := firstNonEmpty(c.Password, c.ID)
		if pw == "" {
			continue
		}
		u := map[string]any{"password": pw}
		if c.Email != "" {
			u["name"] = c.Email
		}
		users = append(users, u)
	}
	entry["users"] = users

	if pad, ok := settings["paddingScheme"].([]any); ok && len(pad) > 0 {
		lines := make([]string, 0, len(pad))
		for _, p := range pad {
			if s, ok := p.(string); ok && s != "" {
				lines = append(lines, s)
			}
		}
		if len(lines) > 0 {
			entry["padding_scheme"] = lines
		}
	}

	tlsObj, err := buildTLSObject(ib, stream, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	entry["tls"] = tlsObj
	return entry, nil
}

func buildShadowtlsInbound(entry map[string]any, ib *model.Inbound, settings, _ map[string]any, clients []model.Client) (map[string]any, error) {
	entry["type"] = "shadowtls"
	entry["version"] = 3
	entry["strict_mode"] = true
	if ib.GatewayMode == "rpxy_sni" {
		entry["proxy_protocol"] = true
	}

	users := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		pw := firstNonEmpty(c.Password, c.ID)
		if pw == "" {
			continue
		}
		u := map[string]any{"password": pw}
		if c.Email != "" {
			u["name"] = c.Email
		}
		users = append(users, u)
	}
	entry["users"] = users

	handshakeServer, _ := settings["handshakeServer"].(string)
	handshakeServer = firstNonEmpty(handshakeServer, ib.GatewaySNI, "www.microsoft.com")
	handshakePort, ok := asInt(settings["handshakePort"])
	if !ok || handshakePort <= 0 {
		handshakePort = 443
	}
	entry["handshake"] = map[string]any{
		"server":      handshakeServer,
		"server_port": handshakePort,
	}

	if detour, _ := settings["detour"].(string); detour != "" {
		entry["detour"] = detour
	}
	return entry, nil
}

func buildVlessInbound(entry map[string]any, ib *model.Inbound, stream map[string]any, clients []model.Client) (map[string]any, error) {
	entry["type"] = "vless"
	if ib.GatewayMode == "rpxy_sni" {
		entry["proxy_protocol"] = true
	}
	users := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if !c.Enable || c.ID == "" {
			continue
		}
		u := map[string]any{"uuid": c.ID}
		if c.Email != "" {
			u["name"] = c.Email
		}
		if c.Flow != "" && isTcpLikeStream(stream) {
			u["flow"] = c.Flow
		}
		users = append(users, u)
	}
	entry["users"] = users

	security, _ := stream["security"].(string)
	switch security {
	case "reality":
		tlsObj, err := buildRealityTLSObject(ib, stream)
		if err != nil {
			return nil, err
		}
		entry["tls"] = tlsObj
	case "tls":
		tlsObj, err := buildTLSObject(ib, stream, []string{"h2", "http/1.1"})
		if err != nil {
			return nil, err
		}
		entry["tls"] = tlsObj
	}

	if transport := buildTransportObject(stream); transport != nil {
		entry["transport"] = transport
	}
	return entry, nil
}

func buildTrojanInbound(entry map[string]any, ib *model.Inbound, stream map[string]any, clients []model.Client) (map[string]any, error) {
	entry["type"] = "trojan"
	if ib.GatewayMode == "rpxy_sni" {
		entry["proxy_protocol"] = true
	}
	users := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		if !c.Enable {
			continue
		}
		pw := firstNonEmpty(c.Password, c.ID)
		if pw == "" {
			continue
		}
		u := map[string]any{"password": pw}
		if c.Email != "" {
			u["name"] = c.Email
		}
		users = append(users, u)
	}
	entry["users"] = users

	security, _ := stream["security"].(string)
	switch security {
	case "reality":
		tlsObj, err := buildRealityTLSObject(ib, stream)
		if err != nil {
			return nil, err
		}
		entry["tls"] = tlsObj
	case "tls", "":
		tlsObj, err := buildTLSObject(ib, stream, []string{"h2", "http/1.1"})
		if err != nil {
			return nil, err
		}
		entry["tls"] = tlsObj
	}

	if transport := buildTransportObject(stream); transport != nil {
		entry["transport"] = transport
	}
	return entry, nil
}

func isTcpLikeStream(stream map[string]any) bool {
	netType, _ := stream["network"].(string)
	return netType == "" || netType == "tcp" || netType == "raw"
}

func buildTLSObject(ib *model.Inbound, stream map[string]any, defaultALPN []string) (map[string]any, error) {
	return buildTLSObjectWithServerFallback(ib, stream, nil, defaultALPN)
}

func buildTLSObjectWithServerFallback(ib *model.Inbound, stream, serverBlock map[string]any, defaultALPN []string) (map[string]any, error) {
	tlsSettings, _ := stream["tlsSettings"].(map[string]any)

	serverName, _ := tlsSettings["serverName"].(string)
	if serverName == "" && serverBlock != nil {
		serverName, _ = serverBlock["sni"].(string)
	}
	serverName = firstNonEmpty(serverName, ib.GatewaySNI)

	alpn := extractStringSlice(tlsSettings["alpn"])
	if len(alpn) == 0 && serverBlock != nil {
		alpn = extractStringSlice(serverBlock["alpn"])
	}
	if len(alpn) == 0 {
		alpn = defaultALPN
	}

	tlsObj := map[string]any{
		"enabled": true,
	}
	if serverName != "" {
		tlsObj["server_name"] = serverName
	}
	if len(alpn) > 0 {
		tlsObj["alpn"] = alpn
	}

	// Extract cert/key from tlsSettings.certificates[0] or legacy TUIC server block.
	certApplied := false
	if certs, ok := tlsSettings["certificates"].([]any); ok && len(certs) > 0 {
		if certMap, ok2 := certs[0].(map[string]any); ok2 {
			cf, _ := certMap["certificateFile"].(string)
			kf, _ := certMap["keyFile"].(string)
			if cf != "" && kf != "" {
				tlsObj["certificate_path"] = cf
				tlsObj["key_path"] = kf
				certApplied = true
			} else {
				cLines := extractStringSlice(certMap["certificate"])
				kLines := extractStringSlice(certMap["key"])
				if len(cLines) > 0 && len(kLines) > 0 {
					tlsObj["certificate"] = cLines
					tlsObj["key"] = kLines
					certApplied = true
				}
			}
		}
	}

	if !certApplied && serverBlock != nil {
		cf, _ := serverBlock["certificate"].(string)
		kf, _ := serverBlock["private_key"].(string)
		if cf != "" && kf != "" {
			if strings.Contains(cf, "BEGIN ") {
				tlsObj["certificate"] = []string{cf}
				tlsObj["key"] = []string{kf}
			} else {
				tlsObj["certificate_path"] = cf
				tlsObj["key_path"] = kf
			}
			certApplied = true
		}
	}

	if !certApplied {
		cf, kf, err := EnsureFallbackCert(serverName)
		if err != nil {
			return nil, fmt.Errorf("ensure fallback cert: %w", err)
		}
		tlsObj["certificate_path"] = cf
		tlsObj["key_path"] = kf
	}

	return tlsObj, nil
}

func buildRealityTLSObject(ib *model.Inbound, stream map[string]any) (map[string]any, error) {
	rs, _ := stream["realitySettings"].(map[string]any)
	dest, _ := rs["target"].(string)
	if dest == "" {
		dest, _ = rs["dest"].(string)
	}
	host := ""
	port := 443
	if dest != "" {
		h, pStr, err := net.SplitHostPort(dest)
		if err == nil {
			host = h
			if p, err2 := strconv.Atoi(pStr); err2 == nil && p > 0 {
				port = p
			}
		} else {
			host = dest
		}
	}
	serverNames := extractStringSlice(rs["serverNames"])
	serverName := firstNonEmpty(ib.GatewaySNI)
	if serverName == "" && len(serverNames) > 0 {
		serverName = serverNames[0]
	}
	if host == "" {
		host = firstNonEmpty(serverName, "www.microsoft.com")
	}
	if serverName == "" {
		serverName = host
	}

	privKey, _ := rs["privateKey"].(string)
	privKey = NormalizeRealityPrivateKey(privKey)
	if privKey == "" {
		return nil, fmt.Errorf("reality privateKey is required for sing-box")
	}

	shortIDs := extractStringSlice(rs["shortIds"])
	if len(shortIDs) == 0 {
		shortIDs = []string{""}
	}

	return map[string]any{
		"enabled":     true,
		"server_name": serverName,
		"reality": map[string]any{
			"enabled": true,
			"handshake": map[string]any{
				"server":      host,
				"server_port": port,
			},
			"private_key": privKey,
			"short_id":    shortIDs,
		},
	}, nil
}

// NormalizeRealityPrivateKey converts an Xray REALITY base64 private key (which may
// use standard or URL alphabet or carry '=' padding) into the unpadded RawURL base64
// string required by upstream sing-box v1.14+.
func NormalizeRealityPrivateKey(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return base64.RawURLEncoding.EncodeToString(b)
		}
	}
	return strings.TrimRight(s, "=")
}

func buildTransportObject(stream map[string]any) map[string]any {
	netType, _ := stream["network"].(string)
	switch netType {
	case "ws":
		ws, _ := stream["wsSettings"].(map[string]any)
		path, _ := ws["path"].(string)
		if path == "" {
			path = "/"
		}
		out := map[string]any{"type": "ws", "path": path}
		if hdrs, ok := ws["headers"].(map[string]any); ok && len(hdrs) > 0 {
			out["headers"] = hdrs
		}
		return out
	case "httpupgrade":
		hu, _ := stream["httpupgradeSettings"].(map[string]any)
		path, _ := hu["path"].(string)
		if path == "" {
			path = "/"
		}
		out := map[string]any{"type": "httpupgrade", "path": path}
		if host, _ := hu["host"].(string); host != "" {
			out["host"] = host
		}
		return out
	case "grpc":
		grpcMap, _ := stream["grpcSettings"].(map[string]any)
		svc, _ := grpcMap["serviceName"].(string)
		out := map[string]any{"type": "grpc"}
		if svc != "" {
			out["service_name"] = svc
		}
		return out
	case "http", "xhttp":
		xm, _ := stream[netType+"Settings"].(map[string]any)
		path, _ := xm["path"].(string)
		if path == "" {
			path = "/"
		}
		out := map[string]any{"type": "http", "path": path}
		if host, _ := xm["host"].(string); host != "" {
			out["host"] = []string{host}
		}
		return out
	default:
		return nil
	}
}

func extractStringSlice(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, it := range arr {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}
