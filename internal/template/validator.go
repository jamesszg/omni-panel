package template

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/jamesszg/omni-panel/internal/database/model"
)

// ValidateInboundConstraints enforces hard protocol/transport/gateway compatibility
// rules and reports non-fatal operational warnings (such as QUIC UDP mux LimitIP impact).
func ValidateInboundConstraints(ib *model.Inbound, existing []*model.Inbound, gatewayDomain string) ([]string, error) {
	if ib == nil {
		return nil, nil
	}

	if strings.TrimSpace(ib.ConfigOverride) != "" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(ib.ConfigOverride), &obj); err != nil || obj == nil {
			return nil, fmt.Errorf("configOverride must be a valid JSON object")
		}
	}

	var stream map[string]any
	if strings.TrimSpace(ib.StreamSettings) != "" {
		_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)
	}
	var settings map[string]any
	if strings.TrimSpace(ib.Settings) != "" {
		_ = json.Unmarshal([]byte(ib.Settings), &settings)
	}

	if err := validateALPNConstraints(ib.Protocol, stream, settings); err != nil {
		return nil, err
	}

	if err := validateRealityDomainExclusion(ib, stream, gatewayDomain); err != nil {
		return nil, err
	}

	if err := validateGatewayCollisions(ib, existing); err != nil {
		return nil, err
	}

	var warnings []string
	if isQuicGatewayInbound(ib) && ib.Enable {
		otherQuic := 0
		for _, peer := range existing {
			if peer == nil || peer.Id == ib.Id || !peer.Enable || peer.NodeID != nil {
				continue
			}
			if isQuicGatewayInbound(peer) {
				otherQuic++
			}
		}
		if otherQuic >= 1 {
			warnings = append(warnings,
				"Multiple QUIC inbounds share :443/UDP via rust-rpxy-l4; client IP limiting (LimitIP) is unavailable on UDP-forwarded inbounds")
		}
	}

	return warnings, nil
}

func validateALPNConstraints(protocol model.Protocol, stream, settings map[string]any) error {
	alpn := extractALPN(stream, settings)
	if protocol == model.Hysteria || protocol == model.TUIC {
		for _, a := range alpn {
			low := strings.ToLower(strings.TrimSpace(a))
			if low == "h2" || low == "http/1.1" || low == "h2c" {
				return fmt.Errorf("%s uses QUIC over UDP and cannot use ALPN %q; set ALPN to 'h3' only", protocol, a)
			}
		}
		return nil
	}

	netType, _ := stream["network"].(string)
	if (netType == "ws" || netType == "httpupgrade") && len(alpn) > 0 {
		hasHTTP11 := false
		for _, a := range alpn {
			if strings.EqualFold(strings.TrimSpace(a), "http/1.1") {
				hasHTTP11 = true
				break
			}
		}
		if !hasHTTP11 {
			return fmt.Errorf("%s transport requires 'http/1.1' in TLS ALPN (got %v); h2-only or h3 breaks WebSocket Upgrade", netType, alpn)
		}
	}
	return nil
}

func validateRealityDomainExclusion(ib *model.Inbound, stream map[string]any, gatewayDomain string) error {
	gwDom := strings.ToLower(strings.TrimSpace(gatewayDomain))
	if gwDom == "" || stream == nil {
		return nil
	}
	security, _ := stream["security"].(string)
	if !strings.EqualFold(security, "reality") {
		return nil
	}

	if strings.EqualFold(strings.TrimSpace(ib.GatewaySNI), gwDom) {
		return fmt.Errorf("REALITY gatewaySni cannot match your own gateway domain %q; choose a foreign TLS 1.3 website", gatewayDomain)
	}

	rs, _ := stream["realitySettings"].(map[string]any)
	if rs == nil {
		return nil
	}
	if snList, ok := rs["serverNames"].([]any); ok {
		for _, item := range snList {
			if s, ok := item.(string); ok && strings.EqualFold(strings.TrimSpace(s), gwDom) {
				return fmt.Errorf("REALITY serverNames cannot include your own gateway domain %q", gatewayDomain)
			}
		}
	}
	for _, key := range []string{"target", "dest"} {
		if dest, ok := rs[key].(string); ok && dest != "" {
			host := dest
			if h, _, err := net.SplitHostPort(dest); err == nil {
				host = h
			}
			if strings.EqualFold(strings.TrimSpace(host), gwDom) {
				return fmt.Errorf("REALITY target cannot point to your own gateway domain %q", gatewayDomain)
			}
		}
	}
	return nil
}

func validateGatewayCollisions(ib *model.Inbound, existing []*model.Inbound) error {
	mode := strings.TrimSpace(ib.GatewayMode)
	sni := strings.ToLower(strings.TrimSpace(ib.GatewaySNI))
	path := normalizeGatewayPath(ib.GatewayPath)

	switch mode {
	case "rpxy_sni":
		if sni == "" {
			return fmt.Errorf("gatewayMode 'rpxy_sni' requires a non-empty gatewaySni for L4 SNI multiplexing")
		}
		for _, peer := range existing {
			if peer == nil || peer.Id == ib.Id || !peer.Enable || peer.NodeID != nil {
				continue
			}
			if peer.GatewayMode == "rpxy_sni" && strings.EqualFold(strings.TrimSpace(peer.GatewaySNI), sni) {
				return fmt.Errorf("duplicate :443 SNI passthrough host %q already claimed by inbound #%d (%s)", sni, peer.Id, peer.Tag)
			}
		}
	case "rpxy_quic":
		if sni != "" {
			for _, peer := range existing {
				if peer == nil || peer.Id == ib.Id || !peer.Enable || peer.NodeID != nil {
					continue
				}
				if peer.GatewayMode == "rpxy_quic" && strings.EqualFold(strings.TrimSpace(peer.GatewaySNI), sni) {
					return fmt.Errorf("duplicate :443 QUIC SNI %q already claimed by inbound #%d (%s)", sni, peer.Id, peer.Tag)
				}
			}
		}
	case "l7_path":
		if path == "" || path == "/" {
			return fmt.Errorf("gatewayMode 'l7_path' requires a non-root gatewayPath (e.g. /ws-abc)")
		}
		if strings.HasPrefix(path, "/assets/") || path == "/downloading" || path == "/upload" {
			return fmt.Errorf("gatewayPath %q conflicts with reserved L7 gateway static/speedtest paths", path)
		}
		for _, peer := range existing {
			if peer == nil || peer.Id == ib.Id || !peer.Enable || peer.NodeID != nil {
				continue
			}
			if peer.GatewayMode != "l7_path" {
				continue
			}
			peerPath := normalizeGatewayPath(peer.GatewayPath)
			peerSNI := strings.ToLower(strings.TrimSpace(peer.GatewaySNI))
			if peerPath == path && (peerSNI == sni || peerSNI == "" || sni == "") {
				return fmt.Errorf("duplicate L7 gateway path %q already used by inbound #%d (%s)", path, peer.Id, peer.Tag)
			}
		}
	}
	return nil
}

func isQuicGatewayInbound(ib *model.Inbound) bool {
	if ib == nil {
		return false
	}
	if ib.GatewayMode == "rpxy_quic" {
		return true
	}
	if (ib.Protocol == model.Hysteria || ib.Protocol == model.TUIC || ib.Protocol == model.MASQUE) &&
		(ib.PublicPort == 443 || ib.Port == 443) {
		return true
	}
	return false
}

func normalizeGatewayPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func extractALPN(stream, settings map[string]any) []string {
	var out []string
	if tlsObj, ok := stream["tlsSettings"].(map[string]any); ok {
		if arr, ok2 := tlsObj["alpn"].([]any); ok2 {
			for _, item := range arr {
				if s, ok3 := item.(string); ok3 && strings.TrimSpace(s) != "" && !slices.Contains(out, s) {
					out = append(out, s)
				}
			}
		}
	}
	appendSettingsALPN := func(m map[string]any) {
		if m == nil {
			return
		}
		if arr, ok := m["alpn"].([]any); ok {
			for _, item := range arr {
				if s, ok2 := item.(string); ok2 && strings.TrimSpace(s) != "" && !slices.Contains(out, s) {
					out = append(out, s)
				}
			}
		}
	}
	appendSettingsALPN(settings)
	if srv, ok := settings["server"].(map[string]any); ok {
		appendSettingsALPN(srv)
	}
	return out
}
