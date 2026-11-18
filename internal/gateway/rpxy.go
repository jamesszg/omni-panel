package gateway

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jamesszg/omni-panel/internal/database/model"
)

// RpxyConfigOptions supplies all inputs required to render rust-rpxy-l4.toml.
type RpxyConfigOptions struct {
	PublicPort    int
	L7Port        int
	ListenIPv6    bool
	Inbounds      []*model.Inbound
	GatewayDomain string
}

// RpxyRuleInfo describes one logical routing rule managed by the :443 gateway.
type RpxyRuleInfo struct {
	Name        string   `json:"name"`
	InboundId   int      `json:"inboundId"`
	InboundTag  string   `json:"inboundTag"`
	Protocol    string   `json:"protocol"`
	Core        string   `json:"core"`
	GatewayMode string   `json:"gatewayMode"`
	ServerNames []string `json:"serverNames,omitempty"`
	Path        string   `json:"path,omitempty"`
	Target      string   `json:"target"`
}

// TopologySummary summarizes the current :443 gateway wiring and caveats.
type TopologySummary struct {
	PublicPort          int            `json:"publicPort"`
	L7Port              int            `json:"l7Port"`
	SniPassthroughCount int            `json:"sniPassthroughCount"`
	L7PathCount         int            `json:"l7PathCount"`
	QuicCount           int            `json:"quicCount"`
	UdpMuxActive        bool           `json:"udpMuxActive"`
	QuicDirectPort      int            `json:"quicDirectPort"`
	Warnings            []string       `json:"warnings"`
	Rules               []RpxyRuleInfo `json:"rules"`
}

// BuildRpxyConfig generates the upstream junkurihara/rust-rpxy-l4 TOML config
// along with a structured topology summary.
func BuildRpxyConfig(opts RpxyConfigOptions) (string, *TopologySummary, error) {
	pubPort := opts.PublicPort
	if pubPort <= 0 {
		pubPort = 443
	}
	l7Port := opts.L7Port
	if l7Port <= 0 {
		l7Port = 30000
	}

	summary := &TopologySummary{
		PublicPort: pubPort,
		L7Port:     l7Port,
		Warnings:   []string{},
		Rules:      []RpxyRuleInfo{},
	}

	var tcpRules []RpxyRuleInfo
	var quicInbounds []*model.Inbound

	for _, ib := range opts.Inbounds {
		if ib == nil || !ib.Enable || ib.NodeID != nil {
			continue
		}
		target := fmt.Sprintf("127.0.0.1:%d", ib.Port)
		switch ib.GatewayMode {
		case "rpxy_sni":
			sni := strings.TrimSpace(ib.GatewaySNI)
			if sni == "" {
				continue
			}
			rule := RpxyRuleInfo{
				Name:        fmt.Sprintf("tcp_%d", ib.Id),
				InboundId:   ib.Id,
				InboundTag:  ib.Tag,
				Protocol:    string(ib.Protocol),
				Core:        ib.EffectiveCore(),
				GatewayMode: ib.GatewayMode,
				ServerNames: []string{sni},
				Target:      target,
			}
			tcpRules = append(tcpRules, rule)
			summary.Rules = append(summary.Rules, rule)
			summary.SniPassthroughCount++

		case "l7_path":
			summary.L7PathCount++
			summary.Rules = append(summary.Rules, RpxyRuleInfo{
				Name:        fmt.Sprintf("l7_%d", ib.Id),
				InboundId:   ib.Id,
				InboundTag:  ib.Tag,
				Protocol:    string(ib.Protocol),
				Core:        ib.EffectiveCore(),
				GatewayMode: ib.GatewayMode,
				ServerNames: nonEmptySlice(strings.TrimSpace(ib.GatewaySNI)),
				Path:        ib.GatewayPath,
				Target:      target,
			})

		case "rpxy_quic":
			quicInbounds = append(quicInbounds, ib)

		default:
			if (ib.Protocol == model.Hysteria || ib.Protocol == model.TUIC || ib.Protocol == model.MASQUE) &&
				ib.PublicPort == pubPort {
				quicInbounds = append(quicInbounds, ib)
			}
		}
	}

	summary.QuicCount = len(quicInbounds)
	if len(quicInbounds) == 1 {
		ib := quicInbounds[0]
		summary.UdpMuxActive = false
		summary.QuicDirectPort = ib.Port
		summary.Rules = append(summary.Rules, RpxyRuleInfo{
			Name:        fmt.Sprintf("quic_direct_%d", ib.Id),
			InboundId:   ib.Id,
			InboundTag:  ib.Tag,
			Protocol:    string(ib.Protocol),
			Core:        ib.EffectiveCore(),
			GatewayMode: "direct_udp",
			ServerNames: nonEmptySlice(firstNonEmpty(ib.GatewaySNI, opts.GatewayDomain)),
			Target:      fmt.Sprintf("0.0.0.0:%d", ib.Port),
		})
	} else if len(quicInbounds) >= 2 {
		summary.UdpMuxActive = true
		summary.Warnings = append(summary.Warnings,
			"Multiple QUIC inbounds share :443/UDP via rust-rpxy-l4; client IP limiting (LimitIP) is unavailable on UDP-forwarded inbounds")
	}

	sort.Slice(tcpRules, func(i, j int) bool { return tcpRules[i].InboundId < tcpRules[j].InboundId })

	var b strings.Builder
	fmt.Fprintf(&b, "listen_port = %d\n", pubPort)
	fmt.Fprintf(&b, "listen_ipv6 = %t\n", opts.ListenIPv6)
	b.WriteString("tcp_protocol_detection_timeout_msec = 500\n")
	b.WriteString("tcp_send_proxy_protocol = \"v2\"\n")
	fmt.Fprintf(&b, "tcp_target = [\"127.0.0.1:%d\"]\n", l7Port)

	for _, r := range tcpRules {
		fmt.Fprintf(&b, "\n[protocol.%s]\n", r.Name)
		b.WriteString("protocol = \"tls\"\n")
		fmt.Fprintf(&b, "server_names = [%s]\n", formatTOMLStrings(r.ServerNames))
		fmt.Fprintf(&b, "target = [%q]\n", r.Target)
		b.WriteString("send_proxy_protocol = \"v2\"\n")
	}

	if summary.UdpMuxActive {
		for _, ib := range quicInbounds {
			sni := firstNonEmpty(ib.GatewaySNI, opts.GatewayDomain)
			rule := RpxyRuleInfo{
				Name:        fmt.Sprintf("quic_%d", ib.Id),
				InboundId:   ib.Id,
				InboundTag:  ib.Tag,
				Protocol:    string(ib.Protocol),
				Core:        ib.EffectiveCore(),
				GatewayMode: "rpxy_quic",
				ServerNames: nonEmptySlice(sni),
				Target:      fmt.Sprintf("127.0.0.1:%d", ib.Port),
			}
			summary.Rules = append(summary.Rules, rule)
			fmt.Fprintf(&b, "\n[protocol.%s]\n", rule.Name)
			b.WriteString("protocol = \"quic\"\n")
			if len(rule.ServerNames) > 0 {
				fmt.Fprintf(&b, "server_names = [%s]\n", formatTOMLStrings(rule.ServerNames))
			}
			b.WriteString("alpn = [\"h3\"]\n")
			fmt.Fprintf(&b, "target = [%q]\n", rule.Target)
		}
	}

	return b.String(), summary, nil
}

func formatTOMLStrings(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, it := range items {
		quoted = append(quoted, fmt.Sprintf("%q", it))
	}
	return strings.Join(quoted, ", ")
}

func nonEmptySlice(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{strings.TrimSpace(s)}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
