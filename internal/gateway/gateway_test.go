package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/jamesszg/omni-panel/internal/database/model"
)

func TestBuildRpxyConfigQUICMuxModes(t *testing.T) {
	baseInbounds := []*model.Inbound{
		{
			Id:          1,
			Tag:         "vless-reality",
			Enable:      true,
			Core:        "xray",
			Protocol:    model.VLESS,
			Port:        30101,
			GatewayMode: "rpxy_sni",
			GatewaySNI:  "www.microsoft.com",
		},
		{
			Id:          2,
			Tag:         "hy2-443",
			Enable:      true,
			Core:        "singbox",
			Protocol:    model.Hysteria,
			Port:        443,
			PublicPort:  443,
			GatewayMode: "rpxy_quic",
			GatewaySNI:  "hy2.example.com",
		},
	}

	// Single QUIC inbound: zero [protocol.quic_*] blocks (direct core UDP bind).
	toml1, sum1, err := BuildRpxyConfig(RpxyConfigOptions{
		PublicPort:    443,
		L7Port:        30000,
		ListenIPv6:    true,
		Inbounds:      baseInbounds,
		GatewayDomain: "edge.example.com",
	})
	if err != nil {
		t.Fatalf("BuildRpxyConfig(1 quic) failed: %v", err)
	}
	if sum1.UdpMuxActive {
		t.Fatalf("expected UdpMuxActive=false with 1 QUIC inbound")
	}
	if sum1.SniPassthroughCount != 1 {
		t.Fatalf("SniPassthroughCount = %d, want 1", sum1.SniPassthroughCount)
	}
	if !strings.Contains(toml1, `tcp_target = ["127.0.0.1:30000"]`) || !strings.Contains(toml1, `server_names = ["www.microsoft.com"]`) {
		t.Fatalf("unexpected rpxy TCP TOML:\n%s", toml1)
	}
	if strings.Contains(toml1, `protocol = "quic"`) {
		t.Fatalf("did not expect quic mux rule when <=1 QUIC inbound:\n%s", toml1)
	}

	// Second QUIC inbound triggers rust-rpxy-l4 QUIC mux + LimitIP warning.
	twoQuic := append(baseInbounds, &model.Inbound{
		Id:          3,
		Tag:         "tuic-443",
		Enable:      true,
		Core:        "singbox",
		Protocol:    model.TUIC,
		Port:        30102,
		PublicPort:  443,
		GatewayMode: "rpxy_quic",
		GatewaySNI:  "tuic.example.com",
	})
	toml2, sum2, err := BuildRpxyConfig(RpxyConfigOptions{
		PublicPort:    443,
		L7Port:        30000,
		ListenIPv6:    true,
		Inbounds:      twoQuic,
		GatewayDomain: "edge.example.com",
	})
	if err != nil {
		t.Fatalf("BuildRpxyConfig(2 quic) failed: %v", err)
	}
	if !sum2.UdpMuxActive || len(sum2.Warnings) == 0 {
		t.Fatalf("expected UdpMuxActive=true and LimitIP warning, got %+v", sum2)
	}
	if !strings.Contains(toml2, `protocol = "quic"`) || !strings.Contains(toml2, `server_names = ["tuic.example.com"]`) {
		t.Fatalf("expected quic mux rules in TOML:\n%s", toml2)
	}
}

func TestL7ServerTLSProxyProtocolAndSpeedtestFallback(t *testing.T) {
	// Mock L7 upstream backend capturing X-Real-IP forwarded from PROXY protocol v2.
	var capturedClientIP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClientIP = r.Header.Get("X-Real-IP")
		_, _ = w.Write([]byte("proxied-ws-ok"))
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	certMgr, err := NewCertManager(t.TempDir(), CertConfig{Domain: "edge.example.com"})
	if err != nil {
		t.Fatalf("NewCertManager failed: %v", err)
	}

	srv := NewL7Server(certMgr, L7RouteConfig{
		WebBasePath:     "/secret-panel/",
		SpeedtestEnable: true,
		PathRoutes: []L7InboundRoute{
			{
				PathPrefix: "/ws-tunnel",
				TargetAddr: backendAddr,
			},
		},
	})
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("L7Server.Start failed: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	// Custom DialContext prepends a PROXY protocol v2 header advertising 198.51.100.42.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // self-signed test fallback cert
				ServerName:         "unknown-probe.example",
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, srv.Addr())
				if err != nil {
					return nil, err
				}
				hdr := proxyproto.HeaderProxyFromAddrs(
					2,
					net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.42:54321")),
					net.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443")),
				)
				if _, err := hdr.WriteTo(conn); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			},
		},
	}

	// 1. Unknown probe path hits OpenSpeedTest HTML fallback.
	resp, err := client.Get("https://127.0.0.1/probe-root")
	if err != nil {
		t.Fatalf("GET fallback failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "openSpeedTestServerList") {
		t.Fatalf("unexpected fallback response: status=%d len=%d", resp.StatusCode, len(body))
	}

	// 2. Configured L7 path proxies to backend with preserved client IP.
	wsResp, err := client.Get("https://127.0.0.1/ws-tunnel")
	if err != nil {
		t.Fatalf("GET /ws-tunnel failed: %v", err)
	}
	wsBody, _ := io.ReadAll(wsResp.Body)
	_ = wsResp.Body.Close()
	if wsResp.StatusCode != http.StatusOK || string(wsBody) != "proxied-ws-ok" {
		t.Fatalf("unexpected proxy response: status=%d body=%q", wsResp.StatusCode, string(wsBody))
	}
	if capturedClientIP != "198.51.100.42" {
		t.Fatalf("X-Real-IP = %q, want 198.51.100.42", capturedClientIP)
	}
}
