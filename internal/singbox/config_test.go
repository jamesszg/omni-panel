package singbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jamesszg/omni-panel/internal/database/model"
)

func generateTestRealityPrivateKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Encode with standard padded base64 to verify NormalizeRealityPrivateKey converts it to RawURL.
	return base64.StdEncoding.EncodeToString(priv.Bytes())
}

func TestBuildConfigAndValidateWithUpstreamSingBox(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", tmpDir)

	certPath, keyPath, err := EnsureFallbackCert("edge.example.com")
	if err != nil {
		t.Fatalf("EnsureFallbackCert failed: %v", err)
	}
	if filepath.Dir(certPath) == "" || keyPath == "" {
		t.Fatal("empty fallback cert path")
	}

	realityPriv := generateTestRealityPrivateKey(t)

	hy2Settings := `{"clients":[{"email":"hy2@test","auth":"hy2-secret-pass","enable":true}]}`
	hy2Stream := `{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"hy2.example.com","alpn":["h3"],"certificates":[{"certificateFile":"` + filepath.ToSlash(certPath) + `","keyFile":"` + filepath.ToSlash(keyPath) + `"}]},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"sala-pass"}}]}}`

	tuicSettings := `{"congestion_control":"bbr","zero_rtt_handshake":true,"clients":[{"email":"tuic@test","id":"11111111-1111-4111-8111-111111111111","password":"tuic-pass","enable":true}]}`
	tuicStream := `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"tuic.example.com","alpn":["h3"]}}`

	anytlsSettings := `{"paddingScheme":["stop=8","0=30-30"],"clients":[{"email":"anytls@test","password":"anytls-password","enable":true}]}`
	anytlsStream := `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"anytls.example.com","alpn":["h2","http/1.1"]}}`

	shadowtlsSettings := `{"handshakeServer":"www.microsoft.com","handshakePort":443,"detour":"sb-trojan-inner","clients":[{"email":"stls@test","password":"stls-password","enable":true}]}`

	trojanSettings := `{"clients":[{"email":"inner@test","password":"inner-password","enable":true}]}`
	trojanStream := `{"network":"tcp","security":"none"}`

	vlessSettings := `{"clients":[{"email":"vless@test","id":"22222222-2222-4222-8222-222222222222","flow":"xtls-rprx-vision","enable":true}]}`
	vlessStream := `{"network":"tcp","security":"reality","realitySettings":{"target":"www.microsoft.com:443","serverNames":["www.microsoft.com"],"privateKey":"` + realityPriv + `","shortIds":["1234abcd"]}}`

	inbounds := []*model.Inbound{
		{
			Id:             1,
			Tag:            "sb-hy2",
			Enable:         true,
			Core:           "singbox",
			Listen:         "127.0.0.1",
			Port:           30101,
			Protocol:       model.Hysteria,
			Settings:       hy2Settings,
			StreamSettings: hy2Stream,
			GatewaySNI:     "hy2.example.com",
		},
		{
			Id:             2,
			Tag:            "sb-tuic",
			Enable:         true,
			Core:           "singbox",
			Listen:         "127.0.0.1",
			Port:           30102,
			Protocol:       model.TUIC,
			Settings:       tuicSettings,
			StreamSettings: tuicStream,
		},
		{
			Id:             3,
			Tag:            "sb-anytls",
			Enable:         true,
			Core:           "singbox",
			Listen:         "127.0.0.1",
			Port:           30103,
			Protocol:       model.AnyTLS,
			Settings:       anytlsSettings,
			StreamSettings: anytlsStream,
			ConfigOverride: `{"tcp_fast_open":true}`,
		},
		{
			Id:       4,
			Tag:      "sb-shadowtls",
			Enable:   true,
			Core:     "singbox",
			Listen:   "127.0.0.1",
			Port:     30104,
			Protocol: model.ShadowTLS,
			Settings: shadowtlsSettings,
		},
		{
			Id:             5,
			Tag:            "sb-trojan-inner",
			Enable:         true,
			Core:           "singbox",
			Listen:         "127.0.0.1",
			Port:           30105,
			Protocol:       model.Trojan,
			Settings:       trojanSettings,
			StreamSettings: trojanStream,
		},
		{
			Id:             6,
			Tag:            "sb-vless-reality",
			Enable:         true,
			Core:           "singbox",
			Listen:         "127.0.0.1",
			Port:           30106,
			Protocol:       model.VLESS,
			Settings:       vlessSettings,
			StreamSettings: vlessStream,
		},
	}

	raw, err := BuildConfig(inbounds, 62795, "test-secret")
	if err != nil {
		t.Fatalf("BuildConfig failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("BuildConfig produced invalid JSON: %v", err)
	}
	inbs, _ := parsed["inbounds"].([]any)
	if len(inbs) != len(inbounds) {
		t.Fatalf("got %d inbounds, want %d", len(inbs), len(inbounds))
	}
	anytlsEntry := inbs[2].(map[string]any)
	if anytlsEntry["tcp_fast_open"] != true {
		t.Fatalf("ConfigOverride not applied: %+v", anytlsEntry)
	}

	binPath, err := FindBinary()
	if err != nil {
		t.Skipf("sing-box binary not present for live schema check: %v", err)
	}
	if err := ValidateConfig(binPath, raw); err != nil {
		t.Fatalf("upstream sing-box check failed: %v\nconfig:\n%s", err, string(raw))
	}
}

func TestTrafficTrackerClashAPIDeltas(t *testing.T) {
	var step atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer my-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var resp ClashConnectionsResponse
		switch step.Load() {
		case 0:
			resp = ClashConnectionsResponse{
				Connections: []ClashConnection{
					{
						ID:       "conn-1",
						Upload:   1000,
						Download: 4000,
						Metadata: ClashConnMetadata{Inbound: "sb-hy2", User: "alice@test"},
					},
				},
			}
		case 1:
			resp = ClashConnectionsResponse{
				Connections: []ClashConnection{
					{
						ID:       "conn-1",
						Upload:   1500,
						Download: 9000,
						Metadata: ClashConnMetadata{Inbound: "sb-hy2", User: "alice@test"},
					},
					{
						ID:       "conn-2",
						Upload:   250,
						Download: 750,
						Metadata: ClashConnMetadata{Inbound: "sb-anytls", User: "bob@test"},
					},
				},
			}
		default:
			resp = ClashConnectionsResponse{Connections: nil}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tracker := NewTrafficTracker()

	tr1, ct1, on1, err := tracker.PollBaseURL(context.Background(), srv.URL, "my-secret")
	if err != nil {
		t.Fatalf("poll 1 failed: %v", err)
	}
	if len(tr1) != 1 || tr1[0].Tag != "sb-hy2" || tr1[0].Up != 1000 || tr1[0].Down != 4000 {
		t.Fatalf("unexpected poll 1 inbound traffic: %+v", tr1)
	}
	if len(ct1) != 1 || ct1[0].Email != "alice@test" || ct1[0].Up != 1000 || ct1[0].Down != 4000 {
		t.Fatalf("unexpected poll 1 client traffic: %+v", ct1)
	}
	if len(on1) != 1 || on1[0] != "alice@test" {
		t.Fatalf("unexpected online list: %+v", on1)
	}

	step.Store(1)
	tr2, ct2, on2, err := tracker.PollBaseURL(context.Background(), srv.URL, "my-secret")
	if err != nil {
		t.Fatalf("poll 2 failed: %v", err)
	}
	if len(tr2) != 2 || len(ct2) != 2 || len(on2) != 2 {
		t.Fatalf("unexpected poll 2 counts: tr=%d ct=%d on=%d", len(tr2), len(ct2), len(on2))
	}
	for _, ct := range ct2 {
		switch ct.Email {
		case "alice@test":
			if ct.Up != 500 || ct.Down != 5000 {
				t.Fatalf("alice delta = (%d,%d), want (500,5000)", ct.Up, ct.Down)
			}
		case "bob@test":
			if ct.Up != 250 || ct.Down != 750 {
				t.Fatalf("bob delta = (%d,%d), want (250,750)", ct.Up, ct.Down)
			}
		}
	}

	step.Store(2)
	tr3, ct3, on3, err := tracker.PollBaseURL(context.Background(), srv.URL, "my-secret")
	if err != nil {
		t.Fatalf("poll 3 failed: %v", err)
	}
	if len(tr3) != 0 || len(ct3) != 0 || len(on3) != 0 {
		t.Fatalf("expected closed connections pruned on poll 3, got tr=%d ct=%d on=%d", len(tr3), len(ct3), len(on3))
	}
}
