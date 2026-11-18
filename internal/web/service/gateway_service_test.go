package service

import (
	"path/filepath"
	"testing"

	"github.com/jamesszg/omni-panel/internal/database/dbtest"
	"github.com/jamesszg/omni-panel/internal/database/model"
)

type mockSubLinkProvider struct{}

func (m *mockSubLinkProvider) SubLinksForSubId(string, string) ([]string, error) {
	return nil, nil
}

func (m *mockSubLinkProvider) LinksForClient(host string, inbound *model.Inbound, email string) []string {
	return []string{"mock://" + email + "@" + host + ":" + string(inbound.Protocol)}
}

func (m *mockSubLinkProvider) LinksForInbounds(string, []*model.Inbound) []string {
	return nil
}

func TestBootstrap443StackAndValidate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	dbtest.InitDB(t, filepath.Join(dir, "x-ui.db"))

	prev := subLinkProvider()
	RegisterSubLinkProvider(&mockSubLinkProvider{})
	t.Cleanup(func() { RegisterSubLinkProvider(prev) })

	gwSvc := &GatewayService{}
	res, err := gwSvc.Bootstrap443Stack("edge.example.com", BootstrapRequest{
		Domain:      "edge.example.com",
		PublicPort:  443,
		RealitySNI:  "www.microsoft.com",
		RealityDest: "www.microsoft.com:443",
		ClientEmail: "wizarduser",
	})
	if err != nil {
		t.Fatalf("Bootstrap443Stack failed: %v", err)
	}
	if len(res.Inbounds) != 3 {
		t.Fatalf("created %d inbounds, want 3 default presets", len(res.Inbounds))
	}
	if res.SubID == "" || res.SubURL == "" {
		t.Fatalf("expected non-empty SubID and SubURL, got %+v", res)
	}
	allInbounds, err := (&InboundService{}).GetInbounds(1)
	if err != nil || len(allInbounds) != 3 {
		t.Fatalf("expected GetInbounds(1) to return 3 user-owned inbounds, got len=%d err=%v", len(allInbounds), err)
	}
	// Calling Bootstrap443Stack a second time must succeed idempotently.
	res2, err := gwSvc.Bootstrap443Stack("edge.example.com", BootstrapRequest{
		Domain:      "edge.example.com",
		PublicPort:  443,
		RealitySNI:  "www.microsoft.com",
		RealityDest: "www.microsoft.com:443",
		ClientEmail: "wizarduser",
	})
	if err != nil || len(res2.Inbounds) != 3 {
		t.Fatalf("repeated Bootstrap443Stack failed: err=%v res=%+v", err, res2)
	}

	// Verify status reflects gatewayEnable=true and domain.
	status, err := gwSvc.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if !status.GatewayEnable || status.Domain != "edge.example.com" || status.GatewayRuntime.Topology == nil {
		t.Fatalf("unexpected gateway status: %+v", status)
	}

	// Verify ValidateCandidateInbound rejects invalid Hysteria ALPN.
	vr := gwSvc.ValidateCandidateInbound(&model.Inbound{
		Enable:         true,
		Core:           "singbox",
		Protocol:       model.Hysteria,
		Port:           30999,
		StreamSettings: `{"network":"hysteria","security":"tls","tlsSettings":{"alpn":["http/1.1"]}}`,
	})
	if vr.Valid || vr.Error == "" {
		t.Fatalf("expected ValidateCandidateInbound rejection for http/1.1 on Hysteria, got %+v", vr)
	}
}
