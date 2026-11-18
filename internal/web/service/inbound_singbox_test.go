package service

import (
	"path/filepath"
	"testing"

	"github.com/jamesszg/omni-panel/internal/database"
	"github.com/jamesszg/omni-panel/internal/database/dbtest"
	"github.com/jamesszg/omni-panel/internal/database/model"
)

func TestSingboxMultiCoreRoutingAndPortConflict(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	dbtest.InitDB(t, filepath.Join(dir, "x-ui.db"))

	svc := &InboundService{}

	anytlsInbound := &model.Inbound{
		UserId:         1,
		Enable:         true,
		Core:           "singbox",
		Listen:         "127.0.0.1",
		Port:           30111,
		Protocol:       model.AnyTLS,
		Remark:         "AnyTLS-Test",
		Settings:       `{"clients":[{"email":"anytls@example.com","password":"pw123","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}`,
	}
	created, _, err := svc.AddInbound(anytlsInbound)
	if err != nil {
		t.Fatalf("AddInbound(anytls) failed: %v", err)
	}
	if created.EffectiveCore() != "singbox" {
		t.Fatalf("EffectiveCore = %q, want singbox", created.EffectiveCore())
	}

	desired, err := svc.DesiredSingboxInbounds()
	if err != nil {
		t.Fatalf("DesiredSingboxInbounds failed: %v", err)
	}
	if len(desired) != 1 || desired[0].Id != created.Id {
		t.Fatalf("DesiredSingboxInbounds = %+v, want inbound %d", desired, created.Id)
	}

	// Verify Xray config omits singbox inbounds even when enabled.
	xraySvc := &XrayService{}
	xrayCfg, err := xraySvc.GetXrayConfig()
	if err != nil {
		t.Fatalf("GetXrayConfig failed: %v", err)
	}
	for _, ib := range xrayCfg.InboundConfigs {
		if ib.Tag == created.Tag {
			t.Fatalf("XrayConfig unexpectedly included singbox inbound %q", ib.Tag)
		}
	}

	// Verify TUIC on singbox is excluded from Go TUIC sidecar instances.
	tuicSb := &model.Inbound{
		UserId:         1,
		Enable:         true,
		Core:           "singbox",
		Listen:         "127.0.0.1",
		Port:           30112,
		Protocol:       model.TUIC,
		Remark:         "TUIC-SB",
		Settings:       `{"congestion_control":"bbr","clients":[{"email":"tuic-sb@example.com","id":"11111111-1111-4111-8111-111111111111","password":"pw","enable":true}]}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":["h3"]}}`,
	}
	if _, _, err := svc.AddInbound(tuicSb); err != nil {
		t.Fatalf("AddInbound(tuic-singbox) failed: %v", err)
	}
	tuicInsts, err := svc.DesiredTuicInstances()
	if err != nil {
		t.Fatalf("DesiredTuicInstances failed: %v", err)
	}
	if len(tuicInsts) != 0 {
		t.Fatalf("expected 0 legacy TUIC instances when core=singbox, got %d", len(tuicInsts))
	}

	// Verify TCP port conflict detection catches duplicate port on AnyTLS / ShadowTLS.
	dupShadow := &model.Inbound{
		UserId:   1,
		Enable:   true,
		Listen:   "127.0.0.1",
		Port:     30111,
		Protocol: model.ShadowTLS,
		Settings: `{"clients":[{"email":"stls@example.com","password":"pw","enable":true}]}`,
	}
	if conflict, err := checkPortConflictTx(database.GetDB(), dupShadow, 0); err != nil || conflict == nil {
		t.Fatalf("expected port conflict on TCP port 30111, got conflict=%v err=%v", conflict, err)
	}
}
