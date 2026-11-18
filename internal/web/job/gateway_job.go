package job

import (
	"fmt"
	"sync"

	"github.com/jamesszg/omni-panel/internal/database"
	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/gateway"
	"github.com/jamesszg/omni-panel/internal/logger"
	"github.com/jamesszg/omni-panel/internal/web/service"
)

// GatewayJob reconciles the :443 L4/L7 gateway and L7 routing table against stored settings and inbounds.
type GatewayJob struct {
	settingService service.SettingService
	runMu          sync.Mutex
}

// NewGatewayJob constructs a new GatewayJob instance.
func NewGatewayJob() *GatewayJob {
	return new(GatewayJob)
}

// Run evaluates current settings and reconciles the embedded L7 gateway and rust-rpxy-l4.
func (j *GatewayJob) Run() {
	j.runMu.Lock()
	defer j.runMu.Unlock()

	enabled, err := j.settingService.GetGatewayEnable()
	if err != nil {
		return
	}

	var inbounds []*model.Inbound
	if enabled {
		if err := database.GetDB().Model(&model.Inbound{}).
			Where("enable = ? AND node_id IS NULL", true).
			Order("id ASC").
			Find(&inbounds).Error; err != nil {
			logger.Warning("gateway job: load inbounds failed:", err)
			return
		}
	}

	pubPort, _ := j.settingService.GetGatewayPublicPort()
	l7Port, _ := j.settingService.GetGatewayL7Port()
	domain, _ := j.settingService.GetGatewayDomain()
	speedtestEn, _ := j.settingService.GetGatewaySpeedtestEnable()
	acmeMode, _ := j.settingService.GetAcmeMode()
	acmeEmail, _ := j.settingService.GetAcmeEmail()
	acmeToken, _ := j.settingService.GetAcmeCfApiToken()
	webBasePath, _ := j.settingService.GetBasePath()
	webPort, _ := j.settingService.GetPort()
	webCert, _ := j.settingService.GetCertFile()
	webKey, _ := j.settingService.GetKeyFile()
	subPort, _ := j.settingService.GetSubPort()
	subPath, _ := j.settingService.GetSubPath()
	subJsonPath, _ := j.settingService.GetSubJsonPath()
	subClashPath, _ := j.settingService.GetSubClashPath()

	webScheme := "http"
	if webCert != "" && webKey != "" {
		webScheme = "https"
	}
	subCert, _ := j.settingService.GetSubCertFile()
	subKey, _ := j.settingService.GetSubKeyFile()
	subScheme := "http"
	if subCert != "" && subKey != "" {
		subScheme = "https"
	}

	opts := gateway.ReconcileOptions{
		Enabled:         enabled,
		PublicPort:      pubPort,
		L7Port:          l7Port,
		ListenIPv6:      true,
		Domain:          domain,
		CertFile:        webCert,
		KeyFile:         webKey,
		AcmeMode:        acmeMode,
		AcmeEmail:       acmeEmail,
		AcmeCfToken:     acmeToken,
		SpeedtestEnable: speedtestEn,
		WebBasePath:     webBasePath,
		WebBackendURL:   fmt.Sprintf("%s://127.0.0.1:%d", webScheme, webPort),
		SubPaths:        []string{subPath, subJsonPath, subClashPath},
		SubBackendURL:   fmt.Sprintf("%s://127.0.0.1:%d", subScheme, subPort),
		Inbounds:        inbounds,
	}

	if err := gateway.GetManager().Reconcile(opts); err != nil {
		logger.Debug("gateway job reconcile:", err)
	}
}
