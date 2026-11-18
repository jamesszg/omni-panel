package job

import (
	"sync"
	"time"

	"github.com/jamesszg/omni-panel/internal/logger"
	"github.com/jamesszg/omni-panel/internal/singbox"
	"github.com/jamesszg/omni-panel/internal/web/service"
	"github.com/jamesszg/omni-panel/internal/web/websocket"
)

const defaultSingboxSpeedSampleInterval = 10 * time.Second

// SingboxJob reconciles desired sing-box inbounds with the upstream sing-box
// process and collects per-connection traffic deltas from its Clash API.
type SingboxJob struct {
	inboundService  service.InboundService
	settingService  service.SettingService
	runMu           sync.Mutex
	lastSpeedSample time.Time
}

// NewSingboxJob constructs a new SingboxJob instance.
func NewSingboxJob() *SingboxJob {
	return new(SingboxJob)
}

// Run reconciles desired sing-box inbounds and scrapes Clash API traffic counters.
func (j *SingboxJob) Run() {
	j.runMu.Lock()
	defer j.runMu.Unlock()

	desired, err := j.inboundService.DesiredSingboxInbounds()
	if err != nil {
		logger.Warning("singbox job: load desired inbounds failed:", err)
		return
	}

	clashPort, err := j.settingService.GetSingboxClashPort()
	if err != nil || clashPort <= 0 {
		clashPort = 62795
	}
	clashSecret, err := j.settingService.GetSingboxClashSecret()
	if err != nil {
		clashSecret = ""
	}

	mgr := singbox.GetManager()
	if err := mgr.Reconcile(desired, clashPort, clashSecret); err != nil {
		logger.Warning("singbox job: reconcile failed:", err)
	}

	if len(desired) == 0 {
		j.inboundService.RefreshLocalOnlineClients(nil, nil)
		return
	}

	activeTags := make([]string, 0, len(desired))
	for _, ib := range desired {
		activeTags = append(activeTags, ib.Tag)
	}

	traffics, clientTraffics, onlineEmails, err := mgr.CollectTraffic()
	if err != nil {
		logger.Debug("singbox job: collect traffic failed:", err)
		return
	}

	sampledAt := time.Now()
	interval := defaultSingboxSpeedSampleInterval
	if !j.lastSpeedSample.IsZero() && sampledAt.After(j.lastSpeedSample) {
		interval = sampledAt.Sub(j.lastSpeedSample)
	}

	if len(traffics) > 0 || len(clientTraffics) > 0 {
		needRestart, _, addErr := j.inboundService.AddTraffic(traffics, clientTraffics)
		if addErr != nil {
			logger.Warning("singbox job: add traffic failed:", addErr)
		} else {
			intervalMs := max(interval.Milliseconds(), 1)
			payload := map[string]any{
				"clientTraffics":          clientTraffics,
				"clientTrafficSource":     "singbox",
				"clientTrafficIntervalMs": intervalMs,
			}
			websocket.BroadcastTraffic(payload)
			j.lastSpeedSample = sampledAt
			if needRestart {
				if refreshed, err := j.inboundService.DesiredSingboxInbounds(); err == nil {
					_ = mgr.Reconcile(refreshed, clashPort, clashSecret)
				}
			}
		}
	}

	if len(onlineEmails) > 0 {
		if err := j.inboundService.BumpClientsLastOnline(onlineEmails); err != nil {
			logger.Warning("singbox job: bump last online failed:", err)
		}
	}
	j.inboundService.RefreshLocalOnlineClients(onlineEmails, activeTags)
}
