package job

import (
	"github.com/jamesszg/omni-panel/internal/logger"
	"github.com/jamesszg/omni-panel/internal/web/service"
)

// ReapSyncOrphansJob hard-deletes the clients the node-snapshot sweep only
// soft-orphaned, once enough clean merges have agreed they are really gone.
type ReapSyncOrphansJob struct {
	clientService service.ClientService
}

func NewReapSyncOrphansJob() *ReapSyncOrphansJob {
	return new(ReapSyncOrphansJob)
}

func (j *ReapSyncOrphansJob) Run() {
	reaped, err := j.clientService.ReapSyncOrphans()
	if err != nil {
		logger.Warning("reap sync orphans failed:", err)
		return
	}
	if reaped > 0 {
		logger.Infof("reap sync orphans: removed %d client(s)", reaped)
	}
}
