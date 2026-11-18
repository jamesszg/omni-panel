package service

import (
	"encoding/json"

	"github.com/jamesszg/omni-panel/internal/database"
	"github.com/jamesszg/omni-panel/internal/database/model"
)

// DesiredSingboxInbounds returns all enabled local inbounds assigned to upstream sing-box,
// with client enable state hydrated for local runtime execution.
func (s *InboundService) DesiredSingboxInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var all []*model.Inbound
	if err := db.Model(model.Inbound{}).
		Where("enable = ? AND node_id IS NULL", true).
		Order("id ASC").
		Find(&all).Error; err != nil {
		return nil, err
	}

	out := make([]*model.Inbound, 0, len(all))
	for _, ib := range all {
		if ib.EffectiveCore() != "singbox" {
			continue
		}
		if built, err := s.buildInboundForLocalRuntime(db, ib); err == nil && built != nil {
			out = append(out, built)
			continue
		}
		// Ensure valid empty JSON does not block buildInboundForLocalRuntime fallback.
		var check map[string]any
		if json.Unmarshal([]byte(ib.Settings), &check) == nil {
			out = append(out, ib)
		}
	}
	return out, nil
}
