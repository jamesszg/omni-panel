package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/jamesszg/omni-panel/internal/database"
	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/gateway"
	"github.com/jamesszg/omni-panel/internal/singbox"
	"github.com/jamesszg/omni-panel/internal/template"
	"github.com/jamesszg/omni-panel/internal/util/random"
)

// GatewayService coordinates the :443 L4/L7 gateway, built-in templates,
// constraint validation, one-click stack bootstrap, and authoritative client links.
type GatewayService struct {
	inboundService InboundService
	settingService SettingService
}

// GatewayStatusView exposes live gateway settings, sing-box health, and routing topology.
type GatewayStatusView struct {
	GatewayEnable   bool                  `json:"gatewayEnable"`
	PublicPort      int                   `json:"publicPort"`
	L7Port          int                   `json:"l7Port"`
	Domain          string                `json:"domain"`
	SpeedtestEnable bool                  `json:"speedtestEnable"`
	AcmeMode        string                `json:"acmeMode"`
	AcmeEmail       string                `json:"acmeEmail"`
	HasAcmeCfToken  bool                  `json:"hasAcmeCfToken"`
	SingboxRunning  bool                  `json:"singboxRunning"`
	SingboxVersion  string                `json:"singboxVersion"`
	SingboxError    string                `json:"singboxError,omitempty"`
	GatewayRuntime  gateway.RuntimeStatus `json:"gatewayRuntime"`
}

// ValidateResult is returned by ValidateCandidateInbound.
type ValidateResult struct {
	Valid    bool     `json:"valid"`
	Warnings []string `json:"warnings"`
	Error    string   `json:"error,omitempty"`
}

// BootstrapRequest configures the one-click full-stack :443 setup wizard.
type BootstrapRequest struct {
	Domain          string   `json:"domain"`
	PublicPort      int      `json:"publicPort"`
	PresetIDs       []string `json:"presetIds"`
	RealityDest     string   `json:"realityDest"`
	RealitySNI      string   `json:"realitySni"`
	ClientEmail     string   `json:"clientEmail"`
	SubID           string   `json:"subId"`
	AcmeMode        string   `json:"acmeMode"`
	AcmeEmail       string   `json:"acmeEmail"`
	AcmeCfToken     string   `json:"acmeCfApiToken"`
	SpeedtestEnable *bool    `json:"speedtestEnable"`
	UserId          int      `json:"-"`
}

// BootstrapCreatedInbound summarizes an inbound created by Bootstrap443Stack.
type BootstrapCreatedInbound struct {
	Id          int                          `json:"id"`
	Tag         string                       `json:"tag"`
	Remark      string                       `json:"remark"`
	Core        string                       `json:"core"`
	Protocol    string                       `json:"protocol"`
	Port        int                          `json:"port"`
	PublicPort  int                          `json:"publicPort"`
	GatewayMode string                       `json:"gatewayMode"`
	TemplateId  string                       `json:"templateId"`
	Bundles     []template.ClientShareBundle `json:"bundles"`
}

// BootstrapResult returns all created inbounds, share links, and subscription URI.
type BootstrapResult struct {
	Domain         string                    `json:"domain"`
	PublicPort     int                       `json:"publicPort"`
	SubID          string                    `json:"subId"`
	SubURL         string                    `json:"subUrl"`
	Inbounds       []BootstrapCreatedInbound `json:"inbounds"`
	Warnings       []string                  `json:"warnings"`
	GatewayRuntime gateway.RuntimeStatus     `json:"gatewayRuntime"`
}

// GetStatus aggregates settings, sing-box health, and gateway topology.
func (s *GatewayService) GetStatus() (*GatewayStatusView, error) {
	en, _ := s.settingService.GetGatewayEnable()
	pubPort, _ := s.settingService.GetGatewayPublicPort()
	l7Port, _ := s.settingService.GetGatewayL7Port()
	domain, _ := s.settingService.GetGatewayDomain()
	stEn, _ := s.settingService.GetGatewaySpeedtestEnable()
	acmeMode, _ := s.settingService.GetAcmeMode()
	acmeEmail, _ := s.settingService.GetAcmeEmail()
	cfTok, _ := s.settingService.GetAcmeCfApiToken()

	sbMgr := singbox.GetManager()
	rt := gateway.GetManager().Status()

	if rt.Topology == nil {
		if inbounds, err := s.inboundService.GetAllInbounds(); err == nil {
			if _, summary, err := gateway.BuildRpxyConfig(gateway.RpxyConfigOptions{
				PublicPort:    pubPort,
				L7Port:        l7Port,
				ListenIPv6:    true,
				Inbounds:      inbounds,
				GatewayDomain: domain,
			}); err == nil {
				rt.Topology = summary
			}
		}
	}

	return &GatewayStatusView{
		GatewayEnable:   en,
		PublicPort:      pubPort,
		L7Port:          l7Port,
		Domain:          domain,
		SpeedtestEnable: stEn,
		AcmeMode:        acmeMode,
		AcmeEmail:       acmeEmail,
		HasAcmeCfToken:  strings.TrimSpace(cfTok) != "",
		SingboxRunning:  sbMgr.IsRunning(),
		SingboxVersion:  sbMgr.Version(),
		SingboxError:    sbMgr.LastError(),
		GatewayRuntime:  rt,
	}, nil
}

// ValidateCandidateInbound runs template and gateway constraint validation without persisting.
func (s *GatewayService) ValidateCandidateInbound(ib *model.Inbound) ValidateResult {
	existing, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return ValidateResult{Valid: false, Error: err.Error()}
	}
	domain, _ := s.settingService.GetGatewayDomain()
	warnings, err := template.ValidateInboundConstraints(ib, existing, domain)
	if err != nil {
		return ValidateResult{Valid: false, Warnings: warnings, Error: err.Error()}
	}
	if warnings == nil {
		warnings = []string{}
	}
	return ValidateResult{Valid: true, Warnings: warnings}
}

// GetClientShareBundles produces authoritative URI + sing-box client outbound JSON per client.
func (s *GatewayService) GetClientShareBundles(host string, inboundId int, filterEmail string) ([]template.ClientShareBundle, error) {
	inbound, err := s.inboundService.GetInbound(inboundId)
	if err != nil {
		return nil, err
	}

	clients, err := s.inboundService.ListClientsForInbound(inbound.Id)
	if err != nil || len(clients) == 0 {
		clients, _ = s.inboundService.GetClients(inbound)
	}

	allInbounds, _ := s.inboundService.GetAllInbounds()
	gwDomain, _ := s.settingService.GetGatewayDomain()
	gwPort, _ := s.settingService.GetGatewayPublicPort()
	warnings, _ := template.ValidateInboundConstraints(inbound, allInbounds, gwDomain)
	if warnings == nil {
		warnings = []string{}
	}

	provider := subLinkProvider()
	out := make([]template.ClientShareBundle, 0, len(clients))
	for _, client := range clients {
		if filterEmail != "" && !strings.EqualFold(client.Email, filterEmail) {
			continue
		}
		uri := ""
		if provider != nil {
			copyIb := *inbound
			if links := provider.LinksForClient(host, &copyIb, client.Email); len(links) > 0 {
				uri = links[0]
			}
		}
		sbJSON, _ := template.BuildSingboxClientOutbound(host, gwPort, gwDomain, inbound, client)
		out = append(out, template.ClientShareBundle{
			Email:               client.Email,
			Protocol:            string(inbound.Protocol),
			Core:                inbound.EffectiveCore(),
			URI:                 uri,
			SingboxOutboundJSON: sbJSON,
			Warnings:            warnings,
		})
	}
	return out, nil
}

// Bootstrap443Stack performs one-click gateway configuration and creates preset multi-core inbounds.
func (s *GatewayService) Bootstrap443Stack(host string, req BootstrapRequest) (*BootstrapResult, error) {
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required to bootstrap the :443 gateway")
	}
	pubPort := req.PublicPort
	if pubPort <= 0 {
		pubPort = 443
	}
	speedtestEn := true
	if req.SpeedtestEnable != nil {
		speedtestEn = *req.SpeedtestEnable
	}
	acmeMode := strings.TrimSpace(req.AcmeMode)
	if acmeMode == "" {
		acmeMode = "tls_alpn"
	}

	if err := s.settingService.SetGatewayDomain(domain); err != nil {
		return nil, err
	}
	if err := s.settingService.SetGatewayPublicPort(pubPort); err != nil {
		return nil, err
	}
	if err := s.settingService.SetGatewaySpeedtestEnable(speedtestEn); err != nil {
		return nil, err
	}
	if err := s.settingService.SetAcmeMode(acmeMode); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.AcmeEmail) != "" {
		if err := s.settingService.SetAcmeEmail(req.AcmeEmail); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(req.AcmeCfToken) != "" {
		if err := s.settingService.SetAcmeCfApiToken(req.AcmeCfToken); err != nil {
			return nil, err
		}
	}
	if err := s.settingService.SetGatewayEnable(true); err != nil {
		return nil, err
	}

	presets := req.PresetIDs
	if len(presets) == 0 {
		presets = []string{
			"singbox-hysteria2-443",
			"xray-vless-reality-vision-443",
			"xray-vless-xhttp-l7-443",
		}
	}

	subID := strings.TrimSpace(req.SubID)
	if subID == "" {
		subID = random.NumLower(16)
	}
	baseEmail := strings.TrimSpace(req.ClientEmail)
	if baseEmail == "" {
		baseEmail = "omni-" + random.NumLower(4)
	}

	userId := req.UserId
	if userId <= 0 {
		var firstUser model.User
		if uErr := database.GetDB().Model(&model.User{}).Order("id ASC").First(&firstUser).Error; uErr == nil && firstUser.Id > 0 {
			userId = firstUser.Id
		}
	}
	if userId <= 0 {
		userId = 1
	}
	_ = database.GetDB().Model(&model.Inbound{}).Where("user_id = 0").Update("user_id", userId).Error

	existing, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	byTemplateID := make(map[string]*model.Inbound, len(existing))
	usedPorts := make(map[int]bool, len(existing))
	existingQuicCount := 0
	for _, ib := range existing {
		usedPorts[ib.Port] = true
		if ib.NodeID == nil && strings.TrimSpace(ib.TemplateId) != "" {
			if _, exists := byTemplateID[ib.TemplateId]; !exists {
				byTemplateID[ib.TemplateId] = ib
			}
		}
		if ib.Enable && ib.NodeID == nil &&
			(ib.Protocol == model.Hysteria || ib.Protocol == model.TUIC || ib.Protocol == model.MASQUE) &&
			(ib.GatewayMode == "rpxy_quic" || ib.PublicPort == pubPort || ib.Port == pubPort) {
			existingQuicCount++
		}
	}
	newQuicCount := 0
	for _, pid := range presets {
		if _, exists := byTemplateID[pid]; exists {
			continue
		}
		if spec, ok := template.FindTemplate(pid); ok && spec.GatewayMode == "rpxy_quic" {
			newQuicCount++
		}
	}
	shareUDP443 := (existingQuicCount + newQuicCount) > 1

	nextLoopbackPort := 30110
	allocPort := func() int {
		for usedPorts[nextLoopbackPort] || nextLoopbackPort == 30000 || nextLoopbackPort == pubPort {
			nextLoopbackPort++
		}
		p := nextLoopbackPort
		usedPorts[p] = true
		nextLoopbackPort++
		return p
	}

	created := make([]BootstrapCreatedInbound, 0, len(presets))
	allWarnings := make([]string, 0)
	var needXrayRestart bool

	for idx, pid := range presets {
		if existingMatch, exists := byTemplateID[pid]; exists {
			bundles, _ := s.GetClientShareBundles(host, existingMatch.Id, "")
			created = append(created, BootstrapCreatedInbound{
				Id:          existingMatch.Id,
				Tag:         existingMatch.Tag,
				Remark:      existingMatch.Remark,
				Core:        existingMatch.EffectiveCore(),
				Protocol:    string(existingMatch.Protocol),
				Port:        existingMatch.Port,
				PublicPort:  existingMatch.PublicPort,
				GatewayMode: existingMatch.GatewayMode,
				TemplateId:  existingMatch.TemplateId,
				Bundles:     bundles,
			})
			continue
		}
		spec, ok := template.FindTemplate(pid)
		if !ok {
			return nil, fmt.Errorf("unknown preset template %q", pid)
		}

		loopPort := allocPort()
		if spec.GatewayMode == "rpxy_quic" && !shareUDP443 && !usedPorts[pubPort] {
			loopPort = pubPort
			usedPorts[pubPort] = true
		}

		clientEmail := fmt.Sprintf("%s-%d", baseEmail, idx+1)
		sniHint := ""
		if spec.GatewayMode == "rpxy_quic" {
			sniHint = domain
			if shareUDP443 {
				sniHint = fmt.Sprintf("%s.%s", strings.ToLower(string(spec.Protocol)), domain)
			}
		}

		ib, _, err := template.InstantiateTemplate(pid, template.InstantiateOptions{
			GatewayDomain: domain,
			RealityDest:   req.RealityDest,
			RealitySNI:    req.RealitySNI,
			ClientEmail:   clientEmail,
			SubID:         subID,
			LoopbackPort:  loopPort,
			PublicPort:    pubPort,
			ServerName:    sniHint,
		})
		if err != nil {
			return nil, err
		}
		ib.UserId = userId

		allNow, _ := s.inboundService.GetAllInbounds()
		warnings, err := template.ValidateInboundConstraints(ib, allNow, domain)
		if err != nil {
			return nil, err
		}
		allWarnings = append(allWarnings, warnings...)

		saved, xrayRestart, err := s.inboundService.AddInbound(ib)
		if err != nil {
			return nil, err
		}
		if xrayRestart {
			needXrayRestart = true
		}
		bundles, _ := s.GetClientShareBundles(host, saved.Id, "")
		created = append(created, BootstrapCreatedInbound{
			Id:          saved.Id,
			Tag:         saved.Tag,
			Remark:      saved.Remark,
			Core:        saved.EffectiveCore(),
			Protocol:    string(saved.Protocol),
			Port:        saved.Port,
			PublicPort:  saved.PublicPort,
			GatewayMode: saved.GatewayMode,
			TemplateId:  saved.TemplateId,
			Bundles:     bundles,
		})
	}

	if needXrayRestart {
		(&XrayService{}).SetToNeedRestart()
	}

	subPath, _ := s.settingService.GetSubPath()
	subURL := s.buildGatewaySubURL(host, domain, pubPort, subPath, subID)
	status, _ := s.GetStatus()
	var gwRT gateway.RuntimeStatus
	if status != nil {
		gwRT = status.GatewayRuntime
	}

	return &BootstrapResult{
		Domain:         domain,
		PublicPort:     pubPort,
		SubID:          subID,
		SubURL:         subURL,
		Inbounds:       created,
		Warnings:       allWarnings,
		GatewayRuntime: gwRT,
	}, nil
}

func (s *GatewayService) buildGatewaySubURL(host, domain string, pubPort int, subPath, subID string) string {
	targetHost := strings.TrimSpace(domain)
	if targetHost == "" {
		targetHost = strings.TrimSpace(host)
	}
	if !strings.HasPrefix(subPath, "/") {
		subPath = "/" + subPath
	}
	if !strings.HasSuffix(subPath, "/") {
		subPath += "/"
	}
	u := &url.URL{
		Scheme: "https",
		Host:   targetHost,
		Path:   subPath + subID,
	}
	if pubPort != 443 && pubPort > 0 {
		u.Host = fmt.Sprintf("%s:%d", targetHost, pubPort)
	}
	return u.String()
}
