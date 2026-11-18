package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jamesszg/omni-panel/internal/database"
	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/gateway"
	"github.com/jamesszg/omni-panel/internal/singbox"
	"github.com/jamesszg/omni-panel/internal/template"
	"github.com/jamesszg/omni-panel/internal/util/random"
)

var defaultCertSearchRoot = "/root/cert"

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
	HasPanelCert    bool                  `json:"hasPanelCert"`
	CertFile        string                `json:"certFile,omitempty"`
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
	Domain          string   `json:"domain" form:"domain"`
	PublicPort      int      `json:"publicPort" form:"publicPort"`
	PresetIDs       []string `json:"presetIds" form:"presetIds"`
	RealityDest     string   `json:"realityDest" form:"realityDest"`
	RealitySNI      string   `json:"realitySni" form:"realitySni"`
	ClientEmail     string   `json:"clientEmail" form:"clientEmail"`
	SubID           string   `json:"subId" form:"subId"`
	AcmeMode        string   `json:"acmeMode" form:"acmeMode"`
	AcmeEmail       string   `json:"acmeEmail" form:"acmeEmail"`
	AcmeCfToken     string   `json:"acmeCfApiToken" form:"acmeCfApiToken"`
	SpeedtestEnable *bool    `json:"speedtestEnable" form:"speedtestEnable"`
	UserId          int      `json:"-" form:"-"`
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
	Domain             string                    `json:"domain"`
	PublicPort         int                       `json:"publicPort"`
	SubID              string                    `json:"subId"`
	SubURL             string                    `json:"subUrl"`
	Inbounds           []BootstrapCreatedInbound `json:"inbounds"`
	Warnings           []string                  `json:"warnings"`
	GatewayRuntime     gateway.RuntimeStatus     `json:"gatewayRuntime"`
	RestartPanelNeeded bool                      `json:"-"`
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

	certFile, keyFile, detectedDomain := s.resolveExistingCert(domain)
	hasPanelCert := certFile != "" && keyFile != ""
	if strings.TrimSpace(domain) == "" && detectedDomain != "" {
		domain = detectedDomain
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
		HasPanelCert:    hasPanelCert,
		CertFile:        certFile,
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
	allWarnings := make([]string, 0)
	certFile, keyFile, _ := s.resolveExistingCert(domain)
	if certFile != "" && keyFile != "" {
		existingCert, _ := s.settingService.GetCertFile()
		existingKey, _ := s.settingService.GetKeyFile()
		if strings.TrimSpace(existingCert) == "" || strings.TrimSpace(existingKey) == "" {
			_ = s.settingService.SetCertFile(certFile)
			_ = s.settingService.SetKeyFile(keyFile)
		}
	}

	acmeMode := normalizeAcmeMode(req.AcmeMode)
	if acmeMode == "" {
		if certFile != "" && keyFile != "" {
			acmeMode = "existing_cert"
		} else {
			acmeMode = "tls_alpn"
		}
	}

	var restartPanelNeeded bool
	if webPort, err := s.settingService.GetPort(); err == nil && webPort == pubPort {
		relocated := pickRelocatedPort(2053, pubPort)
		if err := s.settingService.SetPort(relocated); err != nil {
			return nil, err
		}
		restartPanelNeeded = true
		allWarnings = append(allWarnings, fmt.Sprintf("panel webPort %d conflicts with gateway publicPort %d; moved panel to 127.0.0.1:%d (restarting panel)", webPort, pubPort, relocated))
	}
	if subPort, err := s.settingService.GetSubPort(); err == nil && subPort == pubPort {
		allWarnings = append(allWarnings, fmt.Sprintf("subscription port %d conflicts with gateway publicPort %d; consider changing subPort so :%d stays dedicated to the unified gateway", subPort, pubPort, pubPort))
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
	var needXrayRestart bool

	for idx, pid := range presets {
		if existingMatch, exists := byTemplateID[pid]; exists {
			if ensureInboundTLSCert(existingMatch, certFile, keyFile, domain) {
				if updated, xrayRestart, updErr := s.inboundService.UpdateInbound(existingMatch); updErr != nil {
					allWarnings = append(allWarnings, fmt.Sprintf("update TLS cert on existing inbound %q failed: %v", existingMatch.Tag, updErr))
				} else if updated != nil {
					existingMatch = updated
					if xrayRestart {
						needXrayRestart = true
					}
				}
			}
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
			CertFile:      certFile,
			KeyFile:       keyFile,
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
		Domain:             domain,
		PublicPort:         pubPort,
		SubID:              subID,
		SubURL:             subURL,
		Inbounds:           created,
		Warnings:           allWarnings,
		GatewayRuntime:     gwRT,
		RestartPanelNeeded: restartPanelNeeded,
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

func normalizeAcmeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return ""
	case "tls-alpn-01", "tls_alpn":
		return "tls_alpn"
	case "dns-01-cf", "dns_cf":
		return "dns_cf"
	case "existing-cert", "existing_cert":
		return "existing_cert"
	case "self-signed", "self_signed":
		return "self_signed"
	default:
		return strings.TrimSpace(mode)
	}
}

func (s *GatewayService) resolveExistingCert(domain string) (certFile, keyFile, detectedDomain string) {
	domain = strings.TrimSpace(domain)
	if cleanDomain := sanitizeCertDirName(domain); cleanDomain != "" {
		c := filepath.Join(defaultCertSearchRoot, cleanDomain, "fullchain.pem")
		k := filepath.Join(defaultCertSearchRoot, cleanDomain, "privkey.pem")
		if isNonEmptyFile(c) && isNonEmptyFile(k) {
			return c, k, firstNonEmptyString(extractCertDomain(c), cleanDomain)
		}
	}

	panelCert, _ := s.settingService.GetCertFile()
	panelKey, _ := s.settingService.GetKeyFile()
	panelCert = strings.TrimSpace(panelCert)
	panelKey = strings.TrimSpace(panelKey)
	if isNonEmptyFile(panelCert) && isNonEmptyFile(panelKey) {
		certDom := extractCertDomain(panelCert)
		if domain == "" || certDom == "" || strings.EqualFold(certDom, domain) || certMatchesDomain(panelCert, domain) {
			return panelCert, panelKey, certDom
		}
	}

	if domain == "" {
		matches, _ := filepath.Glob(filepath.Join(defaultCertSearchRoot, "*", "fullchain.pem"))
		sort.Strings(matches)
		for _, c := range matches {
			dir := filepath.Dir(c)
			k := filepath.Join(dir, "privkey.pem")
			if !isNonEmptyFile(c) || !isNonEmptyFile(k) {
				continue
			}
			dirName := filepath.Base(dir)
			d := extractCertDomain(c)
			if d == "" && dirName != "" && dirName != "ip" {
				d = dirName
			}
			return c, k, d
		}
	}

	return "", "", ""
}

func sanitizeCertDirName(domain string) string {
	d := strings.TrimSpace(domain)
	if d == "" || d == "." || d == ".." || strings.ContainsAny(d, `/\`) {
		return ""
	}
	return d
}

func parseFirstCert(certPath string) *x509.Certificate {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	for len(raw) > 0 {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
				return cert
			}
		}
	}
	return nil
}

func extractCertDomain(certPath string) string {
	cert := parseFirstCert(certPath)
	if cert == nil {
		return ""
	}
	for _, dns := range cert.DNSNames {
		if trimmed := strings.TrimSpace(dns); trimmed != "" {
			return trimmed
		}
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

func certMatchesDomain(certPath, domain string) bool {
	cert := parseFirstCert(certPath)
	if cert == nil {
		// Non-x509 test fixtures or custom certs: allow explicit panel cert if domain isn't parseable.
		return true
	}
	return cert.VerifyHostname(domain) == nil
}

func isNonEmptyFile(path string) bool {
	info, err := os.Stat(strings.TrimSpace(path))
	return err == nil && !info.IsDir() && info.Size() > 0
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func ensureInboundTLSCert(ib *model.Inbound, certFile, keyFile, sniHint string) bool {
	if ib == nil || strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return false
	}
	if ib.Protocol != model.Hysteria && ib.Protocol != model.TUIC && ib.Protocol != model.AnyTLS {
		return false
	}

	stream := map[string]any{}
	if strings.TrimSpace(ib.StreamSettings) != "" {
		if err := json.Unmarshal([]byte(ib.StreamSettings), &stream); err != nil {
			return false
		}
	}
	tlsMap, _ := stream["tlsSettings"].(map[string]any)
	if tlsMap == nil {
		tlsMap = map[string]any{}
	}
	if certs, ok := tlsMap["certificates"].([]any); ok && len(certs) > 0 {
		if first, ok := certs[0].(map[string]any); ok {
			cf, _ := first["certificateFile"].(string)
			kf, _ := first["keyFile"].(string)
			if strings.TrimSpace(cf) != "" && strings.TrimSpace(kf) != "" {
				return false
			}
		}
	}

	tlsMap["certificates"] = []map[string]any{
		{
			"certificateFile": certFile,
			"keyFile":         keyFile,
		},
	}
	if curSNI, _ := tlsMap["serverName"].(string); strings.TrimSpace(curSNI) == "" {
		if sni := firstNonEmptyString(ib.GatewaySNI, sniHint); sni != "" {
			tlsMap["serverName"] = sni
		}
	}
	stream["tlsSettings"] = tlsMap
	encoded, err := json.Marshal(stream)
	if err != nil {
		return false
	}
	ib.StreamSettings = string(encoded)
	if strings.TrimSpace(ib.GatewaySNI) == "" && strings.TrimSpace(sniHint) != "" {
		ib.GatewaySNI = strings.TrimSpace(sniHint)
	}
	return true
}

func pickRelocatedPort(preferred int, conflictPorts ...int) int {
	conflicts := make(map[int]bool, len(conflictPorts))
	for _, p := range conflictPorts {
		if p > 0 {
			conflicts[p] = true
		}
	}
	candidates := []int{preferred}
	for p := 30053; p <= 30099; p++ {
		candidates = append(candidates, p)
	}
	var lc net.ListenConfig
	for _, p := range candidates {
		if p <= 0 || conflicts[p] {
			continue
		}
		if ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			_ = ln.Close()
			return p
		}
	}
	return preferred
}
