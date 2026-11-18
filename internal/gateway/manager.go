package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jamesszg/omni-panel/internal/config"
	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/logger"
)

// ReconcileOptions supplies all desired settings and inbounds for gateway reconciliation.
type ReconcileOptions struct {
	Enabled         bool
	PublicPort      int
	L7Port          int
	ListenIPv6      bool
	Domain          string
	CertFile        string
	KeyFile         string
	AcmeMode        string
	AcmeEmail       string
	AcmeCfToken     string
	SpeedtestEnable bool
	WebBasePath     string
	WebBackendURL   string
	SubPaths        []string
	SubBackendURL   string
	Inbounds        []*model.Inbound
}

// RuntimeStatus captures live gateway health, process state, and topology.
type RuntimeStatus struct {
	Enabled         bool             `json:"enabled"`
	L7Running       bool             `json:"l7Running"`
	L7Addr          string           `json:"l7Addr"`
	RpxyBinaryFound bool             `json:"rpxyBinaryFound"`
	RpxyRunning     bool             `json:"rpxyRunning"`
	LastError       string           `json:"lastError,omitempty"`
	Topology        *TopologySummary `json:"topology,omitempty"`
}

var (
	managerOnce sync.Once
	manager     *Manager
)

// Manager supervises the embedded L7 TLS server and rust-rpxy-l4 multiplexer process.
type Manager struct {
	mu         sync.Mutex
	certMgr    *CertManager
	l7         *L7Server
	l7Port     int
	rpxyProc   *rpxyProcess
	rpxyConfig string
	rpxyFP     string
	lastErr    string
	status     RuntimeStatus
}

// GetManager returns the process-wide Gateway Manager singleton.
func GetManager() *Manager {
	managerOnce.Do(func() {
		manager = &Manager{}
	})
	return manager
}

// FindRpxyBinary locates the rust-rpxy-l4 executable in bin/ or PATH.
func FindRpxyBinary() (string, error) {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binDir := config.GetBinFolderPath()
	candidates := []string{
		filepath.Join(binDir, fmt.Sprintf("rpxy-l4-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)),
		filepath.Join(binDir, "rpxy-l4"+ext),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	if p, err := exec.LookPath("rpxy-l4"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("rpxy-l4 binary not found in %s or PATH", binDir)
}

// BuildL7Routes derives L7 path routes for enabled local `l7_path` inbounds.
func BuildL7Routes(opts ReconcileOptions) L7RouteConfig {
	pathRoutes := make([]L7InboundRoute, 0)
	for _, ib := range opts.Inbounds {
		if ib == nil || !ib.Enable || ib.NodeID != nil || ib.GatewayMode != "l7_path" {
			continue
		}
		pathPrefix := strings.TrimSpace(ib.GatewayPath)
		var stream struct {
			Network       string                       `json:"network"`
			WSSettings    struct{ Path string }        `json:"wsSettings"`
			HttpUpgrade   struct{ Path string }        `json:"httpupgradeSettings"`
			XHttpSettings struct{ Path string }        `json:"xhttpSettings"`
			GrpcSettings  struct{ ServiceName string } `json:"grpcSettings"`
		}
		_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)
		if pathPrefix == "" {
			switch stream.Network {
			case "ws":
				pathPrefix = stream.WSSettings.Path
			case "httpupgrade":
				pathPrefix = stream.HttpUpgrade.Path
			case "xhttp":
				pathPrefix = stream.XHttpSettings.Path
			case "grpc":
				if stream.GrpcSettings.ServiceName != "" {
					pathPrefix = "/" + strings.TrimPrefix(stream.GrpcSettings.ServiceName, "/")
				}
			}
		}
		if pathPrefix == "" {
			pathPrefix = "/"
		}
		pathRoutes = append(pathRoutes, L7InboundRoute{
			PathPrefix: pathPrefix,
			SNI:        strings.TrimSpace(ib.GatewaySNI),
			TargetAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(ib.Port)),
			IsGRPC:     stream.Network == "grpc",
		})
	}
	return L7RouteConfig{
		WebBasePath:     opts.WebBasePath,
		WebBackendURL:   opts.WebBackendURL,
		SubPaths:        opts.SubPaths,
		SubBackendURL:   opts.SubBackendURL,
		PathRoutes:      pathRoutes,
		SpeedtestEnable: opts.SpeedtestEnable,
	}
}

// Reconcile drives the L7 TLS server and rust-rpxy-l4 process to match opts.
func (m *Manager) Reconcile(opts ReconcileOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if opts.PublicPort <= 0 {
		opts.PublicPort = 443
	}
	if opts.L7Port <= 0 {
		opts.L7Port = 30000
	}

	tomlCfg, summary, err := BuildRpxyConfig(RpxyConfigOptions{
		PublicPort:    opts.PublicPort,
		L7Port:        opts.L7Port,
		ListenIPv6:    opts.ListenIPv6,
		Inbounds:      opts.Inbounds,
		GatewayDomain: opts.Domain,
	})
	if err != nil {
		m.lastErr = err.Error()
		m.status = RuntimeStatus{Enabled: opts.Enabled, LastError: m.lastErr}
		return err
	}

	_, rpxyBinErr := FindRpxyBinary()
	status := RuntimeStatus{
		Enabled:         opts.Enabled,
		RpxyBinaryFound: rpxyBinErr == nil,
		Topology:        summary,
	}

	if !opts.Enabled {
		m.stopLocked()
		m.lastErr = ""
		m.status = status
		return nil
	}

	certDir := filepath.Join(config.GetBinFolderPath(), "certs")
	certCfg := CertConfig{
		Domain:      opts.Domain,
		CertFile:    opts.CertFile,
		KeyFile:     opts.KeyFile,
		AcmeMode:    opts.AcmeMode,
		AcmeEmail:   opts.AcmeEmail,
		AcmeCfToken: opts.AcmeCfToken,
	}
	if m.certMgr == nil {
		cm, err := NewCertManager(certDir, certCfg)
		if err != nil {
			m.lastErr = err.Error()
			status.LastError = m.lastErr
			m.status = status
			return err
		}
		m.certMgr = cm
	} else {
		if err := m.certMgr.Reload(certCfg); err != nil {
			logger.Warning("gateway: cert reload failed:", err)
		}
	}

	l7Cfg := BuildL7Routes(opts)
	if m.l7 != nil && m.l7Port != opts.L7Port {
		_ = m.l7.Stop()
		m.l7 = nil
	}
	if m.l7 == nil {
		srv := NewL7Server(m.certMgr, l7Cfg)
		if err := srv.Start(net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.L7Port))); err != nil {
			m.lastErr = err.Error()
			status.LastError = m.lastErr
			m.status = status
			return err
		}
		m.l7 = srv
		m.l7Port = opts.L7Port
	} else {
		m.l7.UpdateRoutes(l7Cfg)
	}
	status.L7Running = true
	status.L7Addr = m.l7.Addr()

	// Reconcile rust-rpxy-l4 if binary is installed.
	binPath, err := FindRpxyBinary()
	if err != nil {
		m.stopRpxyLocked()
		m.lastErr = err.Error()
		status.LastError = m.lastErr
		m.status = status
		return err
	}

	sum := sha256.Sum256(append([]byte(binPath+"\n"), []byte(tomlCfg)...))
	fp := hex.EncodeToString(sum[:])

	if m.rpxyProc == nil || !m.rpxyProc.IsRunning() || m.rpxyFP != fp {
		m.stopRpxyLocked()
		cfgDir := filepath.Join(config.GetBinFolderPath(), "gateway")
		if err := os.MkdirAll(cfgDir, 0o755); err != nil {
			m.lastErr = err.Error()
			status.LastError = m.lastErr
			m.status = status
			return err
		}
		cfgPath := filepath.Join(cfgDir, "rust-rpxy-l4.toml")
		if err := os.WriteFile(cfgPath, []byte(tomlCfg), 0o600); err != nil {
			m.lastErr = err.Error()
			status.LastError = m.lastErr
			m.status = status
			return err
		}
		proc := newRpxyProcess(binPath, cfgPath)
		if err := proc.Start(); err != nil {
			m.lastErr = err.Error()
			status.LastError = m.lastErr
			m.status = status
			return err
		}
		m.rpxyProc = proc
		m.rpxyConfig = cfgPath
		m.rpxyFP = fp
		logger.Infof("gateway: started rust-rpxy-l4 on :%d", opts.PublicPort)
	}

	status.RpxyRunning = m.rpxyProc != nil && m.rpxyProc.IsRunning()
	m.lastErr = ""
	m.status = status
	return nil
}

// Status returns the latest RuntimeStatus snapshot.
func (m *Manager) Status() RuntimeStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status
	_, err := FindRpxyBinary()
	st.RpxyBinaryFound = err == nil
	st.L7Running = m.l7 != nil && m.l7.Addr() != ""
	if m.l7 != nil {
		st.L7Addr = m.l7.Addr()
	}
	st.RpxyRunning = m.rpxyProc != nil && m.rpxyProc.IsRunning()
	if st.LastError == "" && m.lastErr != "" {
		st.LastError = m.lastErr
	}
	return st
}

// StopAll stops both rust-rpxy-l4 and the L7 TLS server.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Manager) stopLocked() {
	m.stopRpxyLocked()
	if m.l7 != nil {
		_ = m.l7.Stop()
		m.l7 = nil
		m.l7Port = 0
	}
}

func (m *Manager) stopRpxyLocked() {
	if m.rpxyProc != nil {
		_ = m.rpxyProc.Stop()
		m.rpxyProc = nil
	}
	m.rpxyFP = ""
}

type rpxyProcess struct {
	mu              sync.RWMutex
	cmd             *exec.Cmd
	done            chan struct{}
	binPath         string
	configPath      string
	intentionalStop atomic.Bool
}

func newRpxyProcess(binPath, configPath string) *rpxyProcess {
	return &rpxyProcess{
		binPath:    binPath,
		configPath: configPath,
	}
}

func (p *rpxyProcess) IsRunning() bool {
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if done != nil {
		select {
		case <-done:
			return false
		default:
		}
	}
	return true
}

func (p *rpxyProcess) Start() error {
	if p.IsRunning() {
		return errors.New("rpxy-l4 is already running")
	}
	cmd := exec.CommandContext(context.Background(), p.binPath, "-c", p.configPath)
	done := make(chan struct{})
	p.mu.Lock()
	p.cmd = cmd
	p.done = done
	p.mu.Unlock()
	p.intentionalStop.Store(false)
	if err := cmd.Start(); err != nil {
		close(done)
		p.mu.Lock()
		p.cmd = nil
		p.mu.Unlock()
		return err
	}
	attachChildLifetime(cmd)
	go func() {
		defer close(done)
		err := cmd.Wait()
		if err != nil && !p.intentionalStop.Load() {
			logger.Errorf("gateway: rust-rpxy-l4 exited unexpectedly: %v", err)
		}
	}()
	return nil
}

func (p *rpxyProcess) Stop() error {
	if !p.IsRunning() {
		return nil
	}
	p.intentionalStop.Store(true)
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return waitExit(done, 2*time.Second)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return waitExit(done, 2*time.Second)
		}
		return err
	}
	if waitExit(done, 5*time.Second) == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return waitExit(done, 2*time.Second)
}

func waitExit(done <-chan struct{}, timeout time.Duration) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for rpxy-l4 exit after %s", timeout)
	}
}
