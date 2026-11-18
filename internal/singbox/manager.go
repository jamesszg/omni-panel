package singbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jamesszg/omni-panel/internal/config"
	"github.com/jamesszg/omni-panel/internal/database/model"
	"github.com/jamesszg/omni-panel/internal/logger"
	"github.com/jamesszg/omni-panel/internal/xray"
)

var (
	managerOnce sync.Once
	manager     *Manager
)

// Manager owns the singleton upstream sing-box child process and traffic tracker.
type Manager struct {
	mu          sync.Mutex
	proc        *Process
	configPath  string
	configFP    string
	clashPort   int
	clashSecret string
	lastError   string
	tracker     *TrafficTracker
}

// GetManager returns the process-wide sing-box Manager singleton.
func GetManager() *Manager {
	managerOnce.Do(func() {
		manager = &Manager{
			tracker: NewTrafficTracker(),
		}
	})
	return manager
}

// BinaryCandidates returns ordered paths checked inside config.GetBinFolderPath().
func BinaryCandidates() []string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binDir := config.GetBinFolderPath()
	return []string{
		filepath.Join(binDir, fmt.Sprintf("sing-box-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)),
		filepath.Join(binDir, "sing-box"+ext),
	}
}

// FindBinary locates the upstream sing-box executable in bin/ or PATH.
func FindBinary() (string, error) {
	for _, candidate := range BinaryCandidates() {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("sing-box binary not found in %s or PATH", config.GetBinFolderPath())
}

// ValidateConfig writes rawJSON without BOM to a temp file and validates it with `sing-box check -c`.
func ValidateConfig(binPath string, rawJSON []byte) error {
	if binPath == "" {
		return errors.New("empty sing-box binary path")
	}
	tmp, err := os.CreateTemp("", "omni-singbox-check-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(rawJSON); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "check", "-c", tmpPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("sing-box check failed: %s", msg)
	}
	return nil
}

// Reconcile drives the running sing-box process to match enabled local inbounds
// with EffectiveCore() == "singbox".
func (m *Manager) Reconcile(inbounds []*model.Inbound, clashPort int, clashSecret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	active := make([]*model.Inbound, 0, len(inbounds))
	for _, ib := range inbounds {
		if ib != nil && ib.Enable && ib.NodeID == nil && ib.EffectiveCore() == "singbox" {
			active = append(active, ib)
		}
	}

	if len(active) == 0 {
		m.stopLocked()
		m.configFP = ""
		m.lastError = ""
		return nil
	}

	rawJSON, err := BuildConfig(active, clashPort, clashSecret)
	if err != nil {
		m.lastError = err.Error()
		return err
	}

	binPath, err := FindBinary()
	if err != nil {
		m.lastError = err.Error()
		return err
	}

	sum := sha256.Sum256(append([]byte(binPath+"\n"), rawJSON...))
	fp := hex.EncodeToString(sum[:])

	if m.proc != nil && m.proc.IsRunning() && m.configFP == fp {
		return nil
	}

	if err := ValidateConfig(binPath, rawJSON); err != nil {
		m.lastError = err.Error()
		return err
	}

	m.stopLocked()

	cfgDir := filepath.Join(config.GetBinFolderPath(), "singbox")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		m.lastError = err.Error()
		return err
	}
	cfgPath := filepath.Join(cfgDir, "sing-box.json")
	if err := os.WriteFile(cfgPath, rawJSON, 0o600); err != nil {
		m.lastError = err.Error()
		return err
	}

	proc := newProcess(binPath, cfgPath)
	if err := proc.Start(); err != nil {
		m.lastError = err.Error()
		return err
	}

	m.proc = proc
	m.configPath = cfgPath
	m.configFP = fp
	m.clashPort = clashPort
	m.clashSecret = clashSecret
	m.lastError = ""
	m.tracker.Reset()
	logger.Infof("singbox: started process (%s) with %d inbound(s)", binPath, len(active))
	return nil
}

// CollectTraffic polls the running sing-box Clash API /connections endpoint.
func (m *Manager) CollectTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, []string, error) {
	m.mu.Lock()
	running := m.proc != nil && m.proc.IsRunning()
	port := m.clashPort
	secret := m.clashSecret
	m.mu.Unlock()

	if !running || port <= 0 {
		return nil, nil, nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return m.tracker.PollPort(ctx, port, secret)
}

// StopAll stops any running sing-box process.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	m.configFP = ""
}

func (m *Manager) stopLocked() {
	if m.proc != nil {
		if err := m.proc.Stop(); err != nil {
			logger.Warning("singbox: stop error:", err)
		}
		m.proc = nil
	}
	m.tracker.Reset()
}

// IsRunning reports whether sing-box is currently running.
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.proc != nil && m.proc.IsRunning()
}

// LastError returns the latest configuration/startup error encountered by Reconcile.
func (m *Manager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastError != "" {
		return m.lastError
	}
	if m.proc != nil {
		return m.proc.LastResult()
	}
	return ""
}

// Version returns the installed upstream sing-box version string, or empty if unavailable.
func (m *Manager) Version() string {
	binPath, err := FindBinary()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "version").CombinedOutput()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "sing-box version "); ok {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(string(out))
}
