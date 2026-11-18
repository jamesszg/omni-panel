package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jamesszg/omni-panel/internal/xray"
)

// ClashConnectionsResponse mirrors GET /connections from sing-box's experimental Clash API.
type ClashConnectionsResponse struct {
	DownloadTotal int64             `json:"downloadTotal"`
	UploadTotal   int64             `json:"uploadTotal"`
	Connections   []ClashConnection `json:"connections"`
}

// ClashConnection is a single active connection reported by Clash API.
type ClashConnection struct {
	ID       string            `json:"id"`
	Upload   int64             `json:"upload"`
	Download int64             `json:"download"`
	Metadata ClashConnMetadata `json:"metadata"`
}

// ClashConnMetadata identifies the inbound and authenticated user for a connection.
type ClashConnMetadata struct {
	Inbound     string `json:"inbound"`
	InboundName string `json:"inboundName"`
	InboundPort string `json:"inboundPort"`
	User        string `json:"user"`
	SourceIP    string `json:"sourceIP"`
}

type connCounter struct {
	upload   int64
	download int64
}

// TrafficTracker polls a sing-box Clash API controller and converts cumulative
// per-connection counters into incremental deltas compatible with xray.Traffic
// and xray.ClientTraffic.
type TrafficTracker struct {
	mu     sync.Mutex
	client *http.Client
	prev   map[string]connCounter
}

// NewTrafficTracker creates a tracker for Clash API traffic polling.
func NewTrafficTracker() *TrafficTracker {
	return &TrafficTracker{
		client: &http.Client{Timeout: 2 * time.Second},
		prev:   make(map[string]connCounter),
	}
}

// Reset clears tracked connection state (for example on core restart).
func (t *TrafficTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prev = make(map[string]connCounter)
}

// PollBaseURL fetches /connections from baseURL (e.g. "http://127.0.0.1:62795")
// and returns inbound traffic deltas, client traffic deltas, and active user emails.
func (t *TrafficTracker) PollBaseURL(ctx context.Context, baseURL, secret string) ([]*xray.Traffic, []*xray.ClientTraffic, []string, error) {
	url := strings.TrimRight(baseURL, "/") + "/connections"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("clash api returned status %d", resp.StatusCode)
	}

	var payload ClashConnectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, nil, nil, fmt.Errorf("decode clash /connections: %w", err)
	}
	traffics, clientTraffics, online := t.ProcessSnapshot(&payload)
	return traffics, clientTraffics, online, nil
}

// PollPort polls 127.0.0.1:<clashPort> using PollBaseURL.
func (t *TrafficTracker) PollPort(ctx context.Context, clashPort int, secret string) ([]*xray.Traffic, []*xray.ClientTraffic, []string, error) {
	return t.PollBaseURL(ctx, fmt.Sprintf("http://127.0.0.1:%d", clashPort), secret)
}

// ProcessSnapshot computes traffic deltas from a decoded /connections snapshot.
// Returning slices separately from PollBaseURL makes unit testing straightforward.
func (t *TrafficTracker) ProcessSnapshot(snap *ClashConnectionsResponse) (traffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic, online []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if snap == nil {
		return nil, nil, nil
	}

	next := make(map[string]connCounter, len(snap.Connections))
	inboundDeltas := make(map[string]*xray.Traffic)
	clientDeltas := make(map[string]*xray.ClientTraffic)
	onlineSet := make(map[string]struct{})

	for _, c := range snap.Connections {
		if c.ID == "" {
			continue
		}
		prev := t.prev[c.ID]
		du := c.Upload - prev.upload
		dd := c.Download - prev.download
		if du < 0 {
			du = c.Upload
		}
		if dd < 0 {
			dd = c.Download
		}
		next[c.ID] = connCounter{upload: c.Upload, download: c.Download}

		tag := strings.TrimSpace(c.Metadata.InboundName)
		if tag == "" {
			tag = strings.TrimSpace(c.Metadata.Inbound)
		}
		user := strings.TrimSpace(c.Metadata.User)
		if user != "" {
			onlineSet[user] = struct{}{}
		}

		if du == 0 && dd == 0 {
			continue
		}
		if tag != "" {
			tr := inboundDeltas[tag]
			if tr == nil {
				tr = &xray.Traffic{IsInbound: true, Tag: tag}
				inboundDeltas[tag] = tr
			}
			tr.Up += du
			tr.Down += dd
		}
		if user != "" {
			ct := clientDeltas[user]
			if ct == nil {
				ct = &xray.ClientTraffic{Email: user}
				clientDeltas[user] = ct
			}
			ct.Up += du
			ct.Down += dd
		}
	}

	t.prev = next

	traffics = make([]*xray.Traffic, 0, len(inboundDeltas))
	for _, tr := range inboundDeltas {
		traffics = append(traffics, tr)
	}
	clientTraffics = make([]*xray.ClientTraffic, 0, len(clientDeltas))
	for _, ct := range clientDeltas {
		clientTraffics = append(clientTraffics, ct)
	}
	online = make([]string, 0, len(onlineSet))
	for email := range onlineSet {
		online = append(online, email)
	}
	slices.Sort(online)
	return traffics, clientTraffics, online
}
