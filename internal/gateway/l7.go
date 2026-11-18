package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/jamesszg/omni-panel/internal/gateway/speedtest"
	"github.com/jamesszg/omni-panel/internal/web/network"
)

// L7InboundRoute maps an L7 path (WS / HTTPUpgrade / gRPC / XHTTP) to an internal core port.
type L7InboundRoute struct {
	PathPrefix string
	SNI        string
	TargetAddr string
	IsGRPC     bool
}

// L7RouteConfig holds the routing table evaluated on every request reaching the L7 TLS gateway.
type L7RouteConfig struct {
	WebBasePath     string
	WebBackendURL   string
	SubPaths        []string
	SubBackendURL   string
	PathRoutes      []L7InboundRoute
	SpeedtestEnable bool
}

// L7Server terminates TLS on loopback (with optional PROXY protocol v2 from rust-rpxy-l4),
// routes panel/subscription/L7-transport traffic, and falls back to OpenSpeedTest.
type L7Server struct {
	mu           sync.RWMutex
	certMgr      *CertManager
	cfg          L7RouteConfig
	speedtest    http.Handler
	httpServer   *http.Server
	rawLn        net.Listener
	boundAddr    string
	h1Transport  *http.Transport
	h2cTransport *http.Transport
}

// NewL7Server constructs an L7Server backed by certMgr.
func NewL7Server(certMgr *CertManager, cfg L7RouteConfig) *L7Server {
	h2cProtocols := new(http.Protocols)
	h2cProtocols.SetUnencryptedHTTP2(true)
	s := &L7Server{
		certMgr:   certMgr,
		cfg:       normalizeL7RouteConfig(cfg),
		speedtest: speedtest.NewHandler(),
		h1Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				// Loopback-only backend proxy when panel/sub uses internal TLS.
				InsecureSkipVerify: true, //nolint:gosec // intentional loopback panel/sub backend dial
			},
			MaxIdleConns:        128,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		h2cTransport: &http.Transport{
			Proxy:     nil,
			Protocols: h2cProtocols,
		},
	}
	return s
}

func normalizeL7RouteConfig(cfg L7RouteConfig) L7RouteConfig {
	bp := strings.TrimSpace(cfg.WebBasePath)
	if bp == "" {
		bp = "/"
	}
	if !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}
	if bp != "/" && !strings.HasSuffix(bp, "/") {
		bp += "/"
	}
	cfg.WebBasePath = bp

	subs := make([]string, 0, len(cfg.SubPaths))
	for _, p := range cfg.SubPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		subs = append(subs, p)
	}
	cfg.SubPaths = subs

	routes := make([]L7InboundRoute, 0, len(cfg.PathRoutes))
	for _, r := range cfg.PathRoutes {
		if strings.TrimSpace(r.TargetAddr) == "" {
			continue
		}
		p := strings.TrimSpace(r.PathPrefix)
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		r.PathPrefix = p
		r.SNI = strings.TrimSpace(r.SNI)
		routes = append(routes, r)
	}
	// Longer prefixes match first so "/vless-ws" wins over "/".
	slices.SortFunc(routes, func(a, b L7InboundRoute) int {
		if len(a.PathPrefix) != len(b.PathPrefix) {
			return len(b.PathPrefix) - len(a.PathPrefix)
		}
		return strings.Compare(a.PathPrefix, b.PathPrefix)
	})
	cfg.PathRoutes = routes
	return cfg
}

// UpdateRoutes atomically swaps the live L7 routing table.
func (s *L7Server) UpdateRoutes(cfg L7RouteConfig) {
	norm := normalizeL7RouteConfig(cfg)
	s.mu.Lock()
	s.cfg = norm
	s.mu.Unlock()
}

// Start binds listenAddr (e.g. "127.0.0.1:30000") and begins serving HTTPS + PROXY protocol.
func (s *L7Server) Start(listenAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpServer != nil {
		return nil
	}
	rawLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return err
	}
	ppLn := &proxyproto.Listener{
		Listener:          rawLn,
		ReadHeaderTimeout: 2 * time.Second,
		ConnPolicy: func(_ proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.USE, nil
		},
	}
	tlsLn := tls.NewListener(ppLn, s.certMgr.TLSConfig())

	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.rawLn = rawLn
	s.boundAddr = rawLn.Addr().String()
	s.httpServer = srv

	go network.ServeHTTP(srv, tlsLn, "Gateway L7")
	return nil
}

// Addr returns the bound listener address once Start has succeeded.
func (s *L7Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.boundAddr
}

// Stop gracefully shuts down the L7 HTTP/TLS server.
func (s *L7Server) Stop() error {
	s.mu.Lock()
	srv := s.httpServer
	ln := s.rawLn
	s.httpServer = nil
	s.rawLn = nil
	s.boundAddr = ""
	s.mu.Unlock()

	var err error
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = srv.Shutdown(ctx)
		cancel()
	}
	if ln != nil {
		if cerr := ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = cerr
		}
	}
	return err
}

// ServeHTTP dispatches incoming L7 requests to proxy transports, panel, sub, or speedtest fallback.
func (s *L7Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()

	reqPath := r.URL.Path
	reqHost := stripHostPort(r.Host)

	// 1. Check inbound L7 transport routes first (WS / HTTPUpgrade / gRPC / XHTTP).
	for _, route := range cfg.PathRoutes {
		if route.SNI != "" && !strings.EqualFold(reqHost, route.SNI) {
			continue
		}
		if strings.HasPrefix(reqPath, route.PathPrefix) {
			target := &url.URL{Scheme: "http", Host: route.TargetAddr}
			s.proxyRequest(w, r, target, route.IsGRPC || isGRPCRequest(r))
			return
		}
	}

	// 2. Route configured non-root Panel webBasePath.
	if cfg.WebBackendURL != "" && cfg.WebBasePath != "/" {
		trimmedBase := strings.TrimSuffix(cfg.WebBasePath, "/")
		if reqPath == trimmedBase || strings.HasPrefix(reqPath, cfg.WebBasePath) {
			if target, err := url.Parse(cfg.WebBackendURL); err == nil {
				s.proxyRequest(w, r, target, false)
				return
			}
		}
	}

	// 3. Route subscription paths (/sub/, /json/, /clash/).
	if cfg.SubBackendURL != "" {
		for _, subPrefix := range cfg.SubPaths {
			trimmedSub := strings.TrimSuffix(subPrefix, "/")
			if reqPath == trimmedSub || strings.HasPrefix(reqPath, subPrefix) {
				if target, err := url.Parse(cfg.SubBackendURL); err == nil {
					s.proxyRequest(w, r, target, false)
					return
				}
			}
		}
	}

	// 4. Fallback to embedded static OpenSpeedTest for probing / root / unmatched requests.
	if cfg.SpeedtestEnable {
		s.speedtest.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *L7Server) proxyRequest(w http.ResponseWriter, r *http.Request, target *url.URL, useH2C bool) {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr)
			if err != nil {
				clientIP = pr.In.RemoteAddr
			}
			if clientIP != "" {
				pr.Out.Header.Set("X-Real-IP", clientIP)
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(rw, "Bad Gateway", http.StatusBadGateway)
		},
	}
	if useH2C {
		proxy.Transport = s.h2cTransport
	} else {
		proxy.Transport = s.h1Transport
	}
	proxy.ServeHTTP(w, r)
}

func stripHostPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		return h
	}
	return host
}

func isGRPCRequest(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/grpc")
}
