package speedtest

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSpeedtestHandlerRoutes(t *testing.T) {
	h := NewHandler()

	// 1. Root page returns embedded OpenSpeedTest HTML.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "openSpeedTestServerList") {
		t.Fatalf("GET / body missing expected speedtest marker")
	}

	// 2. Random probe path falls back to speedtest HTML cleanly.
	recProbe := httptest.NewRecorder()
	h.ServeHTTP(recProbe, httptest.NewRequest(http.MethodGet, "/random-probe-1234", nil))
	if recProbe.Code != http.StatusOK || !strings.Contains(recProbe.Body.String(), "openSpeedTestServerList") {
		t.Fatalf("GET /random-probe-1234 did not fallback to speedtest HTML (status=%d)", recProbe.Code)
	}

	// 3. Static JS asset loads from embedded assets.
	recJS := httptest.NewRecorder()
	h.ServeHTTP(recJS, httptest.NewRequest(http.MethodGet, "/assets/js/app-2.5.4.min.js", nil))
	if recJS.Code != http.StatusOK || recJS.Body.Len() == 0 {
		t.Fatalf("GET /assets/js/app-2.5.4.min.js status=%d len=%d", recJS.Code, recJS.Body.Len())
	}

	// 4. GET /downloading streams exactly downloadPayloadBytes.
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/downloading?n=0.5")
	if err != nil {
		t.Fatalf("GET /downloading failed: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read /downloading failed: %v", err)
	}
	if n != downloadPayloadBytes {
		t.Fatalf("GET /downloading bytes = %d, want %d", n, downloadPayloadBytes)
	}

	// 5. GET /upload (ping) and POST /upload (12 MiB payload > 10 MiB panel cap).
	recPing := httptest.NewRecorder()
	h.ServeHTTP(recPing, httptest.NewRequest(http.MethodGet, "/upload", nil))
	if recPing.Code != http.StatusOK {
		t.Fatalf("GET /upload status = %d, want 200", recPing.Code)
	}

	uploadBody := bytes.Repeat([]byte("A"), 12<<20)
	upResp, err := http.Post(srv.URL+"/upload", "application/octet-stream", bytes.NewReader(uploadBody))
	if err != nil {
		t.Fatalf("POST /upload failed: %v", err)
	}
	_ = upResp.Body.Close()
	if upResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /upload status = %d, want 200", upResp.StatusCode)
	}
}
