// Package speedtest provides an embedded static OpenSpeedTest fallback web app
// served for unauthenticated/probing requests that reach the :443 L7 gateway.
package speedtest

import (
	"crypto/rand"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
)

//go:embed all:static
var staticFS embed.FS

const (
	downloadPayloadBytes = 30 << 20 // 30 MiB per /downloading stream
	maxUploadBodyBytes   = 45 << 20 // 45 MiB per /upload request
	chunkSize            = 64 << 10 // 64 KiB write buffer
)

var (
	noiseChunkOnce sync.Once
	noiseChunk     []byte
)

func getNoiseChunk() []byte {
	noiseChunkOnce.Do(func() {
		buf := make([]byte, chunkSize)
		_, _ = rand.Read(buf)
		noiseChunk = buf
	})
	return noiseChunk
}

// NewHandler returns an http.Handler serving the embedded OpenSpeedTest UI,
// /downloading bandwidth endpoint, and /upload ping/upload sink.
func NewHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean("/" + r.URL.Path)

		switch cleanPath {
		case "/downloading":
			handleDownloading(w, r)
			return
		case "/upload":
			handleUpload(w, r)
			return
		case "/favicon.ico":
			serveEmbeddedFile(w, r, sub, "assets/images/icons/favicon.ico", "image/x-icon")
			return
		}

		trimmed := strings.TrimPrefix(cleanPath, "/")
		if trimmed != "" {
			if info, err := fs.Stat(sub, trimmed); err == nil && !info.IsDir() {
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// Any unknown path falls back cleanly to the speedtest home page so active
		// TLS/HTTPS probes always observe a consistent static site.
		serveEmbeddedFile(w, r, sub, "index.html", "text/html; charset=utf-8")
	})
}

func serveEmbeddedFile(w http.ResponseWriter, r *http.Request, sub fs.FS, name, contentType string) {
	data, err := fs.ReadFile(sub, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func handleDownloading(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return
	}

	chunk := getNoiseChunk()
	remaining := downloadPayloadBytes
	ctx := r.Context()
	for remaining > 0 {
		if ctx.Err() != nil {
			return
		}
		toWrite := min(remaining, len(chunk))
		n, err := w.Write(chunk[:toWrite])
		remaining -= n
		if err != nil {
			return
		}
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		limited := http.MaxBytesReader(w, r.Body, maxUploadBodyBytes)
		_, _ = io.Copy(io.Discard, limited)
	}
	w.WriteHeader(http.StatusOK)
}
