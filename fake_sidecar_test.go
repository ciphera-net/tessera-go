package tessera

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeSidecar listens on a temp UDS and replies to each framed JSON request via handler.
type fakeSidecar struct {
	path     string
	ln       net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	requests []map[string]any
}

func newFakeSidecar(t *testing.T, handler func(req map[string]any) map[string]any) *fakeSidecar {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSidecar{path: path, ln: ln}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go f.serveConn(conn, handler)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); _ = os.Remove(path); f.wg.Wait() })
	return f
}

func (f *fakeSidecar) serveConn(conn net.Conn, handler func(map[string]any) map[string]any) {
	defer conn.Close()
	for {
		frame, err := readFrame(conn)
		if err != nil {
			return
		}
		var req map[string]any
		if err := json.Unmarshal(frame, &req); err != nil {
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		resp, _ := json.Marshal(handler(req))
		if err := writeFrame(conn, resp); err != nil {
			return
		}
	}
}

func (f *fakeSidecar) lastRequest(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("no requests recorded")
	}
	return f.requests[len(f.requests)-1]
}
