package tessera

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRegisterStartSendsCorrectFields(t *testing.T) {
	f := newFakeSidecar(t, func(req map[string]any) map[string]any {
		return map[string]any{"result": "register_start", "response_b64": "RESP"}
	})
	c := NewClient(f.path)
	got, err := c.RegisterStart(context.Background(), "REQ", "creds-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "RESP" {
		t.Fatalf("got %q", got)
	}
	req := f.lastRequest(t)
	if req["op"] != "register_start" || req["request_b64"] != "REQ" || req["credential_id"] != "creds-1" {
		t.Fatalf("wrong request: %#v", req)
	}
}

func TestLoginStartNilPasswordFileEncodesNull(t *testing.T) {
	f := newFakeSidecar(t, func(req map[string]any) map[string]any {
		return map[string]any{"result": "login_start", "login_id": "L1", "response_b64": "CR"}
	})
	c := NewClient(f.path)
	if _, _, err := c.LoginStart(context.Background(), "REQ", nil, "creds-1"); err != nil {
		t.Fatal(err)
	}
	req := f.lastRequest(t)
	// nil *string must arrive as JSON null (key present, value nil) — the unknown-user path.
	v, ok := req["password_file_b64"]
	if !ok || v != nil {
		t.Fatalf("expected password_file_b64=null, got present=%v value=%#v", ok, v)
	}
}

func TestLoginStartWithPasswordFileEncodesString(t *testing.T) {
	f := newFakeSidecar(t, func(req map[string]any) map[string]any {
		return map[string]any{"result": "login_start", "login_id": "L1", "response_b64": "CR"}
	})
	c := NewClient(f.path)
	pf := "PWFILE"
	if _, _, err := c.LoginStart(context.Background(), "REQ", &pf, "creds-1"); err != nil {
		t.Fatal(err)
	}
	if f.lastRequest(t)["password_file_b64"] != "PWFILE" {
		t.Fatalf("expected password_file_b64=PWFILE")
	}
}

func TestErrorResponseMapsToSidecarError(t *testing.T) {
	f := newFakeSidecar(t, func(req map[string]any) map[string]any {
		return map[string]any{"result": "error", "code": "unknown_login", "message": "unknown login id"}
	})
	c := NewClient(f.path)
	_, err := c.LoginFinish(context.Background(), "nope", "FIN")
	var se *SidecarError
	if !errors.As(err, &se) || se.Code != "unknown_login" || se.Message != "unknown login id" {
		t.Fatalf("expected *SidecarError{unknown_login}, got %v", err)
	}
}

func TestConcurrentRequestsArePooled(t *testing.T) {
	f := newFakeSidecar(t, func(req map[string]any) map[string]any {
		return map[string]any{"result": "register_start", "response_b64": "OK"}
	})
	c := NewClient(f.path, WithPoolSize(8))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.RegisterStart(context.Background(), "REQ", "creds"); err != nil {
				t.Errorf("concurrent request failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestContextCancellationIsHonored(t *testing.T) {
	f := newFakeSidecar(t, func(req map[string]any) map[string]any {
		time.Sleep(500 * time.Millisecond) // slower than the ctx deadline
		return map[string]any{"result": "register_start", "response_b64": "OK"}
	})
	c := NewClient(f.path)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.RegisterStart(ctx, "REQ", "creds"); err == nil {
		t.Fatal("expected a deadline error")
	}
}
