// WARNING: this test drives examples/client_helper, which prints export_key on stdout; under
// `go test -v` that value lands in CI logs. Safe ONLY because the test uses an ephemeral
// ServerSetup (t.TempDir()) and a throw-away password — never point it at a production
// ServerSetup or a real user password.
//go:build integration

package tessera

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s must be set (path to the built binary)", k)
	}
	return v
}

type helper struct {
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Scanner
}

func newHelper(t *testing.T, bin string) *helper {
	t.Helper()
	c := exec.Command(bin)
	wc, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	h := &helper{cmd: c, stdin: bufio.NewWriter(wc), stdout: bufio.NewScanner(rc)}
	t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait() })
	return h
}

// line sends a command and returns the OK fields (fails the test on ERR).
func (h *helper) line(t *testing.T, cmd string) []string {
	t.Helper()
	if _, err := h.stdin.WriteString(cmd + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := h.stdin.Flush(); err != nil {
		t.Fatal(err)
	}
	// Bound the read so a hung/deadlocked helper fails fast with a clear message instead of
	// blocking until the 10-minute `go test` timeout. The buffered channel lets the Scan goroutine
	// finish and exit even if we already gave up (it drains once t.Cleanup kills the helper).
	scanned := make(chan bool, 1)
	go func() { scanned <- h.stdout.Scan() }()
	select {
	case ok := <-scanned:
		if !ok {
			t.Fatal("client helper produced no output (crashed or closed stdout)")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client helper did not reply within 15s (hung or deadlocked)")
	}
	reply := h.stdout.Text()
	fields := strings.Fields(reply)
	if len(fields) == 0 || fields[0] != "OK" {
		t.Fatalf("client helper error: %s", reply)
	}
	return fields[1:]
}

// waitForSocket blocks until the sidecar is actually accepting connections (not merely until the
// socket file exists): a connect probe distinguishes a live listener from a stale/dead socket file
// and gives a clear failure if the sidecar crashed during startup. The probe connection is closed
// immediately; the sidecar reads EOF and frees the slot.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sidecar socket did not accept connections within 3s")
}

func TestRealHandshakeAndVault(t *testing.T) {
	sidecarBin := mustEnv(t, "TESSERA_SIDECAR_BIN")
	helperBin := mustEnv(t, "TESSERA_CLIENT_HELPER_BIN")

	dir := t.TempDir()
	socket := filepath.Join(dir, "tessera.sock")
	setup := filepath.Join(dir, "setup.bin")

	if out, err := exec.Command(sidecarBin, "gen-setup", setup).CombinedOutput(); err != nil {
		t.Fatalf("gen-setup: %v: %s", err, out)
	}
	sc := exec.Command(sidecarBin, "serve", socket, setup)
	sc.Stderr = os.Stderr
	if err := sc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Process.Kill(); _, _ = sc.Process.Wait() })
	waitForSocket(t, socket)

	h := newHelper(t, helperBin)
	client := NewClient(socket)
	t.Cleanup(func() { _ = client.Close() })
	// Bound the whole exchange so a wedged sidecar fails fast (the client honors ctx deadlines)
	// rather than hanging until the default 10-minute `go test` timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const password = "correcthorsebatterystaple"   // single token: client_helper splits stdin lines on whitespace
	credID := BlindIndexString("user@example.com") // blind index doubles as credential_identifier

	// --- Registration ---
	regReq := h.line(t, "reg-start "+password)[0]
	regRespB64, err := client.RegisterStart(ctx, regReq, credID)
	if err != nil {
		t.Fatal(err)
	}
	regFin := h.line(t, "reg-finish "+password+" "+regRespB64) // [upload_b64, export_key_b64]
	uploadB64, regExportKeyB64 := regFin[0], regFin[1]
	passwordFileB64, err := client.RegisterFinish(ctx, uploadB64)
	if err != nil {
		t.Fatal(err)
	}

	// --- Login ---
	loginReq := h.line(t, "login-start "+password)[0]
	loginID, credRespB64, err := client.LoginStart(ctx, loginReq, &passwordFileB64, credID)
	if err != nil {
		t.Fatal(err)
	}
	loginFin := h.line(t, "login-finish "+password+" "+credRespB64) // [finalization, session_key, export_key]
	finalizationB64, clientSessionKeyB64, loginExportKeyB64 := loginFin[0], loginFin[1], loginFin[2]
	serverSessionKeyB64, err := client.LoginFinish(ctx, loginID, finalizationB64)
	if err != nil {
		t.Fatal(err)
	}

	if serverSessionKeyB64 != clientSessionKeyB64 {
		t.Fatalf("session key mismatch:\n server=%s\n client=%s", serverSessionKeyB64, clientSessionKeyB64)
	}
	if regExportKeyB64 != loginExportKeyB64 {
		t.Fatalf("export_key not stable across register/login:\n reg=%s\n login=%s", regExportKeyB64, loginExportKeyB64)
	}

	// --- Vault under the REAL export_key ---
	exportKey, err := base64.StdEncoding.DecodeString(loginExportKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	record := []byte(`{"address":"1 Privacy Way","totp":"JBSWY3DPEHPK3PXP"}`)
	env, err := Seal(exportKey, "address", record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(exportKey, "address", env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, record) {
		t.Fatal("vault round-trip mismatch under real export_key")
	}
}

// startSidecar boots a sidecar against an EXISTING ServerSetup and returns a
// connected client. Two calls with the same setup file model two replicas: they
// share one Vault-rendered secret and nothing else.
func startSidecar(t *testing.T, sidecarBin, dir, setup, name string) *Client {
	t.Helper()
	socket := filepath.Join(dir, name)
	sc := exec.Command(sidecarBin, "serve", socket, setup)
	sc.Stderr = os.Stderr
	if err := sc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Process.Kill(); _, _ = sc.Process.Wait() })
	waitForSocket(t, socket)
	c := NewClient(socket)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSealedStateFinishesOnAnotherSidecar is the SDK-level proof of the property
// that lets a server run more than one replica: a login started against one
// sidecar process is finished against a different one.
//
// The Rust repo proves the same thing about the sidecar; this proves the JOIN —
// that the Go SDK actually carries `state_b64` across the wire in both
// directions. That join is the part a passing Rust suite and a passing Go unit
// suite can BOTH miss, because each mocks the other side.
//
// Without it, a second replica fails roughly half of all logins, and fails them
// destructively: the caller resolves a real user from its shared binding, gets
// `unknown_login` back, and counts a correct password as a failed attempt.
func TestSealedStateFinishesOnAnotherSidecar(t *testing.T) {
	sidecarBin := mustEnv(t, "TESSERA_SIDECAR_BIN")
	helperBin := mustEnv(t, "TESSERA_CLIENT_HELPER_BIN")

	dir := t.TempDir()
	setup := filepath.Join(dir, "shared-setup.bin")
	if out, err := exec.Command(sidecarBin, "gen-setup", setup).CombinedOutput(); err != nil {
		t.Fatalf("gen-setup: %v: %s", err, out)
	}

	// Two independent processes, sharing only the ServerSetup file.
	a := startSidecar(t, sidecarBin, dir, setup, "a.sock")
	b := startSidecar(t, sidecarBin, dir, setup, "b.sock")

	h := newHelper(t, helperBin)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const password = "correcthorsebatterystaple"
	credID := BlindIndexString("multi-replica@example.com")

	// Register through A; finish registration on B — registration is stateless,
	// so this must work and is worth pinning.
	regReq := h.line(t, "reg-start "+password)[0]
	regRespB64, err := a.RegisterStart(ctx, regReq, credID)
	if err != nil {
		t.Fatal(err)
	}
	uploadB64 := h.line(t, "reg-finish "+password+" "+regRespB64)[0]
	passwordFileB64, err := b.RegisterFinish(ctx, uploadB64)
	if err != nil {
		t.Fatalf("registration is stateless and must complete on either process: %v", err)
	}

	// Login START on A.
	loginReq := h.line(t, "login-start "+password)[0]
	loginID, credRespB64, stateB64, err := a.LoginStartSealed(ctx, loginReq, &passwordFileB64, credID)
	if err != nil {
		t.Fatal(err)
	}
	if stateB64 == "" {
		t.Fatal("LoginStartSealed returned no sealed state — the sidecar is too old, or state_b64 is not being carried")
	}
	loginFin := h.line(t, "login-finish "+password+" "+credRespB64)
	finalizationB64, clientSessionKeyB64 := loginFin[0], loginFin[1]

	// Login FINISH on B, which never saw the start.
	serverSessionKeyB64, err := b.LoginFinishSealed(ctx, loginID, finalizationB64, stateB64)
	if err != nil {
		t.Fatalf("sealed state must let a second process finish the login: %v", err)
	}
	if serverSessionKeyB64 != clientSessionKeyB64 {
		t.Fatalf("session key mismatch across processes:\n server=%s\n client=%s", serverSessionKeyB64, clientSessionKeyB64)
	}

	// Negative control: WITHOUT the sealed state, B cannot finish A's login.
	// If this ever stops failing, the test above proves nothing.
	_, err = b.LoginFinishSealed(ctx, loginID, finalizationB64, "")
	if err == nil {
		t.Fatal("the legacy path must NOT succeed on a process that never served login/start")
	}
	var se *SidecarError
	if !errors.As(err, &se) || se.Code != "unknown_login" {
		t.Fatalf("expected unknown_login from the legacy path, got %v", err)
	}
}
