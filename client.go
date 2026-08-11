package tessera

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// SidecarError is returned when the sidecar replies with an Error frame. Code is a stable error
// class — "unknown_login", "invalid_credentials", "bad_request", or "internal" — suitable for
// control flow (HTTP status mapping); Message is human-readable, for diagnostics only.
type SidecarError struct {
	Code    string
	Message string
}

func (e *SidecarError) Error() string { return "tessera: sidecar error [" + e.Code + "]: " + e.Message }

// Client is a pooled client for the OPAQUE sidecar over a Unix domain socket. It is safe for
// concurrent use. The pool REUSES up to poolSize idle connections; under burst load it may open
// additional connections, bounded only by the sidecar's TESSERA_MAX_CONNECTIONS cap (default
// 256). Size the pool to steady-state concurrency and keep peak concurrency below that cap.
type Client struct {
	socketPath  string
	pool        chan net.Conn
	dialTimeout time.Duration

	mu     sync.Mutex // guards closed and serializes put with Close
	closed bool
}

type config struct {
	poolSize    int
	dialTimeout time.Duration
}

// Option configures a Client.
type Option func(*config)

// WithPoolSize sets the max number of pooled connections (default 32).
func WithPoolSize(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.poolSize = n
		}
	}
}

// WithDialTimeout sets the per-dial timeout (default 5s).
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) { c.dialTimeout = d }
}

// NewClient creates a sidecar client for the given UDS path.
func NewClient(socketPath string, opts ...Option) *Client {
	cfg := config{poolSize: 32, dialTimeout: 5 * time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	return &Client{
		socketPath:  socketPath,
		pool:        make(chan net.Conn, cfg.poolSize),
		dialTimeout: cfg.dialTimeout,
	}
}

// Close shuts the pool, closing all idle connections. It is safe to call concurrently with
// in-flight requests: once Close marks the client closed (under mu), any connection a still-running
// roundTrip later hands to put is closed rather than parked, so no connection is leaked. The pool
// channel is deliberately never closed — that would let a concurrent put panic on send.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	for {
		select {
		case conn := <-c.pool:
			_ = conn.Close()
		default:
			return nil
		}
	}
}

func (c *Client) get(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-c.pool:
		return conn, nil
	default:
	}
	d := net.Dialer{Timeout: c.dialTimeout}
	return d.DialContext(ctx, "unix", c.socketPath)
}

func (c *Client) put(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = conn.Close() // client shut down while this exchange was in flight
		return
	}
	select {
	case c.pool <- conn:
	default:
		_ = conn.Close() // pool full
	}
}

// roundTrip sends one request frame and reads one response frame, honoring ctx for the whole
// exchange — both its deadline AND cancellation (a cancel-only ctx unblocks a stalled write/read
// via an injected immediate deadline). A connection that errors is discarded (not returned to the
// pool).
func (c *Client) roundTrip(ctx context.Context, reqJSON []byte) ([]byte, error) {
	conn, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Time{}) // clear any stale deadline from a pooled conn
	}
	// Honor ctx cancellation (not only its deadline): on ctx.Done, force an immediate I/O deadline
	// so a blocked writeFrame/readFrame returns at once. stop() is called before the conn is reused
	// or closed, so a late firing can never poison a re-pooled connection.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	if err := writeFrame(conn, reqJSON); err != nil {
		stop()
		_ = conn.Close()
		return nil, err
	}
	frame, err := readFrame(conn)
	if err != nil {
		stop()
		_ = conn.Close()
		return nil, err
	}
	stop()
	_ = conn.SetDeadline(time.Time{})
	c.put(conn)
	return frame, nil
}

func (c *Client) exchange(ctx context.Context, v any) (*response, error) {
	reqJSON, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("tessera: encode request: %w", err)
	}
	frame, err := c.roundTrip(ctx, reqJSON)
	if err != nil {
		return nil, err
	}
	var r response
	if err := json.Unmarshal(frame, &r); err != nil {
		return nil, fmt.Errorf("tessera: decode response: %w", err)
	}
	if r.Result == "error" {
		return nil, &SidecarError{Code: r.Code, Message: r.Message}
	}
	return &r, nil
}

// --- wire types (must match src/protocol.rs) ---

type registerStartReq struct {
	Op           string `json:"op"`
	RequestB64   string `json:"request_b64"`
	CredentialID string `json:"credential_id"`
}
type registerFinishReq struct {
	Op        string `json:"op"`
	UploadB64 string `json:"upload_b64"`
}
type loginStartReq struct {
	Op              string  `json:"op"`
	RequestB64      string  `json:"request_b64"`
	PasswordFileB64 *string `json:"password_file_b64"` // no omitempty: nil → null (unknown user)
	CredentialID    string  `json:"credential_id"`
}
type loginFinishReq struct {
	Op              string `json:"op"`
	LoginID         string `json:"login_id"`
	FinalizationB64 string `json:"finalization_b64"`
	// StateB64 is the sealed ServerLogin returned by LoginStart. omitempty so an
	// empty value is omitted entirely, which the sidecar reads as "use my
	// in-memory state" — the legacy, single-process path.
	StateB64 string `json:"state_b64,omitempty"`
}

type response struct {
	Result          string `json:"result"`
	Code            string `json:"code"`
	ResponseB64     string `json:"response_b64"`
	PasswordFileB64 string `json:"password_file_b64"`
	LoginID         string `json:"login_id"`
	StateB64        string `json:"state_b64"`
	SessionKeyB64   string `json:"session_key_b64"`
	Message         string `json:"message"`
}

// --- methods ---
// All take/return base64 strings: the OPAQUE messages are opaque blobs that originate from and
// return to the browser; the Go SDK never parses them.

// RegisterStart forwards the client's RegistrationRequest; credentialID is the blind index.
func (c *Client) RegisterStart(ctx context.Context, requestB64, credentialID string) (responseB64 string, err error) {
	r, err := c.exchange(ctx, registerStartReq{Op: "register_start", RequestB64: requestB64, CredentialID: credentialID})
	if err != nil {
		return "", err
	}
	return r.ResponseB64, nil
}

// RegisterFinish forwards the client's RegistrationUpload and returns the password file to
// persist for this account (input to every future LoginStart).
func (c *Client) RegisterFinish(ctx context.Context, uploadB64 string) (passwordFileB64 string, err error) {
	r, err := c.exchange(ctx, registerFinishReq{Op: "register_finish", UploadB64: uploadB64})
	if err != nil {
		return "", err
	}
	return r.PasswordFileB64, nil
}

// LoginStart begins authentication. passwordFileB64 is the stored record, or nil for an unknown
// account (the sidecar then returns a timing-safe fake response — DO pass nil, never fabricate a
// record, to keep account existence unobservable).
//
// Deprecated: use LoginStartSealed. This form discards the sealed state, which
// ties the matching LoginFinish to this exact sidecar process.
func (c *Client) LoginStart(ctx context.Context, requestB64 string, passwordFileB64 *string, credentialID string) (loginID, responseB64 string, err error) {
	loginID, responseB64, _, err = c.LoginStartSealed(ctx, requestB64, passwordFileB64, credentialID)
	return loginID, responseB64, err
}

// LoginStartSealed begins authentication and additionally returns the SEALED server login state.
//
// Store stateB64 wherever you store loginID and hand it back to LoginFinishSealed. It is
// ciphertext under a key derived from the sidecar's ServerSetup, so your datastore never sees the
// server's key-exchange state — and any process holding that same ServerSetup can finish the
// login. That is what allows more than one server replica: without it, LoginFinish must reach the
// very process that served LoginStart, because the state lives in that process's memory.
func (c *Client) LoginStartSealed(ctx context.Context, requestB64 string, passwordFileB64 *string, credentialID string) (loginID, responseB64, stateB64 string, err error) {
	r, err := c.exchange(ctx, loginStartReq{Op: "login_start", RequestB64: requestB64, PasswordFileB64: passwordFileB64, CredentialID: credentialID})
	if err != nil {
		return "", "", "", err
	}
	return r.LoginID, r.ResponseB64, r.StateB64, nil
}

// LoginFinish finalizes authentication and returns the server's session key (equal to the
// client's on success).
//
// Deprecated: use LoginFinishSealed. Without the sealed state this must run against the same
// sidecar process that served LoginStart, and returns SidecarError{Code: "unknown_login"}
// otherwise — which is indistinguishable, to a caller that does not check the code, from a
// wrong password.
func (c *Client) LoginFinish(ctx context.Context, loginID, finalizationB64 string) (sessionKeyB64 string, err error) {
	return c.LoginFinishSealed(ctx, loginID, finalizationB64, "")
}

// LoginFinishSealed finalizes authentication using the sealed state from LoginStartSealed.
//
// An empty stateB64 falls back to the sidecar's in-memory state (the deprecated single-process
// path). A sealed state that is expired, tampered with, or bound to a different loginID returns
// SidecarError{Code: "unknown_login"} — deliberately without distinguishing which, so nothing
// here becomes an oracle. Treat that code as "this ceremony is over, start a new one", NOT as a
// failed password: counting it as a credential failure means a correct password can accrue
// lockouts.
func (c *Client) LoginFinishSealed(ctx context.Context, loginID, finalizationB64, stateB64 string) (sessionKeyB64 string, err error) {
	r, err := c.exchange(ctx, loginFinishReq{Op: "login_finish", LoginID: loginID, FinalizationB64: finalizationB64, StateB64: stateB64})
	if err != nil {
		return "", err
	}
	return r.SessionKeyB64, nil
}
