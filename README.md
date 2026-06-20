# tessera-go

Server-side Go SDK for [Tessera](https://github.com/ciphera-net/tessera), Ciphera's
zero-knowledge identity system: OPAQUE password login (the password never reaches the server)
and a generic client-encrypted vault.

> **Self-reviewed, not independently audited.** Apache-2.0. See the
> [security model](https://github.com/ciphera-net/tessera/blob/main/docs/THREAT-MODEL.md)
> and [self-audit](https://github.com/ciphera-net/tessera/blob/main/docs/SELF-AUDIT.md) before relying on it.

## Install
    go get github.com/ciphera-net/tessera-go

Requires **Go 1.25+** (the `golang.org/x/crypto` dependency sets the floor; the vault uses the
`crypto/hkdf` standard-library package).

## What this SDK is (and is not)
- **Is:** a pooled client for the OPAQUE sidecar, an Argon2id blind index, and a versioned
  AES-256-GCM vault (`Seal`/`Open`).
- **Is not:** an OPAQUE client (the browser is, via the shared Rust core), a database, or a JWT
  issuer. Persistence and sessions live in your application (your identity service).

## The actors
| Step | Browser (TS SDK) | Your server (this SDK) | Sidecar (Rust) | Your DB |
|---|---|---|---|---|
| blind index | computes `BlindIndex(email)` | receives it (never the email) | — | stores it |
| register | OPAQUE client msgs | relays via `RegisterStart/Finish` | OPAQUE math | stores password file |
| login | OPAQUE client msgs | relays via `LoginStart/Finish` | OPAQUE math | reads password file |
| vault | seals/opens with `export_key` | (optional) `Seal`/`Open` for server-held keys | — | stores ciphertext blob |

**Zero-knowledge rule:** the email blind index and the vault `export_key` are computed
**client-side**. The server stores only the blind index, the OPAQUE password file, and opaque
vault ciphertext. Never call `BlindIndex` on a plaintext email in the request path — it exists
for parity vectors and trusted offline tooling only.

## Example (login, server side)
    // credID arrives from the browser (the blind index); passwordFile is loaded from your DB.
    loginID, credResp, err := client.LoginStart(ctx, credReqFromBrowser, &passwordFileB64, credID)
    // ... send credResp to the browser, receive the finalization ...
    sessionKey, err := client.LoginFinish(ctx, loginID, finalizationFromBrowser)
    // sessionKey now matches the browser's; issue your JWT.

## CI
The integration test runs the real sidecar + a Rust OPAQUE client-helper; it needs read access
to the private `ciphera-net/tessera` repo via the `CI_REPO_TOKEN` secret.
