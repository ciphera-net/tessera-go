// Package tessera is the server-side Go SDK for Tessera, Ciphera's zero-knowledge identity
// system. It provides three primitives:
//
//   - A pooled Unix-domain-socket client for the OPAQUE sidecar (RegisterStart/Finish,
//     LoginStart/Finish). The SDK RELAYS browser-supplied OPAQUE messages to the sidecar; it
//     never computes OPAQUE client math (the single Rust core guarantees cross-environment
//     interop by construction).
//   - A deterministic, privacy-preserving blind index (Argon2id) used as the account lookup
//     key and OPAQUE credential_identifier, so the server never sees a plaintext email.
//   - A generic client-encrypted vault (Seal/Open) for arbitrary user-private records, using a
//     versioned DEK/KEK AES-256-GCM envelope.
//
// Persistence and session issuance (JWT) are the caller's responsibility (e.g. id-backend),
// not this SDK's.
package tessera
