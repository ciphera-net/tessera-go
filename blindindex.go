package tessera

import (
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Blind-index Argon2id parameters. These are a CROSS-LANGUAGE PARITY CONTRACT: the TS/WASM SDK
// and any other implementation MUST use identical values, and they MUST NOT change without a
// versioned migration (bump the salt label below and re-derive affected accounts).
//
// p=1 is NOT about determinism (Argon2id is deterministic for any fixed p) — it is a parity
// requirement: common browser/WASM Argon2 builds run single-threaded and may not support p>1 (or
// silently clamp it), which would yield a DIFFERENT output than a multi-lane native build. Pinning
// p=1 guarantees the browser and the server compute byte-identical indices. Do not "optimize" it.
const (
	blindIndexTime    uint32 = 3         // iterations (t)
	blindIndexMemory  uint32 = 64 * 1024 // memory in KiB (64 MiB)
	blindIndexThreads uint8  = 1         // lanes (p) — see the parity note above
	blindIndexLen     uint32 = 32        // output bytes
)

// blindIndexSalt is a fixed, NON-SECRET, versioned domain-separation salt (it ships in client
// code). It does not add per-user entropy — the index must be deterministic to function as a
// lookup key — it binds the derivation to "Tessera blind index, v1". Bump "v1" to change params.
//
// It is a const string (converted to bytes at the call site) rather than a package-level
// `var []byte`: the latter is mutable global state that any code in the package could corrupt,
// silently changing every derived index. The one tiny conversion allocation is negligible beside
// the 64 MiB of Argon2id work.
const blindIndexSalt = "tessera/blind-index/v1"

// NormalizeEmail canonicalizes an email for stable, implementation-independent lookup. The order
// is PART OF THE PARITY CONTRACT: TrimSpace (strip surrounding whitespace) THEN ToLower — the
// TS/WASM SDK must apply the same sequence. (No Unicode NFC / IDNA punycode folding in v1; a
// documented known limitation and part of the contract.)
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// BlindIndex derives the deterministic, privacy-preserving account lookup key from an email.
//
// SECURITY: in PRODUCTION this MUST be computed CLIENT-SIDE (in the browser). The server must
// never receive a plaintext email, so it must never call this on request-path input — doing so
// would defeat the zero-knowledge property by bringing the email into server memory/logs.
//
// It is ALSO a denial-of-service hazard on the server path: each call allocates 64 MiB held for
// the full Argon2id computation, so even a single network-reachable handler that calls this can be
// memory-exhausted by a few tens of concurrent requests. This function must never be reachable
// from a network-exposed handler. It exists in Go only for (a) cross-language parity vectors and
// (b) trusted offline tooling such as one-time migration jobs. Memory-hard Argon2id is chosen
// because the index faces an offline, cross-user-amortized enumeration attack over a low-entropy
// (email) space; its security rests on that COST, not on the (public, shipped) salt being secret.
func BlindIndex(email string) []byte {
	norm := NormalizeEmail(email)
	return argon2.IDKey([]byte(norm), []byte(blindIndexSalt), blindIndexTime, blindIndexMemory, blindIndexThreads, blindIndexLen)
}

// BlindIndexString returns the base64url (unpadded) encoding, suitable for use as the OPAQUE
// credential_identifier and the database lookup key.
func BlindIndexString(email string) string {
	return base64.RawURLEncoding.EncodeToString(BlindIndex(email))
}
