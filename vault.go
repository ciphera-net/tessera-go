package tessera

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf" // stdlib HKDF (RFC 5869), available since Go 1.24; the module's go.mod floor is 1.25.
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	vaultVersion     = 0x01
	vaultKEKInfoBase = "tessera/vault/v1/record/" // the record context is appended to form the HKDF info
	dekLen           = 32                         // AES-256
	gcmNonceLen      = 12
	gcmTagLen        = 16
	// wrappedDEKLen is the AES-256-GCM wrap of the 32-byte DEK: ciphertext (= DEK len) + tag.
	wrappedDEKLen = dekLen + gcmTagLen // 48
	// vaultMinEnvelopeLen is the smallest valid envelope (empty plaintext): the full header plus a
	// bare content tag. Named so the offset math in Open is auditable against the layout in one place.
	vaultMinEnvelopeLen = 1 + gcmNonceLen + wrappedDEKLen + gcmNonceLen + gcmTagLen // 89
)

var (
	// ErrUnsupportedVersion is returned by Open for an envelope whose version byte is not
	// recognized (forward compatibility — the version is not secret).
	ErrUnsupportedVersion = errors.New("tessera: unsupported vault envelope version")
	// ErrMalformedEnvelope is returned for a too-short envelope, a wrong key/context, or any
	// failed authentication tag — deliberately not distinguished, to avoid a decryption oracle.
	ErrMalformedEnvelope = errors.New("tessera: malformed or unauthentic vault envelope")
	// ErrEmptyVaultKey is returned when the supplied vault key is empty.
	ErrEmptyVaultKey = errors.New("tessera: empty vault key")
	// ErrEmptyContext is returned when the record context is empty — callers MUST name the record
	// type (e.g. "address", "totp") so each type gets an independent key.
	ErrEmptyContext = errors.New("tessera: empty record context")
)

// deriveKEK derives a per-context 32-byte AES-256 key-encryption key from the vault key. The
// record context is folded into the HKDF info string, so each record type gets a cryptographically
// INDEPENDENT wrapping key (key separation): a blob sealed under one context can never be opened
// under another, and a weakness scoped to one context cannot reach the others.
func deriveKEK(vaultKey []byte, context string) ([]byte, error) {
	if len(vaultKey) == 0 {
		return nil, ErrEmptyVaultKey
	}
	if context == "" {
		return nil, ErrEmptyContext
	}
	// nil salt is intentional: RFC 5869 §2.2 permits it when the IKM is uniformly random, and
	// export_key is a 64-byte ristretto255-SHA512 OPRF output (512 bits of entropy). Domain
	// separation comes from the info string (base label + caller context), not a salt.
	return hkdf.Key(sha256.New, vaultKey, nil, vaultKEKInfoBase+context, dekLen)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds the version byte AND the record context to both GCM operations, so a downgraded
// version or a substituted record type/identity fails authentication.
func aad(context string) []byte {
	out := make([]byte, 0, 1+len(context))
	out = append(out, vaultVersion)
	out = append(out, context...)
	return out
}

// Seal encrypts plaintext under a fresh random data-encryption key (DEK), wraps the DEK under a
// per-context KEK derived from vaultKey, and returns the versioned envelope. context names the
// record type (e.g. "address", "totp") and is REQUIRED — it is bound into both the KEK derivation
// and the AAD, and is NOT stored in the envelope (the caller must supply the same context to Open).
// It may also encode a record identity (e.g. "address:user-123"). vaultKey is key-agnostic (any
// non-empty key material): browser-held vault keys, recovery keys, or legitimately server-held keys.
func Seal(vaultKey []byte, context string, plaintext []byte) ([]byte, error) {
	kek, err := deriveKEK(vaultKey, context)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)

	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer wipe(dek)

	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	a := aad(context)

	nonceW := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonceW); err != nil {
		return nil, err
	}
	wrappedDEK := kekGCM.Seal(nil, nonceW, dek, a)

	nonceC := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonceC); err != nil {
		return nil, err
	}
	ct := dekGCM.Seal(nil, nonceC, plaintext, a)

	out := make([]byte, 0, 1+gcmNonceLen+len(wrappedDEK)+gcmNonceLen+len(ct))
	out = append(out, vaultVersion)
	out = append(out, nonceW...)
	out = append(out, wrappedDEK...)
	out = append(out, nonceC...)
	out = append(out, ct...)
	return out, nil
}

// Open reverses Seal. The caller MUST supply the same context used to Seal. It returns
// ErrUnsupportedVersion for an unknown version, ErrEmptyVaultKey for an empty key, ErrEmptyContext
// for an empty context, and ErrMalformedEnvelope for a too-short envelope, a wrong key/context, or
// any failed tag. The empty-key/empty-context guards signal caller error and are independent of
// envelope content, so they are not a decryption oracle.
func Open(vaultKey []byte, context string, envelope []byte) ([]byte, error) {
	if len(envelope) < 1 {
		return nil, ErrMalformedEnvelope
	}
	if envelope[0] != vaultVersion {
		return nil, ErrUnsupportedVersion
	}
	if len(envelope) < vaultMinEnvelopeLen {
		return nil, ErrMalformedEnvelope
	}
	off := 1
	nonceW := envelope[off : off+gcmNonceLen]
	off += gcmNonceLen
	wrappedDEK := envelope[off : off+wrappedDEKLen]
	off += wrappedDEKLen
	nonceC := envelope[off : off+gcmNonceLen]
	off += gcmNonceLen
	ct := envelope[off:]

	a := aad(context)
	kek, err := deriveKEK(vaultKey, context)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)

	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, nonceW, wrappedDEK, a)
	if err != nil {
		return nil, ErrMalformedEnvelope // wrong key or tampered wrap
	}
	defer wipe(dek)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	pt, err := dekGCM.Open(nil, nonceC, ct, a)
	if err != nil {
		return nil, ErrMalformedEnvelope
	}
	return pt, nil
}

// wipe best-effort zeroes sensitive bytes once finished (defense in depth). It is NOT a complete
// erasure: Go's GC may already have copied the slice, and aes.NewCipher expands the key into a
// round-key schedule held inside the cipher.Block that this wipe does not reach — only the raw key
// slice is zeroed, not that schedule. It still shortens the window for the raw key material.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
