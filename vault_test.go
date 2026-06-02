package tessera

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

const testCtx = "record-test"

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 64) // OPAQUE export_key is 64 bytes; Seal is key-agnostic though
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVaultRoundTrip(t *testing.T) {
	key := randKey(t)
	for _, pt := range [][]byte{{}, []byte("x"), []byte(`{"a":1}`), bytes.Repeat([]byte("z"), 5000)} {
		env, err := Seal(key, testCtx, pt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(key, testCtx, env)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip mismatch for %d bytes", len(pt))
		}
	}
}

func TestVaultStructure(t *testing.T) {
	key := randKey(t)
	pt := []byte("hello")
	env, err := Seal(key, testCtx, pt)
	if err != nil {
		t.Fatal(err)
	}
	if env[0] != 0x01 {
		t.Fatalf("version byte = %#x, want 0x01", env[0])
	}
	// context is caller-supplied and NOT stored, so envelope size is independent of it.
	want := 1 + 12 + (32 + 16) + 12 + (len(pt) + 16)
	if len(env) != want {
		t.Fatalf("envelope len = %d, want %d", len(env), want)
	}
}

func TestVaultWrongKeyFails(t *testing.T) {
	env, err := Seal(randKey(t), testCtx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(randKey(t), testCtx, env); err == nil {
		t.Fatal("Open with a wrong key must fail")
	}
}

func TestVaultContextBindingPreventsSubstitution(t *testing.T) {
	key := randKey(t)
	env, err := Seal(key, "address", []byte("1 Privacy Way"))
	if err != nil {
		t.Fatal(err)
	}
	// Same key, different record context: a DB-write adversary swapping blobs across record
	// types must be rejected (per-context KEK + context-in-AAD).
	if _, err := Open(key, "totp", env); err == nil {
		t.Fatal("opening under a different context must fail")
	}
	// Sanity: the correct context still opens.
	if _, err := Open(key, "address", env); err != nil {
		t.Fatalf("correct context must open: %v", err)
	}
}

func TestVaultEmptyContextFails(t *testing.T) {
	if _, err := Seal(randKey(t), "", []byte("x")); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("empty context must be rejected on Seal, got %v", err)
	}
	env, _ := Seal(randKey(t), testCtx, []byte("x"))
	if _, err := Open(randKey(t), "", env); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("empty context must be rejected on Open, got %v", err)
	}
}

func TestVaultEmptyKeyFails(t *testing.T) {
	if _, err := Seal(nil, testCtx, []byte("x")); !errors.Is(err, ErrEmptyVaultKey) {
		t.Fatalf("empty vault key must be rejected on Seal, got %v", err)
	}
	env, _ := Seal(randKey(t), testCtx, []byte("x"))
	if _, err := Open([]byte{}, testCtx, env); !errors.Is(err, ErrEmptyVaultKey) {
		t.Fatalf("empty vault key must be rejected on Open, got %v", err)
	}
}

func TestVaultTamperFails(t *testing.T) {
	key := randKey(t)
	env, err := Seal(key, testCtx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in each region; every variant must fail to open.
	for _, i := range []int{1, 1 + 6, 1 + 12 + 6, 1 + 12 + 48 + 6, len(env) - 1} {
		bad := bytes.Clone(env)
		bad[i] ^= 0xff
		if _, err := Open(key, testCtx, bad); err == nil {
			t.Fatalf("tampering at offset %d must fail", i)
		}
	}
}

func TestVaultSplicedEnvelopeFails(t *testing.T) {
	key := randKey(t)
	const ctx = "address"
	e1, err := Seal(key, ctx, []byte("record one"))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Seal(key, ctx, []byte("record two"))
	if err != nil {
		t.Fatal(err)
	}
	// Cut-and-paste under the SAME key+context: graft e1's wrapped DEK (version|nonceW|wrappedDEK)
	// onto e2's content. The wrap authenticates (intact from e1) and yields DEK1, but e2's
	// ciphertext was sealed under DEK2 — so the content tag must reject the splice. The two layers
	// are bound THROUGH the DEK even though neither layer's AAD names the other layer's bytes.
	spliced := bytes.Clone(e2)
	copy(spliced[1:1+gcmNonceLen+wrappedDEKLen], e1[1:1+gcmNonceLen+wrappedDEKLen])
	if _, err := Open(key, ctx, spliced); err == nil {
		t.Fatal("spliced envelope (wrapped DEK from e1, ciphertext from e2) must not open")
	}
}

func TestVaultUnknownVersionFails(t *testing.T) {
	key := randKey(t)
	env, _ := Seal(key, testCtx, []byte("secret"))
	bad := bytes.Clone(env)
	bad[0] = 0x02
	_, err := Open(key, testCtx, bad)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestVaultMalformedFails(t *testing.T) {
	if _, err := Open(randKey(t), testCtx, []byte{0x01, 0x00}); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("expected ErrMalformedEnvelope, got %v", err)
	}
}

func TestVaultIsNonDeterministic(t *testing.T) {
	key := randKey(t)
	a, _ := Seal(key, testCtx, []byte("same"))
	b, _ := Seal(key, testCtx, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same input must differ (random DEK + nonces)")
	}
}
