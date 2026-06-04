//go:build conformance

// Conformance verifier: the tessera-go SDK checks the canonical Phase 4 vectors (in the sibling
// ciphera-tessera/conformance/vectors). White-box (package tessera) so it can verify intermediate
// KATs against unexported internals (e.g. deriveKEK, added in Task 11). Build-tagged `conformance`
// so the default `go test ./...` does not require the core sibling checkout.
package tessera

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// vectorsDir resolves the canonical conformance vectors. Prefer TESSERA_VECTORS_DIR (set in CI); fall
// back to the sibling derivation. The core repo dir is named "ciphera-tessera" locally AND in CI.
func vectorsDir(t *testing.T) string {
	dir := os.Getenv("TESSERA_VECTORS_DIR")
	if dir == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		dir = filepath.Join(filepath.Dir(thisFile), "..", "ciphera-tessera", "conformance", "vectors")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("conformance vectors not found at %s (set TESSERA_VECTORS_DIR or checkout ciphera-tessera as a sibling): %v", dir, err)
	}
	return dir
}

// loadVectors reads the versioned vector file and returns its `.vectors` array decoded as []T.
func loadVectors[T any](t *testing.T, name string) []T {
	b, err := os.ReadFile(filepath.Join(vectorsDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var f struct {
		Vectors []T `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f.Vectors
}

func TestConformanceBlindIndex(t *testing.T) {
	type v struct {
		Email               string `json:"email"`
		BlindIndexBase64Url string `json:"blindIndexBase64Url"`
	}
	vecs := loadVectors[v](t, "blind-index.json")
	if len(vecs) == 0 {
		t.Fatal("no blind-index vectors loaded")
	}
	for _, vec := range vecs {
		if got := BlindIndexString(vec.Email); got != vec.BlindIndexBase64Url {
			t.Errorf("blind index for %q: got %s want %s", vec.Email, got, vec.BlindIndexBase64Url)
		}
	}
}

func TestConformanceVaultOpen(t *testing.T) {
	type v struct {
		VaultKeyHex  string `json:"vaultKeyHex"`
		Context      string `json:"context"`
		PlaintextHex string `json:"plaintextHex"`
		EnvelopeHex  string `json:"envelopeHex"`
	}
	vecs := loadVectors[v](t, "vault.json")
	if len(vecs) == 0 {
		t.Fatal("no vault vectors loaded")
	}
	for _, vec := range vecs {
		key, err := hex.DecodeString(vec.VaultKeyHex)
		if err != nil {
			t.Fatalf("bad vaultKeyHex for %q: %v", vec.Context, err)
		}
		env, err := hex.DecodeString(vec.EnvelopeHex)
		if err != nil {
			t.Fatalf("bad envelopeHex for %q: %v", vec.Context, err)
		}
		pt, err := Open(key, vec.Context, env)
		if err != nil {
			t.Errorf("open %q: %v", vec.Context, err)
			continue
		}
		if hex.EncodeToString(pt) != vec.PlaintextHex {
			t.Errorf("open %q: plaintext mismatch: got %s want %s", vec.Context, hex.EncodeToString(pt), vec.PlaintextHex)
		}
	}
}
