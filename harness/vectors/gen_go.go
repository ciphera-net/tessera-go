//go:build conformance

// Command gen_go regenerates the Phase 4 conformance vectors using the authoritative tessera-go SDK.
// Build-tagged `conformance` (a dev-only tool): excluded from the default build. Run from the tessera-go
// module root:
//
//	go run -tags conformance ./harness/vectors            # print to stdout
//	go run -tags conformance ./harness/vectors --write    # write ../../../ciphera-tessera/conformance/vectors/*.json
//
// The blind-index values are byte-exact (deterministic Argon2id). The vault envelopeHex values are
// randomly nonce'd each run — only the Open direction is required for parity; the checked-in envelopes
// serve as stable inputs for the cross-language verifiers.
package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	tessera "github.com/ciphera-net/tessera-go"
)

const (
	kitVersion  = "1.0.0"
	suiteID     = "0x01"
	generatedBy = "tessera-go harness/vectors/gen_go.go"

	// vaultKEKInfo MUST byte-match tessera's unexported vaultKEKInfoBase (vault.go). The KEK KAT is
	// derived here via stdlib HKDF — independent of the SDK's deriveKEK — so the conformance verifier
	// (which calls the SDK's deriveKEK) is checked against an independent reference and catches an
	// SDK info-string / param drift.
	vaultKEKInfo = "tessera/vault/v1/record/"
)

// fileHeader is the versioned wrapper emitted at the top of every vector file (fields are promoted
// into the JSON object via embedding).
type fileHeader struct {
	KitVersion  string `json:"kitVersion"`
	Suite       string `json:"suite"`
	GeneratedBy string `json:"generatedBy"`
}

func hdr() fileHeader {
	return fileHeader{KitVersion: kitVersion, Suite: suiteID, GeneratedBy: generatedBy}
}

type blindIndexEntry struct {
	Email               string `json:"email"`
	NormalizedEmail     string `json:"normalizedEmail"` // KAT: byte-exact normalization (trim → Unicode lower)
	BlindIndexBase64Url string `json:"blindIndexBase64Url"`
}

type vaultEntry struct {
	VaultKeyHex  string `json:"vaultKeyHex"`
	Context      string `json:"context"`
	KekHex       string `json:"kekHex"` // KAT: HKDF-SHA256(vaultKey, 32-zero salt, info, 32), byte-exact
	PlaintextHex string `json:"plaintextHex"`
	EnvelopeHex  string `json:"envelopeHex"`
}

type blindIndexFile struct {
	fileHeader
	Vectors []blindIndexEntry `json:"vectors"`
}

type vaultFile struct {
	fileHeader
	Vectors []vaultEntry `json:"vectors"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	write := flag.Bool("write", false, "write JSON files to the core conformance/vectors dir instead of stdout")
	flag.Parse()

	// ── Blind-index vectors (normalization is part of the parity contract: trim → lower) ──
	biEmails := []string{
		"user@example.com",
		"Alice@Example.ORG",
		" bob+tag@gmail.com ",
		"USER@EXAMPLE.COM",
		"  Alice@Example.ORG  ",
		"\tuser@example.com\n",       // tab/newline whitespace → trims to the canonical form
		"  spaced.out@example.com  ", // double-sided ASCII spaces
		"a.very.long.local.part.exceeding.normal.length@subdomain.example.museum", // long local-part + multi-label domain
		"multi+tag+two@gmail.com", // multiple plus segments (NO plus-stripping in v1)
		"José@example.com",        // Unicode: J→j; é already lowercase, stays U+00E9; NO NFC/IDNA in v1
		"ZÜRICH@example.com",      // Unicode case fold: Z/R/I/C/H + Ü→ü (Go ToLower & Rust to_lowercase agree on Latin-1)
	}
	biEntries := make([]blindIndexEntry, len(biEmails))
	for i, email := range biEmails {
		biEntries[i] = blindIndexEntry{
			Email:               email,
			NormalizedEmail:     tessera.NormalizeEmail(email),
			BlindIndexBase64Url: tessera.BlindIndexString(email),
		}
	}

	// ── Vault vectors (fixed 32×0x01 key; envelopes freshly sealed each run; Open-parity only) ──
	vaultKey := make([]byte, 32)
	for i := range vaultKey {
		vaultKey[i] = 0x01
	}
	vaultKeyHex := hex.EncodeToString(vaultKey)
	type seedRow struct{ context, plaintext string }
	seeds := []seedRow{
		{"address", "hello vault"},
		{"totp", "JBSWY3DPEHPK3PXP"},
		{"address", `{"street":"123 Main St","city":"Zurich"}`},
		{"address", ""},                                     // empty plaintext → the 89-byte minimum envelope
		{"notes", string(make([]byte, 4096))},               // large plaintext (4 KiB of 0x00)
		{"display_name", "Zürich café — naïve ✓ 日本語"},       // multi-byte UTF-8 plaintext
		{"address:user-123", "scoped to a record identity"}, // context-with-identity form
	}
	vaultEntries := make([]vaultEntry, len(seeds))
	for i, s := range seeds {
		pt := []byte(s.plaintext)
		env := must(tessera.Seal(vaultKey, s.context, pt))
		// Belt-and-suspenders: Open must recover the original plaintext before we emit the vector.
		if string(must(tessera.Open(vaultKey, s.context, env))) != s.plaintext {
			fmt.Fprintf(os.Stderr, "FATAL: round-trip mismatch for context=%q\n", s.context)
			os.Exit(1)
		}
		// KEK KAT: derive independently of the SDK via stdlib HKDF (nil salt → RFC 5869 32-zero salt).
		kek := must(hkdf.Key(sha256.New, vaultKey, nil, vaultKEKInfo+s.context, 32))
		vaultEntries[i] = vaultEntry{
			VaultKeyHex:  vaultKeyHex,
			Context:      s.context,
			KekHex:       hex.EncodeToString(kek),
			PlaintextHex: hex.EncodeToString(pt),
			EnvelopeHex:  hex.EncodeToString(env),
		}
	}

	biJSON := must(json.MarshalIndent(blindIndexFile{hdr(), biEntries}, "", "  "))
	vaultJSON := must(json.MarshalIndent(vaultFile{hdr(), vaultEntries}, "", "  "))

	if !*write {
		fmt.Println("=== blind-index.json ===")
		fmt.Println(string(biJSON))
		fmt.Println("\n=== vault.json ===")
		fmt.Println(string(vaultJSON))
		return
	}

	// Resolve the canonical core conformance dir. Prefer TESSERA_VECTORS_DIR (set in CI); fall back to
	// the sibling derivation. The core repo dir is named "ciphera-tessera" (NOT "tessera").
	vectorsDir := os.Getenv("TESSERA_VECTORS_DIR")
	if vectorsDir == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		if !filepath.IsAbs(thisFile) { // -trimpath would strip the abs path → wrong relative arithmetic
			fmt.Fprintln(os.Stderr, "runtime.Caller is non-absolute (built with -trimpath?); set TESSERA_VECTORS_DIR")
			os.Exit(1)
		}
		// harness/vectors/gen_go.go → module root is ../.. ; core sibling is ../../../ciphera-tessera
		vectorsDir = filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "ciphera-tessera", "conformance", "vectors")
	}
	writeFile := func(name string, data []byte) {
		path := filepath.Join(vectorsDir, name)
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	}
	writeFile("blind-index.json", biJSON)
	writeFile("vault.json", vaultJSON)
}
