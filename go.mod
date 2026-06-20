module github.com/ciphera-net/tessera-go

go 1.25.0

// Build with >= go1.25.10: patches GO-2026-4971 (net.Dial/LookupPort panic) reached via this SDK.
toolchain go1.25.10

require golang.org/x/crypto v0.52.0

require golang.org/x/sys v0.45.0 // indirect
