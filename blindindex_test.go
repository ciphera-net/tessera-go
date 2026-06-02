package tessera

import "testing"

func TestBlindIndexIsDeterministic(t *testing.T) {
	a := BlindIndexString("user@example.com")
	b := BlindIndexString("user@example.com")
	if a != b {
		t.Fatal("blind index must be deterministic for the same email")
	}
	if len(BlindIndex("user@example.com")) != 32 {
		t.Fatal("blind index must be 32 bytes")
	}
}

func TestBlindIndexNormalizesEmail(t *testing.T) {
	if BlindIndexString("  User@Example.COM ") != BlindIndexString("user@example.com") {
		t.Fatal("blind index must normalize case and surrounding whitespace")
	}
}

func TestBlindIndexDistinguishesEmails(t *testing.T) {
	if BlindIndexString("a@example.com") == BlindIndexString("b@example.com") {
		t.Fatal("distinct emails must produce distinct indices")
	}
}
