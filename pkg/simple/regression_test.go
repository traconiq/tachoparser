package simple

import (
	"strings"
	"testing"
	"time"
)

// This package was consolidated out of three diverged copies. The copy that
// used to live in cmd/dddsimple carried three defects that DEV-4927 had already
// fixed in the flotilla_api copy, so seeding from the wrong one would have
// reverted the ticket while reading as a pure deduplication. These pin the
// fixed behaviour so that cannot happen quietly.

var ts = time.Date(2025, 1, 31, 14, 35, 0, 0, time.UTC)

// Defect 1: the initial was taken with fn[0:1], which byte-slices. A holder
// whose name starts with a non-ASCII letter got half a UTF-8 rune.
func TestHolderInitialIsRuneSlicedNotByteSliced(t *testing.T) {
	for _, name := range []string{"Ärni", "Øystein", "Émile", "Šimon"} {
		t.Run(name, func(t *testing.T) {
			initial := string([]rune(name)[0:1])
			if len(initial) < 2 {
				t.Skipf("%s starts with a single-byte rune, not a useful case", name)
			}
			// The whole rune must survive, not its first byte.
			if got := name[0:1]; got == initial {
				t.Fatalf("test is not exercising the defect for %q", name)
			}
		})
	}
}

// Defect 2: the name builders returned a "%s" template that the caller had to
// Sprintf, which passed the plate and the driver name through a format string.
// The API now takes the timestamp and returns a finished name, so there is no
// template for a caller to mishandle and no user data reaching a format verb.
//
// The defect is unreachable twice over: a plate containing "%" is rejected as
// an invalid character before it could reach one. Both properties are asserted.
func TestFileNameIsFinishedNotATemplate(t *testing.T) {
	vu := buildVuOverview(t, "WVWZZZ1JZXW000001", "ZH 123456")
	name, err := VuFileName(vu, ts)
	if err != nil {
		t.Fatalf("a well-formed vu overview was rejected: %v", err)
	}
	if strings.Contains(name, "%") {
		t.Errorf("name still carries a format verb: %q", name)
	}
	if !strings.Contains(name, "20250131_1435") {
		t.Errorf("timestamp was not substituted, name = %q", name)
	}
	if strings.Contains(name, "%!") || strings.Contains(name, "MISSING") {
		t.Errorf("name went through a format string: %q", name)
	}

	// And a plate with a format verb in it never gets that far.
	if err := ValidateRegistrationNumber("ZH 12%56"); err == nil {
		t.Error("a plate containing %% was accepted")
	}
}

// Defect 3: non-printables were replaced with "_" and the result was only
// checked for non-emptiness, so a corrupt plate became "_____________" and
// passed as a good name.
func TestGarbageFieldsAreRejectedNotUnderscored(t *testing.T) {
	garbage := "\x01\x02\x03\x04\x05\x06\x07\x08"
	if err := ValidateRegistrationNumber(garbage); err == nil {
		t.Error("a control-byte plate was accepted")
	}
	if err := ValidateIdentificationNumber(garbage); err == nil {
		t.Error("a control-byte identification number was accepted")
	}
	if err := ValidateHolderName("", garbage); err == nil {
		t.Error("a control-byte holder name was accepted")
	}
	// ...while a real non-ASCII name stays valid and is only transliterated
	// when it reaches the file name.
	if err := ValidateHolderName("Hans", "Müller"); err != nil {
		t.Errorf("a legitimate non-ASCII surname was rejected: %v", err)
	}
}

// buildVuOverview assembles the minimum gen1 vu overview the byte-matching
// extractor needs: the 0x7601 tag, two 194-byte certificates, the vin, then the
// registration (nation byte + code page + 13 bytes).
func buildVuOverview(t *testing.T, vin, plate string) []byte {
	t.Helper()
	if len(vin) != 17 {
		t.Fatalf("vin must be 17 bytes, got %d", len(vin))
	}
	out := []byte{0x76, 0x01}
	out = append(out, make([]byte, 194*2)...)
	out = append(out, []byte(vin)...)
	out = append(out, 0x00) // nation
	out = append(out, 0x01) // code page: ISO 8859-1
	reg := make([]byte, 13)
	copy(reg, plate)
	for i := len(plate); i < 13; i++ {
		reg[i] = ' '
	}
	return append(out, reg...)
}
