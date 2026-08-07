package simple

import (
	"fmt"
	"strings"
	"unicode"
)

// Validation of the identification fields a DDD file name is built from.
//
// The name builders used to replace every non-printable byte with "_" and then
// only check that the result was non-empty. A truncated or corrupt download
// therefore produced a perfectly "valid" name made of underscores (or of random
// Latin-1 symbols), and that file was archived, pushed to S3 and delivered by
// FTP like a good one — unusable for any analysis software, and noticed only
// when somebody asks for the download much later (DEV-4927).
//
// The checks below run on the DECODED field, before the ASCII sanitizing done
// for the file name, so they see the real characters: a control byte is a hard
// error, while a printable non-ASCII letter (ü, é, ø — common in driver names)
// stays valid and is merely transliterated to "_" in the name.
//
// The bounds are deliberately wider than Annex 1C prescribes. A false rejection
// throws away a genuine download, so these checks target garbage, not spec
// compliance.

const (
	minIdentificationNumberLen = 8 // Annex 1C VehicleIdentificationNumber is 17 bytes; short/padded ones still occur
	maxIdentificationNumberLen = 17
	minRegistrationNumberLen   = 2 // VehicleRegistrationNumber: 13 bytes after the code page
	maxRegistrationNumberLen   = 13
	minCardNumberLen           = 10 // CardNumber is 16 bytes; accept trimmed variants
	maxCardNumberLen           = 16
	maxHolderNameLen           = 35 // HolderSurname / HolderFirstName: 35 bytes after the code page
)

// Characters beyond letters and digits that legitimately occur in a plate
// ("ZH 123456", "M-AB 1234") and in a holder name ("O'Brien", "de la Cruz-Meier").
const (
	registrationNumberExtra = " -./"
	holderNameExtra         = " -.'"
)

// ValidateIdentificationNumber checks the vehicle identification number (VIN)
// read from a VU file. A VIN is alphanumeric; anything else means we did not
// read a VIN but some remnant of a broken transfer.
func ValidateIdentificationNumber(idNo string) error {
	return validateIdentifier("identification number", idNo, minIdentificationNumberLen, maxIdentificationNumberLen, "")
}

// ValidateRegistrationNumber checks the registration number (licence plate)
// read from a VU file.
func ValidateRegistrationNumber(regNo string) error {
	return validateIdentifier("registration number", regNo, minRegistrationNumberLen, maxRegistrationNumberLen, registrationNumberExtra)
}

// ValidateCardNumber checks the card number read from a driver card file.
func ValidateCardNumber(cardNo string) error {
	return validateIdentifier("card number", cardNo, minCardNumberLen, maxCardNumberLen, "")
}

// ValidateHolderName checks the card holder's name. The surname is required —
// it carries the name part of the file name — while the first name is optional
// but must be sane when present.
func ValidateHolderName(firstName, lastName string) error {
	if err := validateName("holder surname", lastName, true); err != nil {
		return err
	}
	return validateName("holder first name", firstName, false)
}

// validateIdentifier accepts ASCII letters and digits plus the characters in
// extra, and requires at least two alphanumerics so a field consisting only of
// separators cannot pass.
func validateIdentifier(field, value string, min, max int, extra string) error {
	if value == "" {
		return fmt.Errorf("%s: empty", field)
	}
	runes := []rune(value)
	if len(runes) < min || len(runes) > max {
		return fmt.Errorf("%s %q: length %d outside %d..%d", field, value, len(runes), min, max)
	}
	alnum := 0
	for _, r := range runes {
		switch {
		case isASCIIAlnum(r):
			alnum++
		case strings.ContainsRune(extra, r):
		default:
			return fmt.Errorf("%s %q: invalid character %s", field, value, describeRune(r))
		}
	}
	if alnum < 2 {
		return fmt.Errorf("%s %q: fewer than two alphanumeric characters", field, value)
	}
	return nil
}

// validateName accepts letters (in any script — driver names are not ASCII),
// digits and the characters in holderNameExtra, and requires at least one
// letter. An empty value is only an error when the field is required.
func validateName(field, value string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s: empty", field)
		}
		return nil
	}
	runes := []rune(value)
	if len(runes) > maxHolderNameLen {
		return fmt.Errorf("%s %q: length %d exceeds %d", field, value, len(runes), maxHolderNameLen)
	}
	letters := 0
	for _, r := range runes {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
		case strings.ContainsRune(holderNameExtra, r):
		default:
			return fmt.Errorf("%s %q: invalid character %s", field, value, describeRune(r))
		}
	}
	if letters == 0 {
		return fmt.Errorf("%s %q: no letters", field, value)
	}
	return nil
}

func isASCIIAlnum(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// describeRune renders an offending character for the error message: printable
// ones as themselves, everything else as a code point, so a log line stays
// readable when the field is binary garbage.
func describeRune(r rune) string {
	if r == unicode.ReplacementChar {
		return "undecodable byte (U+FFFD)"
	}
	if unicode.IsPrint(r) {
		return fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf("non-printable %U", r)
}
