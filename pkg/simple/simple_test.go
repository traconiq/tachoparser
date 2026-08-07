package simple

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"
)

var fileNameTs = time.Date(2025, 1, 31, 14, 35, 0, 0, time.UTC)

// --- synthetic payloads ---------------------------------------------------
//
// Minimal 2nd-generation VU and driver card blocks, just enough structure for
// the simplified parser to find the identification fields.

// latin1Field renders s as a code-page-prefixed field of size bytes (1 byte code
// page + size-1 data bytes), zero padded, the way it sits in a DDD file.
func latin1Field(s string, size int) []byte {
	b := make([]byte, size)
	b[0] = 1 // ISO 8859-1
	for i, r := range s {
		if i+1 >= size {
			break
		}
		b[i+1] = byte(r)
	}
	return b
}

// rawField is latin1Field with the data bytes given verbatim — used to inject
// the binary garbage a truncated transfer leaves behind.
func rawField(raw []byte, size int) []byte {
	b := make([]byte, size)
	b[0] = 1
	copy(b[1:], raw)
	return b
}

func fixedField(s string, size int) []byte {
	b := make([]byte, size)
	copy(b, s)
	return b
}

func buildVuFile(vin []byte, registration []byte) []byte {
	data := append([]byte{}, overviewTag2ndGen...)
	data = append(data, identificationNumberRecordArrayTag...)
	data = append(data, vin...)
	data = append(data, registrationNumberRecordArrayTag...)
	data = append(data, registration...)
	return data
}

func buildCardFile(cardNo []byte, surname []byte, firstName []byte) []byte {
	payload := make([]byte, 0, 137)
	payload = append(payload, 0x01)                // CardIssuingMemberState
	payload = append(payload, cardNo...)           // CardNumber, 16 bytes
	payload = append(payload, make([]byte, 36)...) // CardIssuingAuthorityName
	payload = append(payload, make([]byte, 12)...) // issue / validity / expiry
	payload = append(payload, surname...)          // HolderSurname, 36 bytes
	payload = append(payload, firstName...)        // HolderFirstName, 36 bytes
	data := append([]byte{}, cardIdentificationTag2ndGen...)
	data = append(data, byte(len(payload)>>8), byte(len(payload)))
	return append(data, payload...)
}

// --- file names -----------------------------------------------------------

func TestVuFileName(t *testing.T) {
	tests := []struct {
		name         string
		vin          []byte
		registration []byte
		want         string
		wantErr      bool
	}{
		{
			name:         "valid",
			vin:          fixedField("WVWZZZ1JZXW000001", 17),
			registration: latin1Field("ZH 123456", 14),
			want:         "M_20250131_1435_ZH_123456_WVWZZZ1JZXW000001.DDD",
		},
		{
			// DEV-4927: this used to produce M_..._____________WVWZZZ... — the
			// control bytes were replaced by underscores and the name accepted.
			name:         "garbage registration number",
			vin:          fixedField("WVWZZZ1JZXW000001", 17),
			registration: rawField([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0c, 0x0e, 0x0f}, 14),
			wantErr:      true,
		},
		{
			name:         "garbage identification number",
			vin:          []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x11, 0x12},
			registration: latin1Field("ZH 123456", 14),
			wantErr:      true,
		},
		{
			name:         "empty registration number",
			vin:          fixedField("WVWZZZ1JZXW000001", 17),
			registration: latin1Field("", 14),
			wantErr:      true,
		},
		{
			name:         "truncated identification number",
			vin:          fixedField("WVW", 17),
			registration: latin1Field("ZH 123456", 14),
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VuFileName(buildVuFile(tt.vin, tt.registration), fileNameTs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got name %q", got)
				}
				if got != "" {
					t.Errorf("expected no name on error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCardFileName(t *testing.T) {
	tests := []struct {
		name      string
		cardNo    []byte
		surname   []byte
		firstName []byte
		want      string
		wantErr   bool
	}{
		{
			name:      "valid",
			cardNo:    fixedField("CHE1234567890123", 16),
			surname:   latin1Field("Muster", 36),
			firstName: latin1Field("Hans", 36),
			want:      "C_20250131_1435_H_Muster_CHE1234567890123.DDD",
		},
		{
			// A non-ASCII letter is a valid name, it is only transliterated for
			// the file name — it must not be mistaken for a broken transfer.
			name:      "umlaut in name",
			cardNo:    fixedField("CHE1234567890123", 16),
			surname:   rawField([]byte{'M', 0xfc, 'l', 'l', 'e', 'r'}, 36), // Müller
			firstName: latin1Field("Urs", 36),
			want:      "C_20250131_1435_U_M_ller_CHE1234567890123.DDD",
		},
		{
			name:      "no first name",
			cardNo:    fixedField("CHE1234567890123", 16),
			surname:   latin1Field("Muster", 36),
			firstName: latin1Field("", 36),
			want:      "C_20250131_1435_Muster_CHE1234567890123.DDD",
		},
		{
			// DEV-4927: used to become C_..._H_M______r_CHE... and be stored.
			name:      "garbage surname",
			cardNo:    fixedField("CHE1234567890123", 16),
			surname:   rawField([]byte{'M', 0x01, 0x02, 0x03, 0x04, 'r'}, 36),
			firstName: latin1Field("Hans", 36),
			wantErr:   true,
		},
		{
			name:      "garbage card number",
			cardNo:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12},
			surname:   latin1Field("Muster", 36),
			firstName: latin1Field("Hans", 36),
			wantErr:   true,
		},
		{
			name:      "no surname",
			cardNo:    fixedField("CHE1234567890123", 16),
			surname:   latin1Field("", 36),
			firstName: latin1Field("Hans", 36),
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CardFileName(buildCardFile(tt.cardNo, tt.surname, tt.firstName), fileNameTs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got name %q", got)
				}
				if got != "" {
					t.Errorf("expected no name on error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// A file name must never carry a path separator or a format directive, whatever
// the plate looks like.
func TestVuFileNameSanitizesSeparators(t *testing.T) {
	data := buildVuFile(fixedField("WVWZZZ1JZXW000001", 17), latin1Field("AG 12/34", 14))
	got, err := VuFileName(data, fileNameTs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "M_20250131_1435_AG_12_34_WVWZZZ1JZXW000001.DDD"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- field validation -----------------------------------------------------

func TestValidateRegistrationNumber(t *testing.T) {
	valid := []string{"ZH 123456", "AG12345", "M-AB 1234", "AI 1", "1234567890123"}
	invalid := []string{"", "A", "_____________", "ZH 123456\x00", "ZH\t123456", "ZH+123456", "12345678901234", "--", "\x80\x81"}
	for _, s := range valid {
		if err := ValidateRegistrationNumber(s); err != nil {
			t.Errorf("ValidateRegistrationNumber(%q): unexpected error: %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := ValidateRegistrationNumber(s); err == nil {
			t.Errorf("ValidateRegistrationNumber(%q): expected an error", s)
		}
	}
}

func TestValidateIdentificationNumber(t *testing.T) {
	valid := []string{"WVWZZZ1JZXW000001", "VF1AAAAA", "1HGCM82633A004352"}
	invalid := []string{"", "WVW", "WVWZZZ1JZXW0000012", "WVW ZZZ1JZXW00001", "WVWZZZ1JZXW00000\x01", "_________________"}
	for _, s := range valid {
		if err := ValidateIdentificationNumber(s); err != nil {
			t.Errorf("ValidateIdentificationNumber(%q): unexpected error: %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := ValidateIdentificationNumber(s); err == nil {
			t.Errorf("ValidateIdentificationNumber(%q): expected an error", s)
		}
	}
}

func TestValidateCardNumber(t *testing.T) {
	valid := []string{"CHE1234567890123", "D123456789012", "CHE123456789012"}
	invalid := []string{"", "CHE123", "CHE12345678901234", "CHE 123456789012", "CHE123456789\x0012"}
	for _, s := range valid {
		if err := ValidateCardNumber(s); err != nil {
			t.Errorf("ValidateCardNumber(%q): unexpected error: %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := ValidateCardNumber(s); err == nil {
			t.Errorf("ValidateCardNumber(%q): expected an error", s)
		}
	}
}

func TestValidateHolderName(t *testing.T) {
	valid := [][2]string{
		{"Hans", "Muster"},
		{"", "Muster"},
		{"Jean-Pierre", "de la Cruz-Meier"},
		{"Seán", "O'Brien"},
		{"Urs", "Müller"},
	}
	invalid := [][2]string{
		{"Hans", ""},
		{"Hans", "M\x01ller"},
		{"H\x02ns", "Muster"},
		{"Hans", "----"},
		{"Hans", "\x80\x81\x82"},
	}
	for _, n := range valid {
		if err := ValidateHolderName(n[0], n[1]); err != nil {
			t.Errorf("ValidateHolderName(%q, %q): unexpected error: %v", n[0], n[1], err)
		}
	}
	for _, n := range invalid {
		if err := ValidateHolderName(n[0], n[1]); err == nil {
			t.Errorf("ValidateHolderName(%q, %q): expected an error", n[0], n[1])
		}
	}
}

// --- manual checks against a real file ------------------------------------

func TestVuExtract(t *testing.T) {
	if data64, ok := os.LookupEnv("TACHOFILE"); ok {
		data, err := base64.StdEncoding.DecodeString(data64)
		if err != nil {
			t.Fatal(err)
		}
		idNo, regNo, err := VuExtractIdentificationNumberAndRegistrationNumber(data)
		fmt.Printf("idNo: %v, regNo: %v, err: %v\n", idNo, regNo, err)
	}
}

func TestVuFileNameFromFile(t *testing.T) {
	if data64, ok := os.LookupEnv("TACHOFILE"); ok {
		data, err := base64.StdEncoding.DecodeString(data64)
		if err != nil {
			t.Fatal(err)
		}
		name, err := VuFileName(data, time.Now())
		fmt.Printf("vu name: %v, err: %v\n", name, err)
	}
}

func TestCardExtract(t *testing.T) {
	if data64, ok := os.LookupEnv("CARDFILE"); ok {
		data, err := base64.StdEncoding.DecodeString(data64)
		if err != nil {
			t.Fatal(err)
		}
		cardNo, firstName, lastName, err := CardExtractCardNumberAndDriverName(data)
		fmt.Printf("cardNo: %v, firstName: %v, lastName: %v, err: %v\n", cardNo, firstName, lastName, err)
	}
}

func TestCardFileNameFromFile(t *testing.T) {
	if data64, ok := os.LookupEnv("CARDFILE"); ok {
		data, err := base64.StdEncoding.DecodeString(data64)
		if err != nil {
			t.Fatal(err)
		}
		name, err := CardFileName(data, time.Now())
		fmt.Printf("card name: %v, err: %v\n", name, err)
	}
}
