package simple

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
)

// a simplified parser that only extracts identification and registration numbers from vu files

const (
	distanceIdentificationNumber1stGen       = 194 + 194      // distance in bytes after the overview tag: MemberStateCertificate (194 bytes) + VuCertificate (194 bytes)
	distanceRegistrationIdentification1stGen = 194 + 194 + 17 // distance in bytes after the overview tag: MemberStateCertificate (194 bytes) + VuCertificate (194 bytes) + IdentificationNumber (17 bytes)
)

const (
	RecordTypeVehicleIdentificationNumber       = 0x0a
	RecordTypeVehicleRegistrationNumber         = 0x0b
	RecordTypeVehicleRegistrationIdentification = 0x24
)

var (
	overviewTag1stGen                        = []byte{0x76, 0x01}
	overviewTag2ndGen                        = []byte{0x76, 0x21}
	overviewTag2ndGenV2                      = []byte{0x76, 0x31}
	identificationNumberRecordArrayTag       = []byte{RecordTypeVehicleIdentificationNumber, 0x00, 0x11, 0x00, 0x01}       // RecordType, Length (uint16), Number of records (uint16)
	registrationNumberRecordArrayTag         = []byte{RecordTypeVehicleRegistrationNumber, 0x00, 0x0e, 0x00, 0x01}         // RecordType, Length (uint16), Number of records (uint16)
	registrationIdentificationRecordArrayTag = []byte{RecordTypeVehicleRegistrationIdentification, 0x00, 0x0f, 0x00, 0x01} // RecordType, Length (uint16), Number of records (uint16)
)

var (
	cardIdentificationTag1stGen = []byte{0x05, 0x20, 0x00}
	cardIdentificationTag2ndGen = []byte{0x05, 0x20, 0x02}
)

// tachoFileNameTimeFormat is the date part analysis software expects in a DDD
// file name: 20250131_1435.
const tachoFileNameTimeFormat = "20060102_1504"

// fileNameUnsafe matches everything that must not end up in a DDD file name:
// non-ASCII-printable characters (so umlauts and the like are transliterated),
// spaces, and the separators that would otherwise turn a plate into a path or a
// format directive.
var fileNameUnsafe = regexp.MustCompile(`[[:^print:]]|[ /\\%]`)

// VuFileName returns the archive file name for a vehicle-unit (VU) download,
// e.g. "M_20250131_1435_ZH123456_WVWZZZ1JZXW000001.DDD" — plate and vehicle
// identification number are read out of the file itself.
//
// It fails when those fields cannot be validated. Such a download is corrupt and
// must not be archived under a name that pretends otherwise: name it generically
// and it looks like a real download to everybody downstream, while no analysis
// software can use it (DEV-4927).
func VuFileName(data []byte, ts time.Time) (string, error) {
	vin, regNr, err := VuExtractIdentificationNumberAndRegistrationNumber(data)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("M_%s_%s_%s.DDD", ts.Format(tachoFileNameTimeFormat), sanitizeForFileName(regNr), sanitizeForFileName(vin)), nil
}

// CardFileName returns the archive file name for a driver card download,
// e.g. "C_20250131_1435_H_Muster_CH1234567890123.DDD". See VuFileName for why an
// unvalidatable file yields an error instead of a generic name.
func CardFileName(data []byte, ts time.Time) (string, error) {
	cn, fn, ln, err := CardExtractCardNumberAndDriverName(data)
	if err != nil {
		return "", err
	}
	var driverName string
	if fn != "" {
		driverName = string([]rune(fn)[0:1]) + "_"
	}
	driverName += ln
	return fmt.Sprintf("C_%s_%s_%s.DDD", ts.Format(tachoFileNameTimeFormat), sanitizeForFileName(driverName), sanitizeForFileName(cn)), nil
}

func sanitizeForFileName(s string) string {
	return fileNameUnsafe.ReplaceAllLiteralString(s, "_")
}

// VuExtractIdentificationNumberAndRegistrationNumber reads the vehicle
// identification number and the registration number out of a VU file. The values
// are returned as decoded (not sanitized for a file name), so a caller can log
// what was actually read; on a validation error they are returned as well, next
// to the error.
func VuExtractIdentificationNumberAndRegistrationNumber(data []byte) (idNo string, regNo string, err error) {
	identificationNumber := []byte{}
	registrationNumber := []byte{}

	// 1st Generation
	// there is no other tag to look for, just count the distance from the overview tag
	// we only look for the first occurrence of the overview tag
	if idx := bytes.Index(data, overviewTag1stGen); idx >= 0 {
		idIdx := idx + distanceIdentificationNumber1stGen + len(overviewTag1stGen)
		if len(data[idIdx:]) >= 17 {
			identificationNumber = data[idIdx : idIdx+17]
		}
		regIdx := idx + distanceRegistrationIdentification1stGen + len(overviewTag1stGen) + 1 // +1 -> ignore the NationNumeric byte
		if len(data[regIdx:]) >= 14 {
			registrationNumber = data[regIdx : regIdx+14] // includes CodePage (1 byte) + actual registration number (13 bytes)
		}
	}

	// 2nd Generation V1
	if idx := bytes.Index(data, overviewTag2ndGen); idx >= 0 {
		idx += len(overviewTag2ndGen)
		if idIdx := bytes.Index(data[idx:], identificationNumberRecordArrayTag); idIdx >= 0 {
			idIdx += len(identificationNumberRecordArrayTag)
			if len(data[idx+idIdx:]) >= 17 {
				identificationNumber = data[idx+idIdx : idx+idIdx+17]
				if regIdx := bytes.Index(data[idx+idIdx+17:], registrationNumberRecordArrayTag); regIdx >= 0 {
					regIdx += len(registrationNumberRecordArrayTag)
					if len(data[idx+idIdx+17+regIdx:]) >= 14 {
						registrationNumber = data[idx+idIdx+17+regIdx : idx+idIdx+17+regIdx+14]
					}
				}
			}
		}
	}

	// 2nd Generation V2
	if idx := bytes.Index(data, overviewTag2ndGenV2); idx >= 0 {
		idx += len(overviewTag2ndGenV2)
		if idIdx := bytes.Index(data[idx:], identificationNumberRecordArrayTag); idIdx >= 0 {
			idIdx += len(identificationNumberRecordArrayTag)
			if len(data[idx+idIdx:]) >= 17 {
				identificationNumber = data[idx+idIdx : idx+idIdx+17]
				if regIdx := bytes.Index(data[idx+idIdx+17:], registrationIdentificationRecordArrayTag); regIdx >= 0 {
					regIdx += len(registrationIdentificationRecordArrayTag) + 1 // +1 -> ignore the NationNumeric byte
					if len(data[idx+idIdx+17+regIdx:]) >= 14 {
						registrationNumber = data[idx+idIdx+17+regIdx : idx+idIdx+17+regIdx+14]
					}
				}
			}
		}
	}

	if len(identificationNumber) > 0 {
		idNo = trimSpaceAndZero(string(identificationNumber))
	}

	if len(registrationNumber) > 1 {
		regNo, err = decodeWithCodePage(registrationNumber[0], registrationNumber[1:])
		if err != nil {
			return "", "", err
		}
	}

	if err := ValidateIdentificationNumber(idNo); err != nil {
		return idNo, regNo, err
	}
	if err := ValidateRegistrationNumber(regNo); err != nil {
		return idNo, regNo, err
	}
	return idNo, regNo, nil
}

// CardExtractCardNumberAndDriverName reads the card number and the holder's name
// out of a driver card file. As in
// VuExtractIdentificationNumberAndRegistrationNumber, the values are returned
// decoded and also alongside a validation error.

func CardExtractCardNumberAndDriverName(data []byte) (cardNo string, firstName string, lastName string, err error) {
	var currentTag [3]byte
	var size uint16
cardLoop:
	for len(data) > 5 {
		copy(currentTag[:], data[:3])
		data = data[3:]

		buf := bytes.NewBuffer(data[:2])
		err := binary.Read(buf, binary.BigEndian, &size)
		if err != nil {
			break cardLoop
		}
		if size == 0 {
			break cardLoop
		}
		data = data[2:]
		if len(data) < int(size) {
			break cardLoop
		}
		if len(data) > 136 && size > 136 {
			switch {
			case bytes.Equal(currentTag[:], cardIdentificationTag1stGen) || bytes.Equal(currentTag[:], cardIdentificationTag2ndGen):
				// CardIdentificationAndDriverCardHolderIdentification 1st Gen
				// consists of: CardIdentification, DriverCardHolderIdentification
				// CardIdentification:
				// - CardIssuingMemberState (NationNumeric, 1 byte)
				// - CardNumber (16 bytes)
				// - CardIssuingAuthorityName (36 bytes, 1 byte code page + 35 bytes data)
				// - CardIssueDate (TimeReal, 4 bytes)
				// - CardValidityBegin (TimeReal, 4 bytes)
				// - CardExpiryDate (TimeReal, 4 bytes)
				// DriverCardHolderIdentification:
				// - CardHolderName (HolderName)
				//   - HolderSurname (Name, 36 bytes, 1 byte code page + 35 bytes data)
				//   - HolderFirstName (Name, 36 bytes, 1 byte code page + 35 bytes data)
				// - CardHolderBirthDate (Datef)
				//   - Year (BCDString, 2 bytes)
				//   - Month (BCDString, 1 byte)
				//   - Day (BCDString, 1 byte)
				// - CardHolderPreferredLanguage (Language, 2 bytes)
				cardNo = trimSpaceAndZero(string(data[1:17]))
				lastName, _ = decodeWithCodePage(data[65], data[66:101])
				firstName, _ = decodeWithCodePage(data[101], data[102:137])
			}
		}
		data = data[size:]
	}
	if err := ValidateCardNumber(cardNo); err != nil {
		return cardNo, firstName, lastName, err
	}
	if err := ValidateHolderName(firstName, lastName); err != nil {
		return cardNo, firstName, lastName, err
	}
	return cardNo, firstName, lastName, nil
}

// trimSpaceAndZero trims spaces, 0x00 and 0xff values off a string
func trimSpaceAndZero(s string) string {
	w := "\t\n\v\f\r \x85\xA0\x00\xFF"
	return strings.Trim(s, w)
}

func decodeWithCodePage(codePage byte, data []byte) (string, error) {
	ok := false
	for i := 0; i < len(data); i++ {
		if data[i] > 0 && data[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return "", nil
	}
	// 1: 8859-1
	// 2: 8859-2
	// 3: 8859-3
	// 5: 8859-5
	// 7: 8859-7
	// 9: 8859-9
	// 13: 8859-13
	// 15: 8859-15
	// 16: 8859-16
	// 80: KOI8-R
	// 85: KOI8-U
	var cmap *charmap.Charmap
	switch codePage {
	case 1:
		cmap = charmap.ISO8859_1
	case 2:
		cmap = charmap.ISO8859_2
	case 3:
		cmap = charmap.ISO8859_3
	case 5:
		cmap = charmap.ISO8859_5
	case 7:
		cmap = charmap.ISO8859_7
	case 9:
		cmap = charmap.ISO8859_9
	case 13:
		cmap = charmap.ISO8859_13
	case 15:
		cmap = charmap.ISO8859_15
	case 16:
		cmap = charmap.ISO8859_16
	case 80:
		cmap = charmap.KOI8R
	case 85:
		cmap = charmap.KOI8U
	default:
		cmap = charmap.ISO8859_1
	}
	dec := cmap.NewDecoder()
	res, err := dec.String(string(data))
	if err != nil {
		return "", err
	}
	return trimSpaceAndZero(res), nil
}
