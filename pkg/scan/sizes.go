package scan

// Widths of the fixed-size gen1 vehicle-unit records, in bytes.
//
// A gen1 vu block carries no length field, so walking one means knowing how
// wide its records are. These constants are the only hand-maintained numbers in
// the package and a wrong one desynchronises the walk, which rejects a good
// file — the expensive failure mode here.
//
// So they are not transcribed by eye. They were computed from the decoder's own
// struct definitions, and TestGen1RecordWidths in package scan_test recomputes
// them from those same definitions on every run. If the decoder's view of a
// record changes, or one of these is wrong, that test fails. Treat it as load
// bearing.
const (
	widthCertificate1   = 194 // MemberStateCertificateFirstGen, VuCertificateFirstGen
	widthSignature1     = 128 // SignatureFirstGen (RSA-1024)
	widthTimeReal       = 4
	widthVin            = 17 // VehicleIdentificationNumber
	widthRegistrationId = 15 // VehicleRegistrationIdentification (nation + code page + 13)
	widthDownloadPeriod = 8  // VuDownloadablePeriod (2 x TimeReal)
	widthCardSlots      = 1  // CardSlotsStatus
	widthDownloadAct1   = 58 // VuDownloadActivityDataFirstGen
	widthOdometerShort  = 3  // OdometerValueMidnight
	widthOverspeedCtl   = 9  // VuOverSpeedingControlData (2 x TimeReal + OverspeedNumber)
	widthVuIdent1       = 116
	widthSensorPaired   = 20

	widthCompanyLocksRec1    = 98
	widthControlActivityRec1 = 31
	widthCardIWRec1          = 129
	widthActivityChange      = 2 // ActivityChangeInfo
	widthPlaceRec1           = 28
	widthSpecificCondRec     = 5
	widthFaultRec1           = 82
	widthEventRec1           = 83
	widthOverspeedEventRec1  = 31
	widthTimeAdjustRec1      = 98
	widthDetailedSpeedBlock  = 64 // TimeReal + 60 x Speed
	widthCalibrationRec1     = 167

	widthInterfaceVersion = 2 // DownloadInterfaceVersion, the 0x7600 block
)

// The fixed prefix of a gen1 overview, up to the first counted array:
// two certificates, vin, registration, current time, downloadable period,
// card slot status and download activity data.
const gen1OverviewPrefix = 2*widthCertificate1 + widthVin + widthRegistrationId +
	widthTimeReal + widthDownloadPeriod + widthCardSlots + widthDownloadAct1

// Offsets into a gen1 overview payload (i.e. relative to the first byte after
// the 0x7601 tag) of the fields worth reading without decoding the block.
const (
	gen1OverviewVinOffset          = 2 * widthCertificate1
	gen1OverviewRegistrationOffset = gen1OverviewVinOffset + widthVin
	gen1OverviewCurrentTimeOffset  = gen1OverviewRegistrationOffset + widthRegistrationId
	gen1OverviewPeriodOffset       = gen1OverviewCurrentTimeOffset + widthTimeReal
)

// countedU8 advances past a 1-byte record count followed by that many records
// of recWidth bytes. p is the offset of the count byte.
func countedU8(d []byte, p, recWidth int) (int, error) {
	if p >= len(d) {
		return 0, errShort
	}
	n := int(d[p])
	p++
	return advance(d, p, n*recWidth)
}

// countedU16 is countedU8 for the arrays whose count is a big-endian uint16.
func countedU16(d []byte, p, recWidth int) (int, error) {
	if p+2 > len(d) {
		return 0, errShort
	}
	n := int(d[p])<<8 | int(d[p+1])
	p += 2
	return advance(d, p, n*recWidth)
}

func advance(d []byte, p, n int) (int, error) {
	if n < 0 || p+n > len(d) || p+n < p {
		return 0, errShort
	}
	return p + n, nil
}

// gen1BlockSize returns the payload length of the gen1 vu block whose tag is
// trep, with d starting at the first byte after the tag. The block layouts come
// from Annex 1B; each is a fixed part plus count-prefixed record arrays, so the
// size is arithmetic rather than a parse.
func gen1BlockSize(trep byte, d []byte) (int, error) {
	var (
		p   int
		err error
	)
	switch trep {
	case trepOverview1:
		// certs, vin, registration, time, period, slots, download activity,
		// company locks, control activity, signature
		p = gen1OverviewPrefix
		if p > len(d) {
			return 0, errShort
		}
		if p, err = countedU8(d, p, widthCompanyLocksRec1); err != nil {
			return 0, err
		}
		if p, err = countedU8(d, p, widthControlActivityRec1); err != nil {
			return 0, err
		}

	case trepActivities1:
		// date, odometer, card in/out, activity changes, places, specific
		// conditions, signature
		if p, err = advance(d, 0, widthTimeReal+widthOdometerShort); err != nil {
			return 0, err
		}
		if p, err = countedU16(d, p, widthCardIWRec1); err != nil {
			return 0, err
		}
		if p, err = countedU16(d, p, widthActivityChange); err != nil {
			return 0, err
		}
		if p, err = countedU8(d, p, widthPlaceRec1); err != nil {
			return 0, err
		}
		if p, err = countedU16(d, p, widthSpecificCondRec); err != nil {
			return 0, err
		}

	case trepEventsFaults1:
		// faults, events, overspeeding control, overspeeding events, time
		// adjustments, signature
		if p, err = countedU8(d, 0, widthFaultRec1); err != nil {
			return 0, err
		}
		if p, err = countedU8(d, p, widthEventRec1); err != nil {
			return 0, err
		}
		if p, err = advance(d, p, widthOverspeedCtl); err != nil {
			return 0, err
		}
		if p, err = countedU8(d, p, widthOverspeedEventRec1); err != nil {
			return 0, err
		}
		if p, err = countedU8(d, p, widthTimeAdjustRec1); err != nil {
			return 0, err
		}

	case trepDetailedSpeed1:
		// speed blocks, signature
		if p, err = countedU16(d, 0, widthDetailedSpeedBlock); err != nil {
			return 0, err
		}

	case trepTechnicalData1:
		// vu identification, sensor paired, calibrations, signature
		if p, err = advance(d, 0, widthVuIdent1+widthSensorPaired); err != nil {
			return 0, err
		}
		if p, err = countedU8(d, p, widthCalibrationRec1); err != nil {
			return 0, err
		}

	default:
		return 0, errUnknownTrep
	}

	// every gen1 block is terminated by its signature
	return advance(d, p, widthSignature1)
}
